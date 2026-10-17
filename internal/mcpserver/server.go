// Package mcpserver is the stdio MCP server of "pastevault mcp" (spec §9).
//
// Shares are created and opened by running the CLI's own put, get, status,
// revoke and audit commands in-process (Options.RunCLI), so pinning, sealed
// shares, size limits and exit codes behave exactly as on the command line.
// Secret requests and the local store use internal/secrets directly. No tool
// ever returns a stored secret's value: agents use pv://secret handles with
// "pastevault run" or "pastevault inject" instead.
package mcpserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CLIResult is the outcome of one in-process CLI command run with --json.
type CLIResult struct {
	// Stdout holds exactly one JSON object (the result, or {"error":{...}}).
	Stdout []byte
	// Stderr holds progress lines and warnings (never secrets).
	Stderr []byte
	Exit   int
}

// Options configure the server.
type Options struct {
	// Server is the PasteVault server URL (--server / PASTEVAULT_SERVER).
	Server string
	// PublicBaseURL is the web origin used in request links.
	PublicBaseURL string
	// Agent is the agent identity to act as ("" = the default agent).
	Agent string
	// Roots are the --root directories file tools may use.
	Roots []string
	// AllowPlaintext permits receive to return non-secret-like content.
	AllowPlaintext bool
	// AllowAnyHost lets receive open shares on other servers than Server.
	AllowAnyHost bool
	// AllowHomeRoot accepts the home directory, filesystem roots and
	// ancestors of the home directory as roots.
	AllowHomeRoot bool
	// Version is the CLI version reported to clients.
	Version string

	// RunCLI runs one pastevault command in-process. args starts with the
	// command name; --json and --server are added by the caller of RunCLI.
	RunCLI func(ctx context.Context, args []string, stdin []byte) CLIResult
	// NewClient returns an API client for Server carrying the CLI's
	// credentials (PASTEVAULT_TOKEN, stored token or session). It fails
	// with exit 3 when there are none.
	NewClient func(ctx context.Context) (*pv.Client, error)
	// Log receives diagnostics (stderr). Nil discards them.
	Log io.Writer
}

// Server is a configured PasteVault MCP server.
type Server struct {
	opts      Options
	mcp       *mcp.Server
	stateKey  []byte
	logger    *slog.Logger
	localLock sync.Mutex
	// noRoots remembers sessions whose client does not answer roots/list.
	noRoots sync.Map
	// placed are the files receive wrote in this session (localLock).
	placed placedFiles
	// requestLocks serialise request_secret/request_status per request id.
	requestLocks sync.Map
}

const instructions = `PasteVault shares text and files end-to-end encrypted, and collects secrets from the user without them passing through this conversation.
- Never ask the user to paste a secret (API key, password, token) into the chat. Call request_secret: the user enters it on a PasteVault page and you get a pv://secret/NAME handle, never the value.
- Use handles from the shell: put NAME=pv://secret/NAME lines in .env.pv and run "pastevault run --env-file .env.pv -- <command>". Never print, echo or log secret values.
- Prefer "to" (an agent of the account) for agent-to-agent shares: the link then carries no key.
- Shares default to one view and a short expiry; links are shown once, so pass them on rather than opening them yourself.`

// New builds the MCP server and registers the tools.
func New(opts Options) (*Server, error) {
	if opts.RunCLI == nil || opts.NewClient == nil {
		return nil, errors.New("mcpserver: RunCLI and NewClient are required")
	}
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	s := &Server{
		opts:     opts,
		stateKey: key,
		placed:   placedFiles{},
		logger:   slog.New(slog.NewTextHandler(opts.Log, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
	s.mcp = mcp.NewServer(&mcp.Implementation{
		Name:    "pastevault",
		Title:   "PasteVault",
		Version: opts.Version,
	}, &mcp.ServerOptions{
		Instructions: instructions,
		Logger:       s.logger,
	})
	if err := s.registerTools(); err != nil {
		return nil, err
	}

	return s, nil
}

// MCP returns the underlying SDK server (tests connect it in memory).
func (s *Server) MCP() *mcp.Server {
	return s.mcp
}

// Run serves one client over the given transport until it disconnects.
func (s *Server) Run(ctx context.Context, transport mcp.Transport) error {
	err := s.mcp.Run(ctx, transport)
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}

	return err
}

// ── tool registration ─────────────────────────────────────────────────────

// toolSpec describes one tool; In and Out are its argument and result types.
type toolSpec[In, Out any] struct {
	name        string
	title       string
	description string
	annotations *mcp.ToolAnnotations
	// schema adjusts the inferred input schema (enums, patterns, ranges).
	schema  func(*jsonschema.Schema)
	handler func(ctx context.Context, req *mcp.CallToolRequest, in In) (*Out, *mcp.CallToolResult, error)
}

// addTool registers a tool with an input schema inferred from In (struct
// fields; additionalProperties false) and adjusted by spec.schema, and an
// output schema inferred from Out. Arguments are validated against the
// input schema and decoded strictly. A handler error becomes a tool error
// carrying the CLI error object; a non-nil *mcp.CallToolResult (input
// requests) is returned as is.
func addTool[In, Out any](s *Server, spec toolSpec[In, Out]) error {
	input, err := jsonschema.For[In](nil)
	if err != nil {
		return fmt.Errorf("input schema of %s: %w", spec.name, err)
	}
	if spec.schema != nil {
		spec.schema(input)
	}
	input.AdditionalProperties = &jsonschema.Schema{Not: &jsonschema.Schema{}}
	resolvedInput, err := input.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		return fmt.Errorf("input schema of %s: %w", spec.name, err)
	}
	output, err := jsonschema.For[Out](nil)
	if err != nil {
		return fmt.Errorf("output schema of %s: %w", spec.name, err)
	}

	tool := &mcp.Tool{
		Name:         spec.name,
		Title:        spec.title,
		Description:  spec.description,
		Annotations:  spec.annotations,
		InputSchema:  input,
		OutputSchema: output,
	}
	s.mcp.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		in, err := decodeArguments[In](req.Params.Arguments, resolvedInput)
		if err != nil {
			return errorResult(err), nil
		}
		out, result, err := spec.handler(ctx, req, in)
		switch {
		case err != nil:
			return errorResult(err), nil
		case result != nil:
			return result, nil
		}

		return structuredResult(out)
	})

	return nil
}

func decodeArguments[In any](raw json.RawMessage, schema *jsonschema.Resolved) (In, error) {
	var in In
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		raw = []byte("{}")
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return in, pv.UsageError("invalid arguments: %v", err)
	}
	if err := schema.Validate(generic); err != nil {
		return in, pv.UsageError("invalid arguments: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return in, pv.UsageError("invalid arguments: %v", err)
	}

	return in, nil
}

// structuredResult returns out as structuredContent plus the same JSON as
// text, for clients that only read text content.
func structuredResult(out any) (*mcp.CallToolResult, error) {
	data, err := marshalJSON(out)
	if err != nil {
		return nil, err
	}

	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(data)}},
		StructuredContent: json.RawMessage(data),
	}, nil
}

// ToolError is the error object of a failed tool call: the CLI's
// {"error":{code,message,exit_code}} (docs/cli-reference.md).
type ToolError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	ExitCode int    `json:"exit_code"`
}

func toolErrorOf(err error) ToolError {
	var cliErr *cliFailure
	if errors.As(err, &cliErr) {
		return cliErr.ToolError
	}
	classified := pv.Classify(err)

	return ToolError{Code: classified.Code, Message: strings.TrimSpace(classified.Error()), ExitCode: classified.Exit}
}

// errorResult is a tool error (isError) whose text is the CLI's error
// object {"error":{code,message,exit_code}}. It carries no structured
// content: clients validate structuredContent against the tool's output
// schema, which describes successful results.
func errorResult(err error) *mcp.CallToolResult {
	payload := map[string]ToolError{"error": toolErrorOf(err)}
	data, marshalErr := marshalJSON(payload)
	if marshalErr != nil {
		data = []byte(`{"error":{"code":"internal","message":"internal error","exit_code":1}}`)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
		IsError: true,
	}
}

func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}

	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

// ── in-process CLI ────────────────────────────────────────────────────────

// cliFailure is a CLI command that ended with an error object.
type cliFailure struct {
	ToolError
}

func (e *cliFailure) Error() string {
	return e.Message
}

// cliRun is one finished CLI command: its JSON result and notices.
type cliRun struct {
	result  json.RawMessage
	notices []string
}

// runCLI runs command with flags, then "--" and the positional arguments,
// and returns its JSON result or a *cliFailure. Warnings and pin notices
// from stderr are kept as notices; all of stderr is also logged.
func (s *Server) runCLI(ctx context.Context, command string, flags []string, positional []string, stdin []byte) (cliRun, error) {
	args := append([]string{command}, flags...)
	args = append(args, "--json", "--server", s.opts.Server)
	if len(positional) > 0 {
		args = append(args, "--")
		args = append(args, positional...)
	}

	outcome := s.opts.RunCLI(ctx, args, stdin)
	var notices []string
	for _, line := range strings.Split(string(outcome.Stderr), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fmt.Fprintf(s.opts.Log, "pastevault %s: %s\n", command, line)
		if strings.HasPrefix(line, "Warning: ") || strings.HasPrefix(line, "Pinned ") {
			notices = append(notices, line)
		}
	}

	stdout := bytes.TrimSpace(outcome.Stdout)
	if outcome.Exit != 0 {
		var envelope struct {
			Error *ToolError `json:"error"`
		}
		if err := json.Unmarshal(stdout, &envelope); err == nil && envelope.Error != nil {
			if envelope.Error.ExitCode == 0 {
				envelope.Error.ExitCode = outcome.Exit
			}
			return cliRun{notices: notices}, &cliFailure{*envelope.Error}
		}
		return cliRun{notices: notices}, &cliFailure{ToolError{Code: pv.CodeInternal, Message: fmt.Sprintf("pastevault %s failed (exit %d)", command, outcome.Exit), ExitCode: outcome.Exit}}
	}
	if !json.Valid(stdout) {
		return cliRun{notices: notices}, fmt.Errorf("pastevault %s returned no JSON result", command)
	}

	return cliRun{result: stdout, notices: notices}, nil
}

// ── client capabilities ──────────────────────────────────────────────────

func clientCapabilities(req *mcp.CallToolRequest) *mcp.ClientCapabilities {
	if req == nil || req.Session == nil {
		return nil
	}
	params := req.Session.InitializeParams()
	if params == nil {
		return nil
	}

	return params.Capabilities
}

// supportsURLElicitation reports whether the client accepts
// elicitation/create with mode "url".
func supportsURLElicitation(req *mcp.CallToolRequest) bool {
	caps := clientCapabilities(req)
	return caps != nil && caps.Elicitation != nil && caps.Elicitation.URL != nil
}

// usesSessionlessProtocol reports a client on protocol 2026-07-28 or later,
// where server-initiated requests (roots/list) are not allowed.
func usesSessionlessProtocol(req *mcp.CallToolRequest) bool {
	if req == nil || req.Session == nil || req.Session.InitializeParams() == nil {
		return false
	}

	return req.Session.InitializeParams().ProtocolVersion >= "2026-07-28"
}

// ── request state (multi round-trip) ─────────────────────────────────────

// signState returns an opaque requestState for value, bound to tool, so a
// retried call can only resume what this server process asked that tool's
// client for.
func (s *Server) signState(tool, value string) string {
	payload := tool + "\x00" + value
	mac := hmac.New(sha256.New, s.stateKey)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyState returns the value of a requestState signed for tool.
func (s *Server) verifyState(tool, state string) (string, bool) {
	encoded, signature, found := strings.Cut(state, ".")
	if !found {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	got, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, s.stateKey)
	mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return "", false
	}
	boundTool, value, found := strings.Cut(string(payload), "\x00")
	if !found || boundTool != tool {
		return "", false
	}
	return value, true
}

// requestLock serialises the request tools per request id, so one answer is
// never collected twice concurrently.
func (s *Server) requestLock(id string) *sync.Mutex {
	lock, _ := s.requestLocks.LoadOrStore(id, &sync.Mutex{})
	return lock.(*sync.Mutex)
}
