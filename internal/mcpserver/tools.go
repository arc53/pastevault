package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/secrets"
	"github.com/arc53/pastevault/internal/store"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool names (spec §9). No tool reads a stored secret's value.
const (
	ToolSendText      = "send_text"
	ToolSendFile      = "send_file"
	ToolReceive       = "receive"
	ToolRequestSecret = "request_secret"
	ToolRequestStatus = "request_status"
	ToolListSecrets   = "list_secrets"
	ToolShareStatus   = "share_status"
	ToolAudit         = "audit"
	ToolRevokeShare   = "revoke_share"
)

const (
	secretNamePattern   = `^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`
	expiresPattern      = `^[0-9]+[mhd]$`
	ttlPattern          = `^[0-9]+[smhd]$`
	defaultExpires      = "1h"
	defaultMaxViews     = 1
	maxTextLength       = 1048576
	maxSendFiles        = 25
	defaultRequestTTL   = "10m"
	defaultWaitSeconds  = 300
	defaultShareWaitSec = 30
)

func boolPtr(value bool) *bool { return &value }

func floatPtr(value float64) *float64 { return &value }

func intPtr(value int) *int { return &value }

func rawDefault(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}

// property returns the named property of an inferred object schema.
func property(schema *jsonschema.Schema, name string) *jsonschema.Schema {
	prop := schema.Properties[name]
	if prop == nil {
		panic("mcpserver: no schema property " + name)
	}
	return prop
}

// plainType replaces an inferred ["null", T] type (pointer fields) with T.
func plainType(prop *jsonschema.Schema, typ string) {
	prop.Types = nil
	prop.Type = typ
}

func enum(values ...string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

// ── inputs and outputs ────────────────────────────────────────────────────

type sendTextInput struct {
	Text     string `json:"text" jsonschema:"The text to share. It is encrypted on this machine; the server never sees it."`
	Title    string `json:"title,omitempty" jsonschema:"Optional title shown above the text"`
	Format   string `json:"format,omitempty" jsonschema:"plain (default) or markdown"`
	To       string `json:"to,omitempty" jsonschema:"Seal the share to an agent of your account (name or pvk1_ fingerprint): the link then has no key and only that agent can open it"`
	Expires  string `json:"expires,omitempty" jsonschema:"Expiry such as 15m, 2h or 7d"`
	MaxViews int    `json:"max_views,omitempty" jsonschema:"Destroy the share after this many views"`
}

type sendFileInput struct {
	Paths    []string `json:"paths" jsonschema:"Files to share (absolute, or relative to the first root); they must be inside the allowed roots"`
	As       string   `json:"as,omitempty" jsonschema:"auto (default: a single .env file becomes a text paste), paste or files"`
	To       string   `json:"to,omitempty" jsonschema:"Seal the share to an agent of your account (name or pvk1_ fingerprint)"`
	Expires  string   `json:"expires,omitempty" jsonschema:"Expiry such as 15m, 2h or 7d"`
	MaxViews int      `json:"max_views,omitempty" jsonschema:"Destroy the share after this many views"`
}

type recipientOutput struct {
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

type fileOutput struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Path string `json:"path,omitempty"`
}

type shareOutput struct {
	Slug      string           `json:"slug"`
	Kind      string           `json:"kind"`
	URL       string           `json:"url"`
	KeyInURL  bool             `json:"key_in_url"`
	ExpiresAt *string          `json:"expires_at"`
	MaxViews  *int             `json:"max_views"`
	Recipient *recipientOutput `json:"recipient,omitempty"`
	Files     []fileOutput     `json:"files,omitempty"`
	Notices   []string         `json:"notices,omitempty"`
}

type receiveInput struct {
	Ref            string `json:"ref" jsonschema:"Share link (/p/ or /f/ URL with #k=), slug, or pv://share handle"`
	OutputPath     string `json:"output_path,omitempty" jsonschema:"Write the content here: a file path, or a directory (existing, or ending in /) for multi-file shares. Must be inside the allowed roots."`
	SaveAs         string `json:"save_as,omitempty" jsonschema:"Store the content in the local secret store as NAME; use it as pv://secret/NAME with pastevault run"`
	Overwrite      bool   `json:"overwrite,omitempty" jsonschema:"Replace an existing output file or stored secret"`
	AllowPlaintext bool   `json:"allow_plaintext,omitempty" jsonschema:"Return the text in the result. Only works when the server was started with --allow-plaintext, and never for content that looks like a secret."`
}

type receiveOutput struct {
	Kind           string           `json:"kind"`
	Slug           string           `json:"slug"`
	Title          *string          `json:"title,omitempty"`
	SizeBytes      int64            `json:"size_bytes"`
	WrittenTo      string           `json:"written_to,omitempty"`
	SavedAs        string           `json:"saved_as,omitempty"`
	Files          []fileOutput     `json:"files,omitempty"`
	Content        *string          `json:"content,omitempty"`
	Withheld       string           `json:"withheld,omitempty"`
	Burned         bool             `json:"burned"`
	ViewsRemaining *int             `json:"views_remaining"`
	Recipient      *recipientOutput `json:"recipient,omitempty"`
	Notices        []string         `json:"notices,omitempty"`
}

type requestSecretInput struct {
	Name           string `json:"name" jsonschema:"What to ask for, e.g. OPENAI_API_KEY. It also becomes the store name: pv://secret/NAME"`
	Reason         string `json:"reason" jsonschema:"Why you need it; shown to the user (as untrusted text) on the request page"`
	TTL            string `json:"ttl,omitempty" jsonschema:"How long the request stays open, e.g. 10m or 2h"`
	Accept         string `json:"accept,omitempty" jsonschema:"What the user may send: text (default), file or any"`
	Wait           *bool  `json:"wait,omitempty" jsonschema:"After the user was shown the link (URL elicitation), wait for the answer. Without elicitation support the link is returned at once."`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"How long to wait for the answer"`
}

type requestOutput struct {
	RequestID   string `json:"request_id"`
	Code        string `json:"code"`
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expires_at"`
	Status      string `json:"status"`
	Handle      string `json:"handle,omitempty"`
	Message     string `json:"message,omitempty"`
}

type requestStatusInput struct {
	RequestID string `json:"request_id" jsonschema:"Request id or code from request_secret"`
}

type listSecretsInput struct{}

type secretOutput struct {
	Name      string       `json:"name"`
	Handle    string       `json:"handle"`
	Kind      string       `json:"kind"`
	CreatedAt string       `json:"created_at"`
	Source    store.Source `json:"source"`
}

type listSecretsOutput struct {
	Agent   string         `json:"agent"`
	Secrets []secretOutput `json:"secrets"`
}

type shareStatusInput struct {
	Ref         string `json:"ref" jsonschema:"Share link, slug or owned-share id"`
	WaitFor     string `json:"wait_for,omitempty" jsonschema:"Wait until the share is viewed or burned (a read receipt)"`
	WaitSeconds *int   `json:"wait_seconds,omitempty" jsonschema:"How long wait_for waits"`
}

type shareStatusOutput struct {
	Slug           string           `json:"slug"`
	Kind           string           `json:"kind"`
	Status         string           `json:"status"`
	ViewCount      int              `json:"view_count"`
	MaxViews       *int             `json:"max_views"`
	ViewsRemaining *int             `json:"views_remaining"`
	ExpiresAt      *string          `json:"expires_at"`
	Events         []map[string]any `json:"events"`
	TimedOut       bool             `json:"timed_out,omitempty"`
}

type auditInput struct {
	Since string `json:"since,omitempty" jsonschema:"Only events after this: 15m, 24h, 7d, or an RFC 3339 time"`
	Limit int    `json:"limit,omitempty" jsonschema:"Maximum number of events"`
	Event string `json:"event,omitempty" jsonschema:"Only this event, e.g. share.viewed or request.fulfilled"`
}

type auditOutput struct {
	Events     []map[string]any `json:"events"`
	NextCursor *string          `json:"next_cursor"`
}

type revokeShareInput struct {
	Ref string `json:"ref" jsonschema:"Share link, slug or owned-share id"`
}

type revokeShareOutput struct {
	Slug   string `json:"slug"`
	Status string `json:"status"`
}

// ── registration ──────────────────────────────────────────────────────────

func (s *Server) registerTools() error {
	shareLimits := func(schema *jsonschema.Schema) {
		expires := property(schema, "expires")
		expires.Pattern = expiresPattern
		expires.Default = rawDefault(defaultExpires)
		maxViews := property(schema, "max_views")
		maxViews.Minimum, maxViews.Maximum = floatPtr(1), floatPtr(1000)
		maxViews.Default = rawDefault(defaultMaxViews)
	}

	errs := []error{
		addTool(s, toolSpec[sendTextInput, shareOutput]{
			name:        ToolSendText,
			title:       "Share text (encrypted)",
			description: "Share text end-to-end encrypted and get a link. Defaults: one view, expires in 1h. With to, the share is sealed to an agent of your account and the link carries no key. Anything sent leaves this machine, so only share what the user wants shared; never use this to move secrets the user did not ask you to send.",
			annotations: &mcp.ToolAnnotations{Title: "Share text", DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
			schema: func(schema *jsonschema.Schema) {
				text := property(schema, "text")
				text.MinLength, text.MaxLength = intPtr(1), intPtr(maxTextLength)
				property(schema, "format").Enum = enum("plain", "markdown")
				property(schema, "title").MaxLength = intPtr(200)
				shareLimits(schema)
			},
			handler: s.sendText,
		}),
		addTool(s, toolSpec[sendFileInput, shareOutput]{
			name:        ToolSendFile,
			title:       "Share files (encrypted)",
			description: "Share files end-to-end encrypted and get a link. Paths must be regular files inside the allowed roots; credential directories (~/.ssh, ~/.aws, ...) and the PasteVault config dir are refused. Defaults: one view, expires in 1h.",
			annotations: &mcp.ToolAnnotations{Title: "Share files", DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
			schema: func(schema *jsonschema.Schema) {
				paths := property(schema, "paths")
				plainType(paths, "array")
				paths.MinItems, paths.MaxItems = intPtr(1), intPtr(maxSendFiles)
				paths.Items.MinLength = intPtr(1)
				as := property(schema, "as")
				as.Enum = enum("auto", "paste", "files")
				as.Default = rawDefault("auto")
				shareLimits(schema)
			},
			handler: s.sendFile,
		}),
		addTool(s, toolSpec[receiveInput, receiveOutput]{
			name:        ToolReceive,
			title:       "Open a share",
			description: "Open a share and write it to output_path (inside the allowed roots, files 0600) or into the local secret store with save_as (then use pv://secret/NAME with pastevault run). One of them is required: the content is only returned when the MCP server runs with --allow-plaintext, allow_plaintext is true and it does not look like a secret. Opening uses a view; the last view destroys the share.",
			annotations: &mcp.ToolAnnotations{Title: "Open a share", DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
			schema: func(schema *jsonschema.Schema) {
				property(schema, "ref").MinLength = intPtr(1)
				property(schema, "save_as").Pattern = secretNamePattern
			},
			handler: s.receive,
		}),
		addTool(s, toolSpec[requestSecretInput, requestOutput]{
			name:        ToolRequestSecret,
			title:       "Ask the user for a secret",
			description: "Ask the user for a secret (API key, password, file) without it passing through the conversation. The user opens a PasteVault link signed in to their account and enters the value; it is stored encrypted on this machine and you get a pv://secret/NAME handle, never the value. If the client supports URL elicitation the link is shown to the user directly; otherwise show the returned url to the user and call request_status later.",
			annotations: &mcp.ToolAnnotations{Title: "Request a secret", DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
			schema: func(schema *jsonschema.Schema) {
				property(schema, "name").Pattern = secretNamePattern
				reason := property(schema, "reason")
				reason.MinLength, reason.MaxLength = intPtr(1), intPtr(500)
				ttl := property(schema, "ttl")
				ttl.Pattern = ttlPattern
				ttl.Default = rawDefault(defaultRequestTTL)
				accept := property(schema, "accept")
				accept.Enum = enum(pv.SecretKindText, pv.SecretKindFile, pv.AcceptAny)
				accept.Default = rawDefault(pv.SecretKindText)
				wait := property(schema, "wait")
				plainType(wait, "boolean")
				wait.Default = rawDefault(true)
				timeout := property(schema, "timeout_seconds")
				timeout.Minimum, timeout.Maximum = floatPtr(10), floatPtr(900)
				timeout.Default = rawDefault(defaultWaitSeconds)
			},
			handler: s.requestSecret,
		}),
		addTool(s, toolSpec[requestStatusInput, requestOutput]{
			name:        ToolRequestStatus,
			title:       "Check a secret request",
			description: "Check a secret request made with request_secret. When the user has answered, the secret is stored locally and the pv://secret/NAME handle is returned (never the value).",
			annotations: &mcp.ToolAnnotations{Title: "Check a secret request", ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
			schema: func(schema *jsonschema.Schema) {
				property(schema, "request_id").MinLength = intPtr(1)
			},
			handler: s.requestStatus,
		}),
		addTool(s, toolSpec[listSecretsInput, listSecretsOutput]{
			name:        ToolListSecrets,
			title:       "List stored secrets",
			description: "List the secrets in the local store as pv://secret/NAME handles (names and metadata only, never values). Use a handle with: pastevault run --env-file .env.pv -- <command>.",
			annotations: &mcp.ToolAnnotations{Title: "List stored secrets", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)},
			handler:     s.listSecrets,
		}),
		addTool(s, toolSpec[shareStatusInput, shareStatusOutput]{
			name:        ToolShareStatus,
			title:       "Share status",
			description: "Show a share you created: status, views and its activity. wait_for viewed|burned waits (up to wait_seconds) for a read receipt.",
			annotations: &mcp.ToolAnnotations{Title: "Share status", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)},
			schema: func(schema *jsonschema.Schema) {
				property(schema, "ref").MinLength = intPtr(1)
				property(schema, "wait_for").Enum = enum("viewed", "burned")
				wait := property(schema, "wait_seconds")
				plainType(wait, "integer")
				wait.Minimum, wait.Maximum = floatPtr(0), floatPtr(120)
				wait.Default = rawDefault(defaultShareWaitSec)
			},
			handler: s.shareStatus,
		}),
		addTool(s, toolSpec[auditInput, auditOutput]{
			name:        ToolAudit,
			title:       "Audit log",
			description: "Show the account's audit log: shares created, viewed, burned, revoked; secret requests; agents and tokens. Metadata only.",
			annotations: &mcp.ToolAnnotations{Title: "Audit log", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)},
			schema: func(schema *jsonschema.Schema) {
				limit := property(schema, "limit")
				limit.Minimum, limit.Maximum = floatPtr(1), floatPtr(200)
				limit.Default = rawDefault(50)
				property(schema, "event").MaxLength = intPtr(64)
			},
			handler: s.audit,
		}),
		addTool(s, toolSpec[revokeShareInput, revokeShareOutput]{
			name:        ToolRevokeShare,
			title:       "Revoke a share",
			description: "Delete a share you created, so its link stops working.",
			annotations: &mcp.ToolAnnotations{Title: "Revoke a share", DestructiveHint: boolPtr(true), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
			schema: func(schema *jsonschema.Schema) {
				property(schema, "ref").MinLength = intPtr(1)
			},
			handler: s.revokeShare,
		}),
	}

	return errors.Join(errs...)
}

// ── send_text / send_file ─────────────────────────────────────────────────

func shareFlags(to, expires string, maxViews int) []string {
	if expires == "" {
		expires = defaultExpires
	}
	if maxViews == 0 {
		maxViews = defaultMaxViews
	}
	flags := []string{"--expires", expires, "--max-views", strconv.Itoa(maxViews)}
	if to != "" {
		flags = append(flags, "--to", to)
	}

	return flags
}

// putResult is the part of put's JSON the tools return.
type putResult struct {
	Slug      string           `json:"slug"`
	Kind      string           `json:"kind"`
	URL       string           `json:"url"`
	KeyInURL  bool             `json:"key_in_url"`
	ExpiresAt *string          `json:"expires_at"`
	MaxViews  *int             `json:"max_views"`
	Recipient *recipientOutput `json:"recipient"`
}

func shareOutputFrom(run cliRun) (*shareOutput, error) {
	var result putResult
	if err := json.Unmarshal(run.result, &result); err != nil {
		return nil, err
	}

	return &shareOutput{
		Slug:      result.Slug,
		Kind:      result.Kind,
		URL:       result.URL,
		KeyInURL:  result.KeyInURL,
		ExpiresAt: result.ExpiresAt,
		MaxViews:  result.MaxViews,
		Recipient: result.Recipient,
		Notices:   run.notices,
	}, nil
}

func (s *Server) sendText(ctx context.Context, _ *mcp.CallToolRequest, in sendTextInput) (*shareOutput, *mcp.CallToolResult, error) {
	if strings.TrimSpace(in.Text) == "" {
		return nil, nil, pv.UsageError("text is empty")
	}
	flags := shareFlags(in.To, in.Expires, in.MaxViews)
	if in.Title != "" {
		flags = append(flags, "--title", in.Title)
	}
	if in.Format != "" {
		flags = append(flags, "--format", in.Format)
	}

	s.localLock.Lock()
	run, err := s.runCLI(ctx, "put", flags, []string{"-"}, []byte(in.Text))
	s.localLock.Unlock()
	if err != nil {
		return nil, nil, err
	}

	out, err := shareOutputFrom(run)
	return out, nil, err
}

func (s *Server) sendFile(ctx context.Context, req *mcp.CallToolRequest, in sendFileInput) (*shareOutput, *mcp.CallToolResult, error) {
	policy, rootsRequest := s.pathPolicy(ctx, req)
	if rootsRequest != nil {
		return nil, rootsRequest, nil
	}
	resolved := make([]string, 0, len(in.Paths))
	files := make([]fileOutput, 0, len(in.Paths))
	for _, path := range in.Paths {
		real, err := policy.resolveRead(path)
		if err != nil {
			return nil, nil, err
		}
		info, err := os.Stat(real)
		if err != nil {
			return nil, nil, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot read %s", path)
		}
		resolved = append(resolved, real)
		files = append(files, fileOutput{Name: filepath.Base(real), Size: info.Size()})
	}

	flags := shareFlags(in.To, in.Expires, in.MaxViews)
	if in.As != "" {
		flags = append(flags, "--as", in.As)
	}

	s.localLock.Lock()
	run, err := s.runCLI(ctx, "put", flags, resolved, nil)
	s.localLock.Unlock()
	if err != nil {
		return nil, nil, err
	}

	out, err := shareOutputFrom(run)
	if out != nil {
		out.Files = files
	}
	return out, nil, err
}

// ── receive ───────────────────────────────────────────────────────────────

// getResult is the part of get's JSON that receive uses.
type getResult struct {
	Slug           string           `json:"slug"`
	Kind           string           `json:"kind"`
	Title          *string          `json:"title"`
	SizeBytes      int64            `json:"size_bytes"`
	WrittenTo      string           `json:"written_to"`
	SavedAs        string           `json:"saved_as"`
	Files          []fileOutput     `json:"files"`
	ViewsRemaining *int             `json:"views_remaining"`
	Burned         bool             `json:"burned"`
	Recipient      *recipientOutput `json:"recipient"`
	Content        *string          `json:"content"`
}

func (s *Server) receive(ctx context.Context, req *mcp.CallToolRequest, in receiveInput) (*receiveOutput, *mcp.CallToolResult, error) {
	destinations := 0
	if in.OutputPath != "" {
		destinations++
	}
	if in.SaveAs != "" {
		destinations++
	}
	plaintext := destinations == 0 && in.AllowPlaintext
	switch {
	case destinations > 1:
		return nil, nil, pv.UsageError("use either output_path or save_as, not both")
	case destinations == 0 && !in.AllowPlaintext:
		return nil, nil, pv.UsageError("receive needs output_path (a file inside the allowed roots) or save_as (the local secret store); nothing was opened")
	case plaintext && !s.opts.AllowPlaintext:
		return nil, nil, pv.UsageError("this MCP server does not return share content (start it with pastevault mcp --allow-plaintext); use output_path or save_as instead; nothing was opened")
	}

	flags := []string{}
	switch {
	case in.OutputPath != "":
		policy, rootsRequest := s.pathPolicy(ctx, req)
		if rootsRequest != nil {
			return nil, rootsRequest, nil
		}
		target, err := policy.resolveWrite(in.OutputPath)
		if err != nil {
			return nil, nil, err
		}
		if target.dir {
			// Never --overwrite into a directory: clashing names get a
			// " (1)" suffix, and existing symlinks are never followed.
			flags = append(flags, "--out", target.path)
		} else {
			flags = append(flags, "-o", target.path)
			if in.Overwrite {
				flags = append(flags, "--overwrite")
			}
		}
	case in.SaveAs != "":
		flags = append(flags, "--save", in.SaveAs)
		if in.Overwrite {
			flags = append(flags, "--overwrite")
		}
	default:
		flags = append(flags, "--stdout")
	}

	s.localLock.Lock()
	defer s.localLock.Unlock()
	run, err := s.runCLI(ctx, "get", flags, []string{in.Ref}, nil)
	if err != nil {
		return nil, nil, err
	}
	var result getResult
	if err := json.Unmarshal(run.result, &result); err != nil {
		return nil, nil, err
	}

	out := &receiveOutput{
		Kind:           result.Kind,
		Slug:           result.Slug,
		Title:          result.Title,
		SizeBytes:      result.SizeBytes,
		WrittenTo:      result.WrittenTo,
		SavedAs:        result.SavedAs,
		Files:          result.Files,
		Burned:         result.Burned,
		ViewsRemaining: result.ViewsRemaining,
		Recipient:      result.Recipient,
		Notices:        run.notices,
	}
	if out.Title != nil && (*out.Title == "" || IsSecretLike(*out.Title)) {
		out.Title = nil
	}
	if !plaintext || result.Content == nil {
		return out, nil, nil
	}

	if reason := SecretLikeReason(*result.Content); reason != "" {
		// Never into the transcript. The share may already be burned, so
		// keep the content in the local store instead of dropping it.
		handle, storeErr := s.storeWithheld(result.Slug, *result.Content)
		if storeErr != nil {
			return nil, nil, pv.NewError(pv.ExitUsage, "secret_like_content", "the share's content looks like a secret (%s), so it is not returned, and it could not be kept in the local store (%v). Open shares that may hold secrets with save_as or output_path", reason, pv.Classify(storeErr).Error())
		}
		out.SavedAs = handle
		out.Withheld = fmt.Sprintf("the content looks like a secret (%s), so it was not returned; it is stored as %s for use with pastevault run", reason, handle)
		return out, nil, nil
	}
	out.Content = result.Content

	return out, nil, nil
}

// storeWithheld keeps secret-like text that receive refused to return in
// the local store, as received_<slug> (or received_<slug>_2, ...).
func (s *Server) storeWithheld(slug, content string) (string, error) {
	identity, err := pv.ResolveLocalAgent(s.opts.Server, s.opts.Agent)
	if err != nil {
		return "", err
	}
	target, err := store.Open(s.opts.Server, identity)
	if err != nil {
		return "", err
	}
	base := "received_" + strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, slug)
	for attempt := 1; attempt <= 100; attempt++ {
		name := base
		if attempt > 1 {
			name = fmt.Sprintf("%s_%d", base, attempt)
		}
		if exists, err := target.Exists(name); err != nil {
			return "", err
		} else if exists {
			continue
		}
		payload, err := pv.NewTextPayload(name, []byte(content))
		if err != nil {
			return "", err
		}
		entry, err := target.Put(name, payload, store.Source{Type: store.SourceShare, Ref: slug}, false)
		if err != nil {
			return "", err
		}
		return entry.Handle(), nil
	}

	return "", pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "too many stored secrets named %s", base)
}

// ── secret requests ───────────────────────────────────────────────────────

const elicitationKey = "open_request"

func requestOutputFrom(pending *pv.PendingRequest, status string) *requestOutput {
	return &requestOutput{
		RequestID:   pending.ID,
		Code:        pending.Code,
		URL:         pending.URL,
		Fingerprint: pending.Fingerprint,
		ExpiresAt:   pending.ExpiresAt,
		Status:      status,
	}
}

// requestClient returns a client for the configured server after checking
// it supports secret requests (exit 14 otherwise).
func (s *Server) requestClient(ctx context.Context) (*pv.Client, pv.CapabilitiesResponse, error) {
	client, err := s.opts.NewClient(ctx)
	if err != nil {
		return nil, pv.CapabilitiesResponse{}, err
	}
	capabilities, err := client.GetCapabilities(ctx)
	if err != nil {
		if pv.IsStatus(err, 404) {
			return nil, capabilities, pv.UnsupportedError("%s does not support secret requests; update the server", client.BaseURL())
		}
		return nil, capabilities, err
	}
	if !capabilities.Auth.Enabled || !capabilities.Features.SecretRequests {
		return nil, capabilities, pv.UnsupportedError("%s does not support secret requests (it is too old, or accounts are disabled)", client.BaseURL())
	}

	return client, capabilities, nil
}

func (s *Server) requestSecret(ctx context.Context, req *mcp.CallToolRequest, in requestSecretInput) (*requestOutput, *mcp.CallToolResult, error) {
	wait := in.Wait == nil || *in.Wait
	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = defaultWaitSeconds * time.Second
	}

	// The retry of a multi round-trip call: the user has been shown the link.
	if req.Params.RequestState != "" || len(req.Params.InputResponses) > 0 {
		return s.resumeRequest(ctx, req, wait, timeout)
	}

	ttlText := in.TTL
	if ttlText == "" {
		ttlText = defaultRequestTTL
	}
	ttl, err := pv.ParseWaitDuration("ttl", ttlText)
	if err != nil {
		return nil, nil, err
	}
	accept := in.Accept
	if accept == "" {
		accept = pv.SecretKindText
	}

	identity, err := pv.ResolveLocalAgent(s.opts.Server, s.opts.Agent)
	if err != nil {
		var cliErr *pv.CLIError
		if errors.As(err, &cliErr) && cliErr.Exit == pv.ExitUsage {
			return nil, nil, pv.UsageError("a secret request is made as an agent, and %v", err)
		}
		return nil, nil, err
	}
	client, capabilities, err := s.requestClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	minimum := time.Duration(capabilities.Limits.MinSecretRequestTTLSeconds) * time.Second
	if minimum <= 0 {
		minimum = time.Minute
	}
	if ttl < minimum || ttl > 24*time.Hour || ttl%time.Second != 0 {
		return nil, nil, pv.UsageError("ttl must be between %s and 24h on this server", minimum)
	}

	pending, err := secrets.NewRequest(ctx, client, s.opts.PublicBaseURL, identity, secrets.RequestOptions{
		Name:   in.Name,
		Reason: in.Reason,
		TTL:    ttl,
		Accept: accept,
	})
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintf(s.opts.Log, "pastevault mcp: secret request %s for %s: %s\n", pending.Code, pending.Name, pending.URL)

	if supportsURLElicitation(req) {
		message := fmt.Sprintf("An agent asks for %s. Open this PasteVault page signed in to your account and enter the value there (not in the chat). The page must show the request key %s.", pending.Name, pv.ShortFingerprint(pending.Fingerprint))
		return nil, &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{
				elicitationKey: &mcp.ElicitParams{
					Mode:          "url",
					Message:       message,
					URL:           pending.URL,
					ElicitationID: pending.ID,
				},
			},
			RequestState: s.signState(pending.ID),
		}, nil
	}

	out := requestOutputFrom(pending, pv.RequestPending)
	out.Message = fmt.Sprintf("Show the user this link and ask them to open it signed in to their PasteVault account and enter %s there (never in the chat). The page must show the request key %s. Then call request_status with request_id %s.", pending.Name, pv.FormatFingerprint(pending.Fingerprint), pending.ID)
	return out, nil, nil
}

// resumeRequest continues request_secret after the URL elicitation.
func (s *Server) resumeRequest(ctx context.Context, req *mcp.CallToolRequest, wait bool, timeout time.Duration) (*requestOutput, *mcp.CallToolResult, error) {
	id, ok := s.verifyState(req.Params.RequestState)
	if !ok {
		return nil, nil, pv.UsageError("invalid requestState; call request_secret again without it")
	}
	pending, err := pv.FindPendingRequest(id)
	if err != nil {
		return nil, nil, err
	}
	if pending == nil {
		return nil, nil, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "the request %s is no longer open on this machine (use list_secrets or request_status)", id)
	}

	action := ""
	if response, ok := req.Params.InputResponses[elicitationKey].(*mcp.ElicitResult); ok && response != nil {
		action = response.Action
	}

	switch action {
	case "decline":
		// The user refused to answer: withdraw the request.
		client, _, err := s.requestClient(ctx)
		if err != nil {
			return nil, nil, err
		}
		if _, err := client.CancelSecretRequest(ctx, pending.ID); err != nil && !pv.IsStatus(err, 404) && !pv.IsStatus(err, 409) {
			return nil, nil, err
		}
		_ = pv.DeletePendingRequest(pending)
		out := requestOutputFrom(pending, pv.RequestCancelled)
		out.Message = "The user declined to open the request page, so the request was cancelled. Do not ask for the secret in the chat."
		return out, nil, nil
	case "accept":
		if !wait {
			out := requestOutputFrom(pending, pv.RequestPending)
			out.Message = "The user was shown the request page. Call request_status with this request_id to collect the answer."
			return out, nil, nil
		}
		return s.awaitRequest(ctx, req, pending, timeout)
	default:
		out := requestOutputFrom(pending, pv.RequestPending)
		out.Message = fmt.Sprintf("The request page was not opened. Show the user this link (to open signed in to their PasteVault account), then call request_status with request_id %s.", pending.ID)
		return out, nil, nil
	}
}

// awaitRequest waits for the answer, reporting progress when the client
// asked for it. A timeout is not an error: the request stays pending.
func (s *Server) awaitRequest(ctx context.Context, req *mcp.CallToolRequest, pending *pv.PendingRequest, timeout time.Duration) (*requestOutput, *mcp.CallToolResult, error) {
	client, _, err := s.requestClient(ctx)
	if err != nil {
		return nil, nil, err
	}

	started := time.Now()
	token := req.Params.GetProgressToken()
	onPoll := func() {
		if token == nil || req.Session == nil {
			return
		}
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Progress:      time.Since(started).Seconds(),
			Total:         timeout.Seconds(),
			Message:       "waiting for the user to answer " + pending.Code,
		})
	}

	outcome, err := secrets.Await(ctx, client, pending, secrets.AwaitOptions{Timeout: timeout, OnPoll: onPoll})
	if err != nil {
		if pv.Classify(err).Exit == pv.ExitTimeout {
			out := requestOutputFrom(pending, pv.RequestPending)
			out.Message = fmt.Sprintf("No answer yet. Call request_status with request_id %s later; the link stays valid until %s.", pending.ID, pending.ExpiresAt)
			return out, nil, nil
		}
		return nil, nil, err
	}

	return outcomeOutput(pending, outcome), nil, nil
}

// outcomeOutput maps a final or pending outcome to the tool result. A
// stored answer is reported as "delivered" with its handle (like the CLI).
func outcomeOutput(pending *pv.PendingRequest, outcome secrets.Outcome) *requestOutput {
	switch outcome.Status {
	case secrets.OutcomeStored:
		out := requestOutputFrom(pending, pv.RequestDelivered)
		out.Handle = outcome.Handle
		out.Message = fmt.Sprintf("Stored. Use %s with pastevault run (e.g. %s=%s in .env.pv); never print the value.", outcome.Handle, pending.SaveAs, outcome.Handle)
		return out
	case pv.RequestPending:
		out := requestOutputFrom(pending, pv.RequestPending)
		out.Message = "The user has not answered yet."
		return out
	}

	out := requestOutputFrom(pending, outcome.Status)
	if err := secrets.OutcomeError(pending, outcome); err != nil {
		out.Message = pv.Classify(err).Error()
	}
	return out
}

func (s *Server) requestStatus(ctx context.Context, _ *mcp.CallToolRequest, in requestStatusInput) (*requestOutput, *mcp.CallToolResult, error) {
	pending, err := pv.FindPendingRequest(strings.TrimSpace(in.RequestID))
	if err != nil {
		return nil, nil, err
	}
	if pending == nil {
		return nil, nil, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "this machine has no open request %s (it was answered and stored, cancelled, or made elsewhere; list_secrets shows stored secrets)", in.RequestID)
	}
	if !pv.SameServer(pending.Server, s.opts.Server) {
		return nil, nil, pv.UsageError("request %s was made on %s, not on %s", pending.Code, pending.Server, s.opts.Server)
	}

	client, _, err := s.requestClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	outcome, err := secrets.Check(ctx, client, pending)
	if pv.IsSlowDown(err) {
		out := requestOutputFrom(pending, pv.RequestPending)
		out.Message = "Polled too quickly; try again in a few seconds."
		return out, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	return outcomeOutput(pending, outcome), nil, nil
}

func (s *Server) listSecrets(_ context.Context, _ *mcp.CallToolRequest, _ listSecretsInput) (*listSecretsOutput, *mcp.CallToolResult, error) {
	target, entries, warnings, err := secrets.ListSecrets(s.opts.Server, s.opts.Agent)
	if err != nil {
		return nil, nil, err
	}
	for _, warning := range warnings {
		fmt.Fprintf(s.opts.Log, "pastevault mcp: %s\n", warning)
	}

	out := &listSecretsOutput{Agent: target.Agent, Secrets: []secretOutput{}}
	for _, entry := range entries {
		out.Secrets = append(out.Secrets, secretOutput{
			Name:      entry.Name,
			Handle:    entry.Handle(),
			Kind:      entry.Kind,
			CreatedAt: entry.CreatedAt,
			Source:    entry.Source,
		})
	}

	return out, nil, nil
}

// ── share_status / audit / revoke_share ───────────────────────────────────

// statusResult is the part of status's JSON share_status returns.
type statusResult struct {
	Slug           string           `json:"slug"`
	ShareType      string           `json:"share_type"`
	Status         string           `json:"status"`
	ViewCount      int              `json:"view_count"`
	MaxViews       *int             `json:"max_views"`
	ViewsRemaining *int             `json:"views_remaining"`
	ExpiresAt      *string          `json:"expires_at"`
	Events         []map[string]any `json:"events"`
}

func (s *Server) shareStatus(ctx context.Context, _ *mcp.CallToolRequest, in shareStatusInput) (*shareStatusOutput, *mcp.CallToolResult, error) {
	flags := []string{}
	waitSeconds := defaultShareWaitSec
	if in.WaitSeconds != nil {
		waitSeconds = *in.WaitSeconds
	}
	if in.WaitFor != "" && waitSeconds > 0 {
		flags = append(flags, "--wait", in.WaitFor, "--timeout", fmt.Sprintf("%ds", waitSeconds))
	}

	timedOut := false
	run, err := s.runCLI(ctx, "status", flags, []string{in.Ref}, nil)
	var failure *cliFailure
	if errors.As(err, &failure) && failure.ExitCode == pv.ExitTimeout && len(flags) > 0 {
		// Not viewed or burned in time: report the current state.
		timedOut = true
		run, err = s.runCLI(ctx, "status", nil, []string{in.Ref}, nil)
	}
	if err != nil {
		return nil, nil, err
	}

	var result statusResult
	if err := json.Unmarshal(run.result, &result); err != nil {
		return nil, nil, err
	}
	if result.Events == nil {
		result.Events = []map[string]any{}
	}

	return &shareStatusOutput{
		Slug:           result.Slug,
		Kind:           result.ShareType,
		Status:         result.Status,
		ViewCount:      result.ViewCount,
		MaxViews:       result.MaxViews,
		ViewsRemaining: result.ViewsRemaining,
		ExpiresAt:      result.ExpiresAt,
		Events:         result.Events,
		TimedOut:       timedOut,
	}, nil, nil
}

func (s *Server) audit(ctx context.Context, _ *mcp.CallToolRequest, in auditInput) (*auditOutput, *mcp.CallToolResult, error) {
	flags := []string{}
	if in.Since != "" {
		flags = append(flags, "--since", in.Since)
	}
	if in.Limit != 0 {
		flags = append(flags, "--limit", strconv.Itoa(in.Limit))
	}
	if in.Event != "" {
		flags = append(flags, "--event", in.Event)
	}

	run, err := s.runCLI(ctx, "audit", flags, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	var out auditOutput
	if err := json.Unmarshal(run.result, &out); err != nil {
		return nil, nil, err
	}
	if out.Events == nil {
		out.Events = []map[string]any{}
	}

	return &out, nil, nil
}

func (s *Server) revokeShare(ctx context.Context, _ *mcp.CallToolRequest, in revokeShareInput) (*revokeShareOutput, *mcp.CallToolResult, error) {
	run, err := s.runCLI(ctx, "revoke", nil, []string{in.Ref}, nil)
	if err != nil {
		return nil, nil, err
	}
	var result struct {
		Revoked []revokeShareOutput `json:"revoked"`
	}
	if err := json.Unmarshal(run.result, &result); err != nil {
		return nil, nil, err
	}
	if len(result.Revoked) != 1 {
		return nil, nil, fmt.Errorf("revoke returned %d results", len(result.Revoked))
	}

	return &result.Revoked[0], nil, nil
}

// ── roots ─────────────────────────────────────────────────────────────────

// rootsInputKey labels the roots/list input request of a multi round-trip
// call.
const rootsInputKey = "roots"

// pathPolicy builds the call's path policy from --root and the client's
// roots. On protocol 2026-07-28 and later, roots can only be asked for as an
// input request of the call itself: a non-nil result must then be returned
// to the client, which retries the call with the roots.
func (s *Server) pathPolicy(ctx context.Context, req *mcp.CallToolRequest) (*pathPolicy, *mcp.CallToolResult) {
	clientRoots, ask := s.clientRoots(ctx, req)
	if ask {
		return nil, &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{rootsInputKey: &mcp.ListRootsParams{}},
			RequestState:  s.signState(rootsInputKey),
		}
	}

	return newPathPolicy(s.opts.Roots, clientRoots), nil
}

// clientRoots returns the client's roots as paths, or ask=true when they
// must first be requested (sessionless protocol, client with roots).
// Clients on older protocols are asked with roots/list directly, best
// effort: a client that does not answer is not asked again.
func (s *Server) clientRoots(ctx context.Context, req *mcp.CallToolRequest) (roots []string, ask bool) {
	if req == nil || req.Session == nil {
		return nil, false
	}
	if response, ok := req.Params.InputResponses[rootsInputKey].(*mcp.ListRootsResult); ok && response != nil {
		return rootPaths(response), false
	}
	caps := clientCapabilities(req)
	if caps == nil {
		return nil, false
	}
	if usesSessionlessProtocol(req) {
		return nil, caps.RootsV2 != nil && len(req.Params.InputResponses) == 0
	}
	if _, unsupported := s.noRoots.Load(req.Session); unsupported {
		return nil, false
	}

	listCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	result, err := req.Session.ListRoots(listCtx, nil)
	if err != nil {
		s.noRoots.Store(req.Session, true)
		fmt.Fprintf(s.opts.Log, "pastevault mcp: the client does not list roots (%v); using --root and the working directory\n", err)
		return nil, false
	}

	return rootPaths(result), false
}

func rootPaths(result *mcp.ListRootsResult) []string {
	var roots []string
	for _, root := range result.Roots {
		if root == nil {
			continue
		}
		if path, ok := fileURIToPath(root.URI); ok {
			roots = append(roots, path)
		}
	}

	return roots
}
