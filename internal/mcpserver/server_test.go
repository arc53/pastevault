package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/tools.golden.json")

const legacyProtocol = "2025-11-25"

// isolate gives the test its own config dir and no credentials.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv(pv.EnvConfigDir, filepath.Join(t.TempDir(), "config"))
	t.Setenv(pv.EnvAgent, "")
	t.Setenv(pv.EnvAgentKey, "")
	t.Setenv(pv.EnvToken, "")
}

func newAgent(t *testing.T, server, name, id string) *pv.AgentIdentity {
	t.Helper()
	keys, err := pv.GenerateAgentKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	identity := pv.NewAgentIdentity(server, name, keys)
	identity.AgentID = id
	path, _ := pv.AgentKeyPath(server, name)
	if err := pv.SaveAgentIdentity(identity, path, false); err != nil {
		t.Fatal(err)
	}
	return identity
}

// noCLI fails the test if a tool runs a CLI command.
func noCLI(t *testing.T) func(context.Context, []string, []byte) CLIResult {
	return func(_ context.Context, args []string, _ []byte) CLIResult {
		t.Errorf("unexpected CLI run %v", args)
		return CLIResult{Exit: 1}
	}
}

type testSetup struct {
	options       Options
	clientOptions *mcp.ClientOptions
	protocol      string
	roots         []string
}

// connect starts the server and a client over the in-memory transport.
func connect(t *testing.T, setup testSetup) *mcp.ClientSession {
	t.Helper()
	options := setup.options
	if options.Server == "" {
		options.Server = "http://127.0.0.1:9"
	}
	if options.PublicBaseURL == "" {
		options.PublicBaseURL = options.Server
	}
	if options.RunCLI == nil {
		options.RunCLI = noCLI(t)
	}
	if options.NewClient == nil {
		options.NewClient = func(context.Context) (*pv.Client, error) {
			return nil, pv.NewError(pv.ExitAuth, pv.CodeNotLoggedIn, "not logged in")
		}
	}
	server, err := New(options)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.MCP().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, setup.clientOptions)
	for _, root := range setup.roots {
		client.AddRoots(&mcp.Root{URI: fileURI(root)})
	}
	var sessionOptions *mcp.ClientSessionOptions
	if setup.protocol != "" {
		sessionOptions = &mcp.ClientSessionOptions{ProtocolVersion: setup.protocol}
	}
	session, err := client.Connect(ctx, clientTransport, sessionOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })

	return session
}

// fileURI is the file:// URI of an absolute path (file:///C:/dir on Windows).
func fileURI(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return (&url.URL{Scheme: "file", Path: slashed}).String()
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return result
}

func resultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) != 1 {
		t.Fatalf("want one content block, got %d", len(result.Content))
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, not text", result.Content[0])
	}
	return text.Text
}

// structured decodes a successful result (structuredContent, which must
// equal the text content).
func structured(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	if result.IsError {
		t.Fatalf("tool error: %s", resultText(t, result))
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	var fromText map[string]any
	if err := json.Unmarshal([]byte(resultText(t, result)), &fromText); err != nil {
		t.Fatalf("text content is not the JSON result: %v", err)
	}
	if !jsonEqual(value, fromText) {
		t.Fatalf("structured and text content differ:\n%v\n%v", value, fromText)
	}
	return value
}

func jsonEqual(left, right any) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
}

// toolError decodes an error result's {"error":{...}}.
func toolError(t *testing.T, result *mcp.CallToolResult) ToolError {
	t.Helper()
	if !result.IsError {
		t.Fatalf("want a tool error, got %s", resultText(t, result))
	}
	var envelope struct {
		Error ToolError `json:"error"`
	}
	if err := json.Unmarshal([]byte(resultText(t, result)), &envelope); err != nil {
		t.Fatalf("error text is not JSON: %v", err)
	}
	return envelope.Error
}

func TestToolListMatchesGolden(t *testing.T) {
	isolate(t)
	session := connect(t, testSetup{})
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
		if strings.Contains(strings.ToLower(tool.Name), "read") {
			t.Errorf("tool %s: no tool name may contain \"read\"", tool.Name)
		}
		schema, _ := json.Marshal(tool.InputSchema)
		var decoded map[string]any
		_ = json.Unmarshal(schema, &decoded)
		if decoded["type"] != "object" || decoded["additionalProperties"] != false {
			t.Errorf("tool %s: input schema must be an object with additionalProperties false: %s", tool.Name, schema)
		}
		if tool.OutputSchema == nil {
			t.Errorf("tool %s has no output schema", tool.Name)
		}
		if tool.Annotations == nil {
			t.Errorf("tool %s has no annotations", tool.Name)
		}
	}
	want := []string{ToolAudit, ToolListSecrets, ToolReceive, ToolRequestSecret, ToolRequestStatus, ToolRevokeShare, ToolSendFile, ToolSendText, ToolShareStatus}
	slices.Sort(names)
	if !slices.Equal(names, want) {
		t.Fatalf("tools = %v, want %v", names, want)
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(listed.Tools); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "tools.golden.json")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/mcpserver -run TestToolListMatchesGolden -update)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(golden, []byte("\r\n"), []byte("\n")), buffer.Bytes()) {
		t.Fatalf("tool list differs from %s (rerun with -update if intended):\n%s", path, buffer.String())
	}
}

func TestArgumentsAreValidated(t *testing.T) {
	isolate(t)
	session := connect(t, testSetup{})

	for _, arguments := range []map[string]any{
		{"text": "hi", "unknown": true},
		{"text": "hi", "max_views": 0},
		{"text": "hi", "expires": "1w"},
		{"text": "hi", "format": "html"},
		{},
	} {
		failure := toolError(t, callTool(t, session, ToolSendText, arguments))
		if failure.ExitCode != pv.ExitUsage {
			t.Errorf("%v: exit %d, want 2 (%s)", arguments, failure.ExitCode, failure.Message)
		}
	}
	failure := toolError(t, callTool(t, session, ToolRequestSecret, map[string]any{"name": "1BAD", "reason": "x"}))
	if failure.ExitCode != pv.ExitUsage {
		t.Errorf("bad secret name: exit %d", failure.ExitCode)
	}
}

func TestSecretLike(t *testing.T) {
	secretLike := []string{
		"sk-proj-abcdefghijklmnop1234",
		"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"github_pat_11ABCDEFG0123456789_abcdefghijklmnop",
		"AKIAIOSFODNN7EXAMPLE",
		"xoxb-1234567890-abcdefghij",
		"pv_pat_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"DATABASE_URL=postgres://u:p@host/db",
		"export API_TOKEN=abc",
		"# config\nFOO=bar\n",
		"the key is 9f8e7d6c5b4a39281706f5e4d3c2b1a0Zx",
		"https://user:hunter2@example.com/",
	}
	for _, text := range secretLike {
		if !IsSecretLike(text) {
			t.Errorf("not detected as secret-like: %q", text)
		}
	}

	plain := []string{
		"hello world",
		"Meeting notes: ship the release on Friday.",
		"see https://pastevault.dev/docs/agents for details",
		"/home/dev/projects/pastevault/internal/mcpserver",
		"if a == b { return internationalization }",
		"x = 5 // spaces around the equals sign",
	}
	for _, text := range plain {
		if reason := SecretLikeReason(text); reason != "" {
			t.Errorf("%q detected as secret-like (%s)", text, reason)
		}
	}
}

// ── paths ─────────────────────────────────────────────────────────────────

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func refusedPath(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: not refused", what)
	}
	if exit := pv.Classify(err).Exit; exit != pv.ExitLocalFile {
		t.Fatalf("%s: exit %d, want 13 (%v)", what, exit, err)
	}
}

func TestPathPolicy(t *testing.T) {
	isolate(t)
	base := t.TempDir()
	root := filepath.Join(base, "project")
	outside := filepath.Join(base, "outside")
	writeTestFile(t, filepath.Join(root, "notes.txt"), "notes")
	writeTestFile(t, filepath.Join(root, ".env"), "A=1")
	writeTestFile(t, filepath.Join(root, ".ssh", "id_ed25519"), "key")
	writeTestFile(t, filepath.Join(root, ".git", "config"), "[core]")
	writeTestFile(t, filepath.Join(outside, "secret.txt"), "secret")
	policy := newPathPolicy([]string{root}, nil, false)
	realRoot := policy.roots[0]

	if got, err := policy.resolveRead("notes.txt"); err != nil || got != filepath.Join(realRoot, "notes.txt") {
		t.Fatalf("relative read = %q, %v", got, err)
	}
	if _, err := policy.resolveRead(filepath.Join(root, ".env")); err != nil {
		t.Fatalf(".env inside the root is allowed: %v", err)
	}
	_, err := policy.resolveRead(filepath.Join(outside, "secret.txt"))
	refusedPath(t, err, "file outside the roots")
	_, err = policy.resolveRead("../outside/secret.txt")
	refusedPath(t, err, "relative escape")
	_, err = policy.resolveRead(filepath.Join(root, ".ssh", "id_ed25519"))
	refusedPath(t, err, ".ssh inside the root")
	_, err = policy.resolveRead(root)
	refusedPath(t, err, "a directory")

	configDir, _ := pv.ConfigDir()
	writeTestFile(t, filepath.Join(configDir, "auth.json"), "{}")
	inRoot := newPathPolicy([]string{root, configDir}, nil, false)
	_, err = inRoot.resolveRead(filepath.Join(configDir, "auth.json"))
	refusedPath(t, err, "config dir even when it is a root")

	// Writes.
	target, err := policy.resolveWrite("out.txt")
	if err != nil || target.dir || target.path != filepath.Join(realRoot, "out.txt") {
		t.Fatalf("file target = %+v, %v", target, err)
	}
	target, err = policy.resolveWrite("downloads/")
	if err != nil || !target.dir || target.path != filepath.Join(realRoot, "downloads") {
		t.Fatalf("new directory target = %+v, %v", target, err)
	}
	target, err = policy.resolveWrite(root)
	if err != nil || !target.dir {
		t.Fatalf("root as directory target = %+v, %v", target, err)
	}
	_, err = policy.resolveWrite(filepath.Join(root, ".git", "hooks", "pre-commit"))
	refusedPath(t, err, "write into .git")
	_, err = policy.resolveWrite(filepath.Join(outside, "x.txt"))
	refusedPath(t, err, "write outside the roots")
	_, err = policy.resolveWrite(filepath.Join(root, "missing", "x.txt"))
	refusedPath(t, err, "write into a missing directory")

	if runtime.GOOS == "windows" {
		return
	}
	// Symlink escapes.
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}
	_, err = policy.resolveRead(filepath.Join(root, "link.txt"))
	refusedPath(t, err, "symlink to a file outside")
	_, err = policy.resolveRead(filepath.Join(root, "linkdir", "secret.txt"))
	refusedPath(t, err, "path through a symlinked directory")
	_, err = policy.resolveWrite(filepath.Join(root, "link.txt"))
	refusedPath(t, err, "write through a symlink")
	_, err = policy.resolveWrite(filepath.Join(root, "linkdir", "new.txt"))
	refusedPath(t, err, "write through a symlinked directory")
	_, err = policy.resolveWrite(filepath.Join(root, "linkdir"))
	refusedPath(t, err, "symlinked directory as target")
}

func TestClientRootsAndFallback(t *testing.T) {
	isolate(t)
	clientRoot := t.TempDir()
	writeTestFile(t, filepath.Join(clientRoot, "a.txt"), "a")
	var ran []string
	runner := func(_ context.Context, args []string, _ []byte) CLIResult {
		ran = args
		return CLIResult{Stdout: []byte(`{"slug":"abc","kind":"file_share","url":"http://x/f/abc#k=k","key_in_url":true,"expires_at":null,"max_views":1,"recipient":null}`)}
	}

	// Clients list their roots (roots/list on older protocols, an input
	// request of the call on 2026-07-28): send_file may read there.
	for _, protocol := range []string{legacyProtocol, ""} {
		ran = nil
		session := connect(t, testSetup{options: Options{RunCLI: runner}, protocol: protocol, roots: []string{clientRoot}})
		result := structured(t, callTool(t, session, ToolSendFile, map[string]any{"paths": []string{filepath.Join(clientRoot, "a.txt")}}))
		if files, _ := result["files"].([]any); len(files) != 1 {
			t.Fatalf("%s: files = %v", protocol, result["files"])
		}
		if !slices.Contains(ran, "--") || !strings.HasSuffix(ran[len(ran)-1], "a.txt") {
			t.Fatalf("%s: put args = %v", protocol, ran)
		}

		// A file outside the roots is refused.
		other := t.TempDir()
		writeTestFile(t, filepath.Join(other, "b.txt"), "b")
		failure := toolError(t, callTool(t, session, ToolSendFile, map[string]any{"paths": []string{filepath.Join(other, "b.txt")}}))
		if failure.ExitCode != pv.ExitLocalFile || failure.Code != CodePathRefused {
			t.Fatalf("%s: outside root: %+v", protocol, failure)
		}
	}
}

// ── receive ───────────────────────────────────────────────────────────────

func TestReceivePlaintextNeedsServerFlag(t *testing.T) {
	isolate(t)
	session := connect(t, testSetup{})
	failure := toolError(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "allow_plaintext": true}))
	if failure.ExitCode != pv.ExitUsage || !strings.Contains(failure.Message, "--allow-plaintext") {
		t.Fatalf("plaintext without --allow-plaintext: %+v", failure)
	}
}

func TestReceivePlaintextWithholdsSecrets(t *testing.T) {
	isolate(t)
	server := "http://127.0.0.1:9"
	newAgent(t, server, "tester", "agent-1")
	content := "notes for the deploy"
	runner := func(_ context.Context, args []string, _ []byte) CLIResult {
		if !slices.Contains(args, "--stdout") {
			t.Errorf("get without --stdout: %v", args)
		}
		body, _ := json.Marshal(map[string]any{"slug": "slug123", "kind": "paste", "title": "", "size_bytes": len(content), "burned": true, "views_remaining": 0, "content": content})
		return CLIResult{Stdout: body}
	}
	session := connect(t, testSetup{options: Options{Server: server, RunCLI: runner, AllowPlaintext: true}})

	result := structured(t, callTool(t, session, ToolReceive, map[string]any{"ref": "slug123", "allow_plaintext": true}))
	if result["content"] != content {
		t.Fatalf("plain content not returned: %v", result)
	}

	content = "OPENAI_API_KEY=sk-live-0123456789abcdefghijkl"
	raw := callTool(t, session, ToolReceive, map[string]any{"ref": "slug123", "allow_plaintext": true})
	if text := resultText(t, raw); strings.Contains(text, "sk-live") {
		t.Fatalf("secret-like content leaked into the result: %s", text)
	}
	result = structured(t, raw)
	if _, ok := result["content"]; ok || result["withheld"] == nil || result["saved_as"] != "pv://secret/received_slug123" {
		t.Fatalf("secret-like content: %v", result)
	}
	identity, _ := pv.ResolveLocalAgent(server, "")
	target, _ := store.Open(server, identity)
	_, payload, err := target.Get("received_slug123")
	if err != nil || string(payload.Value) != content {
		t.Fatalf("withheld content not stored: %v", err)
	}
}

// ── secret requests ───────────────────────────────────────────────────────

const requestID = "11111111-2222-4333-8444-555555555555"

// requestServer implements capabilities and the agent side of secret
// requests. answer is set once the "human" has answered.
type requestServer struct {
	t         *testing.T
	mu        sync.Mutex
	url       string
	created   *pv.CreateSecretRequestRequest
	value     string
	polls     int
	acks      int
	cancelled int
}

func newRequestServer(t *testing.T) *requestServer {
	fake := &requestServer{t: t}
	server := httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(server.Close)
	fake.url = server.URL
	return fake
}

func (f *requestServer) answer(value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.value = value
}

func (f *requestServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	if r.Header.Get("Authorization") != "Bearer pv_pat_test" && r.URL.Path != "/api/capabilities" {
		reply(401, map[string]string{"error": "Authentication required"})
		return
	}

	switch path := r.URL.Path; {
	case path == "/api/capabilities":
		reply(200, map[string]any{"api_version": 2, "auth": map[string]any{"enabled": true}, "features": map[string]any{"secret_requests": true, "agents": true}, "limits": map[string]any{"min_secret_request_ttl_seconds": 5}})
	case r.Method == http.MethodPost && path == "/api/secret-requests":
		var body pv.CreateSecretRequestRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.created = &body
		reply(201, pv.CreateSecretRequestResponse{ID: requestID, Code: "ABCD-EFGH", URLPath: "/r/ABCD-EFGH", ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano), PollToken: "poll-secret", Interval: 1})
	case r.Method == http.MethodPost && path == "/api/secret-requests/"+requestID+"/poll":
		f.polls++
		if f.value == "" {
			reply(200, map[string]any{"status": "pending", "interval": 1})
			return
		}
		publicKey, _ := pv.DecodeAgentPublicKey(f.created.PublicKey)
		payload, _ := pv.NewTextPayload(f.created.Name, []byte(f.value))
		sealed, err := pv.SealSecretPayload(payload, publicKey, pv.RequestWrapContext(requestID), pv.RequestPayloadAAD(requestID))
		if err != nil {
			f.t.Error(err)
		}
		reply(200, pv.PollSecretRequestResponse{Status: pv.RequestFulfilled, Interval: 1, Kind: pv.SecretKindText, SealedSecret: sealed})
	case r.Method == http.MethodPost && path == "/api/secret-requests/"+requestID+"/ack":
		f.acks++
		reply(204, nil)
	case r.Method == http.MethodDelete && path == "/api/secret-requests/"+requestID:
		f.cancelled++
		reply(200, map[string]string{"status": "cancelled"})
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, path)
		reply(404, map[string]string{"error": "unexpected"})
	}
}

func requestOptions(fake *requestServer) Options {
	return Options{
		Server:        fake.url,
		PublicBaseURL: "https://pastevault.example",
		NewClient: func(context.Context) (*pv.Client, error) {
			client, err := pv.NewClient(fake.url, "test")
			if err != nil {
				return nil, err
			}
			client.SetAuthToken("pv_pat_test")
			return client, nil
		},
	}
}

func urlElicitationClient(handler func(*mcp.ElicitParams) string) *mcp.ClientOptions {
	return &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{URL: &mcp.URLElicitationCapabilities{}}},
		ElicitationHandler: func(_ context.Context, request *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: handler(request.Params)}, nil
		},
	}
}

func TestRequestSecretWithURLElicitation(t *testing.T) {
	for _, protocol := range []string{"", legacyProtocol} {
		name := protocol
		if name == "" {
			name = "latest"
		}
		t.Run(name, func(t *testing.T) {
			isolate(t)
			fake := newRequestServer(t)
			identity := newAgent(t, fake.url, "builder", "agent-1")
			var elicited []*mcp.ElicitParams
			client := urlElicitationClient(func(params *mcp.ElicitParams) string {
				elicited = append(elicited, params)
				// The human opens the page and answers.
				fake.answer("s3cr3t-value-123456")
				return "accept"
			})
			session := connect(t, testSetup{options: requestOptions(fake), clientOptions: client, protocol: protocol})

			raw := callTool(t, session, ToolRequestSecret, map[string]any{"name": "OPENAI_API_KEY", "reason": "run the evals", "timeout_seconds": 30})
			if strings.Contains(resultText(t, raw), "s3cr3t") {
				t.Fatal("the secret value is in the tool result")
			}
			result := structured(t, raw)
			if len(elicited) != 1 {
				t.Fatalf("elicitations = %d, want 1", len(elicited))
			}
			params := elicited[0]
			if params.Mode != "url" || params.URL != result["url"] || !strings.HasPrefix(params.URL, "https://pastevault.example/r/ABCD-EFGH#fp=pvk1_") || params.ElicitationID != requestID {
				t.Fatalf("elicitation = %+v", params)
			}
			if result["status"] != pv.RequestDelivered || result["handle"] != "pv://secret/OPENAI_API_KEY" || result["request_id"] != requestID {
				t.Fatalf("result = %v", result)
			}
			if fake.acks != 1 || fake.created.AgentID != "agent-1" || fake.created.Reason != "run the evals" {
				t.Fatalf("acks %d, created %+v", fake.acks, fake.created)
			}

			target, _ := store.Open(fake.url, identity)
			_, payload, err := target.Get("OPENAI_API_KEY")
			if err != nil || string(payload.Value) != "s3cr3t-value-123456" {
				t.Fatalf("stored secret: %v", err)
			}

			listed := structured(t, callTool(t, session, ToolListSecrets, map[string]any{}))
			secretsList, _ := listed["secrets"].([]any)
			if len(secretsList) != 1 || secretsList[0].(map[string]any)["handle"] != "pv://secret/OPENAI_API_KEY" {
				t.Fatalf("list_secrets = %v", listed)
			}
		})
	}
}

func TestRequestSecretDeclinedElicitationCancels(t *testing.T) {
	isolate(t)
	fake := newRequestServer(t)
	newAgent(t, fake.url, "builder", "agent-1")
	client := urlElicitationClient(func(*mcp.ElicitParams) string { return "decline" })
	session := connect(t, testSetup{options: requestOptions(fake), clientOptions: client})

	result := structured(t, callTool(t, session, ToolRequestSecret, map[string]any{"name": "TOKEN", "reason": "deploy"}))
	if result["status"] != pv.RequestCancelled || fake.cancelled != 1 {
		t.Fatalf("result %v, cancelled %d", result, fake.cancelled)
	}
	if pending, _ := pv.FindPendingRequest(requestID); pending != nil {
		t.Fatal("the request file was kept")
	}
}

func TestRequestSecretWithoutElicitationReturnsURL(t *testing.T) {
	for _, protocol := range []string{"", legacyProtocol} {
		t.Run("protocol="+protocol, func(t *testing.T) {
			isolate(t)
			fake := newRequestServer(t)
			newAgent(t, fake.url, "builder", "agent-1")
			// A client with form-only elicitation: no URL mode.
			client := &mcp.ClientOptions{
				Capabilities: &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{Form: &mcp.FormElicitationCapabilities{}}},
				ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
					t.Error("elicitation sent to a client without URL mode")
					return &mcp.ElicitResult{Action: "cancel"}, nil
				},
			}
			session := connect(t, testSetup{options: requestOptions(fake), clientOptions: client, protocol: protocol})

			result := structured(t, callTool(t, session, ToolRequestSecret, map[string]any{"name": "TOKEN", "reason": "deploy", "wait": true}))
			url, _ := result["url"].(string)
			if result["status"] != pv.RequestPending || !strings.Contains(url, "/r/ABCD-EFGH#fp=pvk1_") || result["message"] == nil {
				t.Fatalf("result = %v", result)
			}
			if _, ok := result["handle"]; ok {
				t.Fatalf("handle before an answer: %v", result)
			}

			status := structured(t, callTool(t, session, ToolRequestStatus, map[string]any{"request_id": requestID}))
			if status["status"] != pv.RequestPending {
				t.Fatalf("status = %v", status)
			}
			time.Sleep(1100 * time.Millisecond) // the server's poll interval
			fake.answer("value-from-the-page-1")
			status = structured(t, callTool(t, session, ToolRequestStatus, map[string]any{"request_id": "ABCD-EFGH"}))
			if status["status"] != pv.RequestDelivered || status["handle"] != "pv://secret/TOKEN" {
				t.Fatalf("status = %v", status)
			}
			if strings.Contains(resultText(t, callTool(t, session, ToolListSecrets, nil)), "value-from-the-page") {
				t.Fatal("list_secrets returned a value")
			}

			failure := toolError(t, callTool(t, session, ToolRequestStatus, map[string]any{"request_id": requestID}))
			if failure.ExitCode != pv.ExitNotFound {
				t.Fatalf("after delivery: %+v", failure)
			}
		})
	}
}

func TestRequestSecretNeedsAgent(t *testing.T) {
	isolate(t)
	fake := newRequestServer(t)
	session := connect(t, testSetup{options: requestOptions(fake)})
	failure := toolError(t, callTool(t, session, ToolRequestSecret, map[string]any{"name": "TOKEN", "reason": "deploy"}))
	if failure.ExitCode != pv.ExitUsage || !strings.Contains(failure.Message, "agent init") {
		t.Fatalf("no agent: %+v", failure)
	}
	if fake.created != nil {
		t.Fatal("a request was created without an agent")
	}
}
