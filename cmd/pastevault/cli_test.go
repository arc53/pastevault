package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden files")

// fakeServer implements the paste endpoints of the PasteVault API in memory.
type fakeServer struct {
	*httptest.Server
	mu           sync.Mutex
	pastes       map[string]*fakePaste
	consumed     int
	capabilities map[string]any
	lastCreate   map[string]any
}

type fakePaste struct {
	request  map[string]any
	views    int
	maxViews int
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()

	server := &fakeServer{
		pastes: map[string]*fakePaste{},
		capabilities: map[string]any{
			"api_version": 2,
			"file_shares": map[string]any{"enabled": false},
			"features":    map[string]any{"expires_in_minutes": true, "max_views": true},
			"limits":      map[string]any{"max_views": 1000},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/capabilities", func(w http.ResponseWriter, _ *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		writeTestJSON(w, 200, server.capabilities)
	})
	mux.HandleFunc("GET /api/auth/get-session", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, 200, nil)
	})
	mux.HandleFunc("POST /api/pastes", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeTestJSON(w, 400, map[string]any{"error": "bad json"})
			return
		}
		server.mu.Lock()
		defer server.mu.Unlock()
		server.lastCreate = body
		slug, _ := body["slug"].(string)
		paste := &fakePaste{request: body}
		if value, ok := body["max_views"].(float64); ok {
			paste.maxViews = int(value)
		} else if body["burn_after_read"] == true {
			paste.maxViews = 1
		}
		server.pastes[slug] = paste
		var maxViews any
		if paste.maxViews > 0 {
			maxViews = paste.maxViews
		}
		writeTestJSON(w, 201, map[string]any{"slug": slug, "expires_at": "2026-10-17T12:00:00.000Z", "max_views": maxViews})
	})
	mux.HandleFunc("GET /api/pastes/{slug}/meta", func(w http.ResponseWriter, r *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		paste, status := server.find(r.PathValue("slug"))
		if paste == nil {
			writeTestJSON(w, status, map[string]any{"error": pasteError(status)})
			return
		}
		salt, _ := paste.request["salt"].(string)
		kdf, _ := paste.request["kdf_params"].(string)
		writeTestJSON(w, 200, map[string]any{
			"slug": r.PathValue("slug"), "password_protected": salt != "", "salt": salt, "kdf_params": kdf,
			"max_views": nullableInt(paste.maxViews), "views_remaining": nullableInt(paste.maxViews - paste.views),
			"recipient": nil, "requires_recipient_auth": false, "expires_at": "2026-10-17T12:00:00.000Z",
		})
	})
	mux.HandleFunc("GET /api/pastes/{slug}", func(w http.ResponseWriter, r *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		slug := r.PathValue("slug")
		paste, status := server.find(slug)
		if paste == nil {
			writeTestJSON(w, status, map[string]any{"error": pasteError(status)})
			return
		}
		paste.views++
		server.consumed++
		burned := paste.maxViews > 0 && paste.views >= paste.maxViews
		response := map[string]any{
			"metadata": map[string]any{
				"id": "paste-id", "slug": slug, "created_at": "2026-10-16T12:00:00.000Z", "expires_at": "2026-10-17T12:00:00.000Z",
				"burn_after_read": paste.maxViews == 1, "is_burned": burned, "view_count": paste.views,
				"max_views": nullableInt(paste.maxViews), "views_remaining": nullableInt(paste.maxViews - paste.views),
			},
			"ciphertext": paste.request["ciphertext"], "nonce": paste.request["nonce"],
			"salt": paste.request["salt"], "kdf_params": paste.request["kdf_params"],
		}
		writeTestJSON(w, 200, response)
	})

	server.Server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func (s *fakeServer) find(slug string) (*fakePaste, int) {
	paste := s.pastes[slug]
	switch {
	case paste == nil:
		return nil, 404
	case paste.maxViews > 0 && paste.views >= paste.maxViews:
		return nil, 410
	}

	return paste, 200
}

// pasteError matches the real server's messages.
func pasteError(status int) string {
	if status == 410 {
		return "Paste has been burned"
	}

	return "Paste not found"
}

func nullableInt(value int) any {
	if value <= 0 {
		return nil
	}

	return value
}

func writeTestJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type runResult struct {
	exit   int
	stdout string
	stderr string
}

// runCLI runs one invocation with the given stdin. stdinTTY simulates an
// interactive terminal.
func runCLI(t *testing.T, stdin string, stdinTTY bool, args ...string) runResult {
	t.Helper()

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:            strings.NewReader(stdin),
		stdout:           &stdout,
		stderr:           &stderr,
		stdinIsTerminal:  func() bool { return stdinTTY },
		stdoutIsTerminal: func() bool { return false },
		promptPassword: func(string) (string, error) {
			return "", fmt.Errorf("no terminal in tests")
		},
	}

	exit := a.run(context.Background(), args)
	return runResult{exit: exit, stdout: stdout.String(), stderr: stderr.String()}
}

// isolate gives each test its own config dir and a clean environment.
func isolate(t *testing.T, server string) {
	t.Helper()
	t.Setenv(pv.EnvConfigDir, t.TempDir())
	t.Setenv("PASTEVAULT_SERVER", server)
	t.Setenv("PASTEVAULT_PUBLIC_URL", "")
	t.Setenv(pv.EnvToken, "")
	t.Setenv(pv.EnvPassword, "")
	t.Setenv("PASTEVAULT_JSON", "")
}

func decodeJSON(t *testing.T, text string) map[string]any {
	t.Helper()

	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(text))
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, text)
	}
	if decoder.More() {
		t.Fatalf("stdout holds more than one JSON value:\n%s", text)
	}

	return value
}

var (
	slugInURL = regexp.MustCompile(`/p/[A-Za-z0-9_-]{12}`)
	slugInAPI = regexp.MustCompile(`/api/pastes/[A-Za-z0-9_-]{12}`)
	keyInURL  = regexp.MustCompile(`#k=[A-Za-z0-9_-]{43}`)
)

// assertGolden compares JSON output with testdata/golden/<name>.json after
// replacing the server URL, slugs and keys with placeholders.
func assertGolden(t *testing.T, name, serverURL, output string) {
	t.Helper()

	normalized := strings.ReplaceAll(output, serverURL, "<server>")
	normalized = slugInURL.ReplaceAllString(normalized, "/p/<slug>")
	normalized = keyInURL.ReplaceAllString(normalized, "#k=<key>")
	normalized = slugInAPI.ReplaceAllString(normalized, "/api/pastes/<slug>")

	var value map[string]any
	if err := json.Unmarshal([]byte(normalized), &value); err != nil {
		t.Fatalf("%s: not JSON: %v\n%s", name, err, output)
	}
	if slug, ok := value["slug"].(string); ok && len(slug) == 12 {
		value["slug"] = "<slug>"
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	pretty := buffer.Bytes()

	path := filepath.Join("testdata", "golden", name+".json")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pretty, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./cmd/pastevault -run %s -update)", err, t.Name())
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), pretty) {
		t.Fatalf("%s differs from golden file:\n%s", name, pretty)
	}
}

func TestPutStdinThenGetStdoutRoundTrip(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)

	put := runCLI(t, "hello from stdin\n", false, "put", "-", "--json")
	if put.exit != 0 {
		t.Fatalf("put exit %d: %s", put.exit, put.stderr)
	}
	assertGolden(t, "put_paste", server.URL, put.stdout)
	created := decodeJSON(t, put.stdout)

	get := runCLI(t, "", false, "get", created["url"].(string), "--stdout")
	if get.exit != 0 || get.stdout != "hello from stdin\n" {
		t.Fatalf("get exit %d stdout %q stderr %s", get.exit, get.stdout, get.stderr)
	}

	// The plaintext is the web's PasteContent.
	request := server.lastCreate
	if request["expires_in_minutes"] != float64(1440) || request["expires_in_hours"] != nil {
		t.Fatalf("default expiry: %v", request)
	}
}

func TestPutWithoutArgumentsReadsPipedStdin(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)

	put := runCLI(t, "piped", false, "put", "-q")
	if put.exit != 0 || !strings.HasPrefix(put.stdout, server.URL+"/p/") || strings.Count(put.stdout, "\n") != 1 {
		t.Fatalf("exit %d stdout %q stderr %s", put.exit, put.stdout, put.stderr)
	}

	tty := runCLI(t, "", true, "put")
	if tty.exit != pv.ExitUsage {
		t.Fatalf("put on a terminal without input: exit %d", tty.exit)
	}

	empty := runCLI(t, "  \n", false, "put", "-")
	if empty.exit != pv.ExitUsage || !strings.Contains(empty.stderr, "empty") {
		t.Fatalf("empty stdin: exit %d %s", empty.exit, empty.stderr)
	}

	mixed := runCLI(t, "x", false, "put", "-", "file.txt")
	if mixed.exit != pv.ExitUsage {
		t.Fatalf("- with files: exit %d", mixed.exit)
	}
}

func TestPutTextOptionsAndGetJSON(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)

	put := runCLI(t, "", false, "put", "--text", "echo hi", "--title", "script", "--language", "bash", "--expires", "15m", "--max-views", "2", "--json")
	if put.exit != 0 {
		t.Fatalf("put exit %d: %s", put.exit, put.stderr)
	}
	if !strings.Contains(put.stderr, "process list") {
		t.Fatalf("--text should warn about argv: %s", put.stderr)
	}
	assertGolden(t, "put_paste_options", server.URL, put.stdout)
	if server.lastCreate["expires_in_minutes"] != float64(15) || server.lastCreate["max_views"] != float64(2) {
		t.Fatalf("request: %v", server.lastCreate)
	}
	created := decodeJSON(t, put.stdout)
	url := created["url"].(string)

	get := runCLI(t, "", false, "get", url, "--json", "--stdout")
	if get.exit != 0 {
		t.Fatalf("get exit %d: %s", get.exit, get.stderr)
	}
	assertGolden(t, "get_paste_stdout", server.URL, get.stdout)

	// Second view burns it; the third is gone (exit 5) and fails at /meta.
	if second := runCLI(t, "", false, "get", url, "--stdout"); second.exit != 0 || second.stdout != "echo hi" {
		t.Fatalf("second view: %+v", second)
	}
	before := server.consumed
	gone := runCLI(t, "", false, "get", url, "--json", "--stdout")
	if gone.exit != pv.ExitGone || server.consumed != before {
		t.Fatalf("burned: exit %d consumed %d->%d", gone.exit, before, server.consumed)
	}
	assertGolden(t, "error_gone", server.URL, gone.stdout)
	if !strings.HasPrefix(gone.stderr, "Error: ") {
		t.Fatalf("error must also go to stderr: %q", gone.stderr)
	}
}

func TestGetFailsBeforeConsuming(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)

	put := runCLI(t, "secret", false, "put", "-", "--burn", "--json")
	if put.exit != 0 {
		t.Fatalf("put: %+v", put)
	}
	url := decodeJSON(t, put.stdout)["url"].(string)
	withoutKey := strings.SplitN(url, "#", 2)[0]

	cases := []struct {
		name string
		args []string
		exit int
	}{
		{"missing key", []string{"get", withoutKey, "--stdout"}, pv.ExitUsage},
		{"json without destination", []string{"get", url, "--json"}, pv.ExitUsage},
		{"two destinations", []string{"get", url, "--stdout", "--out", "."}, pv.ExitUsage},
		{"existing -o target", []string{"get", url, "-o", "cli_test.go"}, pv.ExitLocalFile},
		{"missing paste", []string{"get", server.URL + "/p/doesnotexist", "--stdout"}, pv.ExitNotFound},
		{"bad key", []string{"get", withoutKey + "#k=abc", "--stdout"}, pv.ExitUsage},
	}
	for _, testCase := range cases {
		result := runCLI(t, "", false, testCase.args...)
		if result.exit != testCase.exit {
			t.Errorf("%s: exit %d, want %d (%s)", testCase.name, result.exit, testCase.exit, result.stderr)
		}
	}
	if server.consumed != 0 {
		t.Fatalf("a failing get consumed %d views", server.consumed)
	}

	// The burn-after-read paste still opens once, then is gone.
	if ok := runCLI(t, "", false, "get", url, "--stdout"); ok.exit != 0 || ok.stdout != "secret" {
		t.Fatalf("open: %+v", ok)
	}
	if again := runCLI(t, "", false, "get", url, "--stdout"); again.exit != pv.ExitGone {
		t.Fatalf("reopen: exit %d", again.exit)
	}
}

func TestPutKeyOutAndGetKeySources(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "share.key")

	if result := runCLI(t, "x", false, "put", "-", "--no-key-in-output"); result.exit != pv.ExitUsage {
		t.Fatalf("--no-key-in-output without --key-out: exit %d", result.exit)
	}

	put := runCLI(t, "keyed content", false, "put", "-", "--no-key-in-output", "--key-out", keyPath, "--json")
	if put.exit != 0 {
		t.Fatalf("put: %+v", put)
	}
	escapedKeyPath, _ := json.Marshal(keyPath) // Windows paths are escaped in JSON
	assertGolden(t, "put_paste_no_key", server.URL, strings.ReplaceAll(put.stdout, strings.Trim(string(escapedKeyPath), `"`), "<key-file>"))
	created := decodeJSON(t, put.stdout)
	if strings.Contains(created["url"].(string), "#") || created["key_in_url"] != false {
		t.Fatalf("URL must not carry the key: %v", created)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode: %v %v", info, err)
		}
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// The key file is never overwritten.
	if again := runCLI(t, "x", false, "put", "-", "--no-key-in-output", "--key-out", keyPath); again.exit != pv.ExitLocalFile {
		t.Fatalf("existing --key-out: exit %d", again.exit)
	}

	url := created["url"].(string)
	if got := runCLI(t, "", false, "get", url, "--key-file", keyPath, "--stdout"); got.exit != 0 || got.stdout != "keyed content" {
		t.Fatalf("--key-file: %+v", got)
	}
	t.Setenv("PV_SHARE_KEY", strings.TrimSpace(string(keyData)))
	if got := runCLI(t, "", false, "get", created["slug"].(string), "--key-env", "PV_SHARE_KEY", "--stdout"); got.exit != 0 || got.stdout != "keyed content" {
		t.Fatalf("--key-env with a bare slug: %+v", got)
	}
	if got := runCLI(t, string(keyData), false, "get", "pv://share/"+created["slug"].(string), "--key-stdin", "--stdout"); got.exit != 0 || got.stdout != "keyed content" {
		t.Fatalf("--key-stdin with a handle: %+v", got)
	}
	got := runCLI(t, "", false, "get", url, "--key", strings.TrimSpace(string(keyData)), "--stdout")
	if got.exit != 0 || !strings.Contains(got.stderr, "process list") {
		t.Fatalf("--key should work with a warning: %+v", got)
	}
	if strings.Contains(got.stderr, strings.TrimSpace(string(keyData))) {
		t.Fatal("stderr echoed the key")
	}
}

func TestPutPasswordFromFileAndEnv(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)
	passwordPath := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(passwordPath, []byte("s3cret pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	put := runCLI(t, "protected", false, "put", "-", "--password-file", passwordPath, "--json")
	if put.exit != 0 {
		t.Fatalf("put: %+v", put)
	}
	created := decodeJSON(t, put.stdout)
	if created["password_protected"] != true || created["key_in_url"] != false || strings.Contains(created["url"].(string), "#") {
		t.Fatalf("output: %v", created)
	}
	if server.lastCreate["kdf_params"] != `{"iterations":600000,"algorithm":"PBKDF2","hash":"SHA-256","keyLen":32}` {
		t.Fatalf("kdf_params: %v", server.lastCreate["kdf_params"])
	}

	slug := created["slug"].(string)
	if missing := runCLI(t, "", false, "get", slug, "--stdout"); missing.exit != pv.ExitUsage || server.consumed != 0 {
		t.Fatalf("no password: exit %d consumed %d", missing.exit, server.consumed)
	}

	t.Setenv(pv.EnvPassword, "wrong")
	if wrong := runCLI(t, "", false, "get", slug, "--stdout"); wrong.exit != pv.ExitDecrypt {
		t.Fatalf("wrong password: exit %d (%s)", wrong.exit, wrong.stderr)
	}
	t.Setenv(pv.EnvPassword, "s3cret pass")
	if right := runCLI(t, "", false, "get", slug, "--stdout"); right.exit != 0 || right.stdout != "protected" {
		t.Fatalf("right password: %+v", right)
	}

	// --password with no terminal and no other source fails before creating.
	t.Setenv(pv.EnvPassword, "")
	before := len(server.pastes)
	if result := runCLI(t, "x", false, "put", "-", "--password"); result.exit != pv.ExitUsage || len(server.pastes) != before {
		t.Fatalf("--password without terminal: exit %d", result.exit)
	}
}

func TestPutEnvFileBecomesPaste(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("API_KEY=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	put := runCLI(t, "", true, "put", envPath, "--json")
	if put.exit != 0 {
		t.Fatalf("put: %+v", put)
	}
	created := decodeJSON(t, put.stdout)
	if created["kind"] != "paste" {
		t.Fatalf("a .env file must become a paste: %v", created)
	}

	get := runCLI(t, "", false, "get", created["url"].(string), "--json", "--stdout")
	result := decodeJSON(t, get.stdout)
	if result["title"] != ".env" || result["language_hint"] != "bash" || result["render_mode"] != "plain" || result["content"] != "API_KEY=abc\n" {
		t.Fatalf("paste content: %v", result)
	}

	// Other files need file sharing, which this server lacks (exit 14).
	other := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if files := runCLI(t, "", true, "put", other); files.exit != pv.ExitUnsupported {
		t.Fatalf("file share on a server without file sharing: exit %d (%s)", files.exit, files.stderr)
	}
	if forced := runCLI(t, "", true, "put", other, "--as", "paste", "-q"); forced.exit != 0 {
		t.Fatalf("--as paste: %+v", forced)
	}
}

func TestExpiryFallbackOnOldServer(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)
	server.capabilities = map[string]any{"file_shares": map[string]any{"enabled": false}}

	if result := runCLI(t, "x", false, "put", "-", "--expires", "90m"); result.exit != pv.ExitUnsupported {
		t.Fatalf("90m on an old server: exit %d", result.exit)
	}
	if result := runCLI(t, "x", false, "put", "-", "--expires", "2h"); result.exit != 0 || server.lastCreate["expires_in_hours"] != float64(2) || server.lastCreate["expires_in_minutes"] != nil {
		t.Fatalf("2h on an old server: exit %d request %v", result.exit, server.lastCreate)
	}
	result := runCLI(t, "x", false, "put", "-", "--expires-hours", "3")
	if result.exit != 0 || server.lastCreate["expires_in_hours"] != float64(3) || !strings.Contains(result.stderr, "deprecated") {
		t.Fatalf("--expires-hours: exit %d %v %s", result.exit, server.lastCreate, result.stderr)
	}
	if result := runCLI(t, "x", false, "put", "-", "--max-views", "3"); result.exit != pv.ExitUnsupported {
		t.Fatalf("--max-views on an old server: exit %d", result.exit)
	}
}

func TestUsageErrorsAreJSONWithJSONFlagOrEnv(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)

	result := runCLI(t, "", false, "put", "--json", "--as", "bogus", "-")
	if result.exit != pv.ExitUsage {
		t.Fatalf("exit %d", result.exit)
	}
	assertGolden(t, "error_usage", server.URL, result.stdout)

	t.Setenv("PASTEVAULT_JSON", "1")
	unknown := runCLI(t, "", false, "frobnicate")
	if unknown.exit != pv.ExitUsage || decodeJSON(t, unknown.stdout)["error"] == nil {
		t.Fatalf("unknown command: %+v", unknown)
	}
	badFlag := runCLI(t, "", false, "get", "--no-such-flag", "abc")
	if badFlag.exit != pv.ExitUsage || decodeJSON(t, badFlag.stdout)["error"] == nil {
		t.Fatalf("bad flag: %+v", badFlag)
	}
}

func TestAccountCommandsNeedCredentials(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)

	for _, args := range [][]string{{"list"}, {"status", "abcdef"}, {"revoke", "abcdef"}, {"audit"}, {"whoami"}, {"token", "list"}} {
		result := runCLI(t, "", false, append(args, "--json")...)
		if result.exit != pv.ExitAuth {
			t.Errorf("%v: exit %d (%s)", args, result.exit, result.stderr)
		}
	}

	// Token management ignores PASTEVAULT_TOKEN: it is session-only.
	t.Setenv(pv.EnvToken, pv.APITokenPrefix+strings.Repeat("a", 52))
	result := runCLI(t, "", false, "token", "create", "--name", "x", "--json")
	if result.exit != pv.ExitAuth || decodeJSON(t, result.stdout)["error"].(map[string]any)["code"] != pv.CodeSessionRequired {
		t.Fatalf("token create with only an env token: %+v", result)
	}
}

func TestParseArgsInterspersed(t *testing.T) {
	a := &app{stderr: io.Discard}
	fs, common := a.newFlagSet("x", "x")
	verbose := fs.Bool("v", false, "")

	positional, err := parseArgs(fs, []string{"one", "--json", "two", "-v", "--", "--three", "-q"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(positional, " ") != "one two --three -q" || !common.json || !*verbose || common.quiet {
		t.Fatalf("positional %q json %v v %v quiet %v", positional, common.json, *verbose, common.quiet)
	}
}
