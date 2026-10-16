package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── H1: case-insensitive deny lists, canonical paths ──────────────────────

func TestDenyListsIgnoreCaseAndTrailingDots(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	for _, path := range []string{".SSH/id_ed25519", ".Git/config", ".GIT/HEAD", ".Aws/credentials", "ID_RSA", ".NetRC"} {
		writeTestFile(t, filepath.Join(root, path), "x")
	}
	policy := newPathPolicy([]string{root}, nil, false)

	for _, path := range []string{".SSH/id_ed25519", ".Git/config", ".GIT/HEAD", ".Aws/credentials", "ID_RSA", ".NetRC"} {
		_, err := policy.resolveRead(path)
		refusedPath(t, err, "read "+path)
	}
	for _, path := range []string{".Claude/settings.json", ".GIT/hooks/pre-commit", ".GitHub/workflows/x.yml", "Node_Modules/.bin/x", ".VSCode/tasks.json", ".claude./settings.json", ".git /config"} {
		_, err := policy.resolveWrite(path)
		refusedPath(t, err, "write "+path)
	}
	if err := policy.checkDenied(filepath.Join(root, ".ssh.", "id_rsa"), false); err == nil {
		t.Fatal(".ssh. (trailing dot, as Windows ignores it) not refused")
	}
}

func TestCaseInsensitiveRootContainment(t *testing.T) {
	saved := caseInsensitiveRoots
	t.Cleanup(func() { caseInsensitiveRoots = saved })

	base := filepath.Join(string(filepath.Separator), "tmp", "Work", "Project")
	other := filepath.Join(string(filepath.Separator), "tmp", "work", "project", "a.txt")
	caseInsensitiveRoots = true
	if !within(base, other) {
		t.Fatal("case-insensitive file systems: different case is the same directory")
	}
	caseInsensitiveRoots = false
	if within(base, other) {
		t.Fatal("case-sensitive file systems: different case is another directory")
	}
}

func TestReadReturnsCanonicalPath(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "dir", "a.txt"), "a")
	policy := newPathPolicy([]string{root}, nil, false)
	got, err := policy.resolveRead(filepath.Join(root, "dir", "..", "dir", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(root, "dir", "a.txt"))
	if !strings.EqualFold(got, want) {
		t.Fatalf("canonical = %q, want %q", got, want)
	}
}

// ── M1: broad roots, credential files ─────────────────────────────────────

func TestBroadRootsAndHomeCredentials(t *testing.T) {
	isolate(t)
	base := t.TempDir()
	home := filepath.Join(base, "home", "me")
	project := filepath.Join(home, "project")
	writeTestFile(t, filepath.Join(project, "a.txt"), "a")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if roots := newPathPolicy([]string{home, filepath.Dir(home)}, nil, false).roots; len(roots) != 0 {
		// Only the cwd fallback could remain; it is never home either.
		for _, root := range roots {
			if within(root, home) {
				t.Fatalf("home or an ancestor of home accepted as a root: %v", roots)
			}
		}
	}
	if !TooBroadRoot(home) || !TooBroadRoot(filepath.Dir(home)) || TooBroadRoot(project) {
		t.Fatal("TooBroadRoot")
	}
	if roots := newPathPolicy([]string{home}, nil, true).roots; len(roots) != 1 {
		t.Fatalf("--allow-home-root: roots = %v", roots)
	}

	policy := newPathPolicy([]string{home}, nil, true)
	for _, path := range []string{
		".claude/.credentials.json", ".codex/auth.json", ".gemini/oauth_creds.json", ".cargo/credentials.toml",
		".config/gh/hosts.yml", ".docker/config.json", ".kube/config", ".npmrc", ".pypirc", ".netrc",
		".bash_history", ".zsh_history", ".local/share/fish/fish_history", ".git-credentials", ".config/gcloud/credentials.db",
		".azure/accessTokens.json", ".password-store/x.gpg", "project/.git/config",
	} {
		writeTestFile(t, filepath.Join(home, path), "secret")
		_, err := policy.resolveRead(path)
		refusedPath(t, err, "read ~/"+path)
	}
	if _, err := policy.resolveRead("project/a.txt"); err != nil {
		t.Fatalf("ordinary file: %v", err)
	}
}

// ── H2: safe names, no planting, overwrite only own files ─────────────────

func TestSafeFileNames(t *testing.T) {
	for name, want := range map[string]string{
		"report.pdf":      "report.pdf",
		".mcp.json":       "received-slug1-mcp.json",
		"CLAUDE.md":       "received-slug1-CLAUDE.md",
		"claude.MD.":      "received-slug1-claude.MD",
		"AGENTS.md":       "received-slug1-AGENTS.md",
		".envrc":          "received-slug1-envrc",
		".env.production": "received-slug1-env.production",
		"package.json":    "received-slug1-package.json",
		"Makefile":        "received-slug1-Makefile",
		"go.mod":          "received-slug1-go.mod",
		"pyproject.toml":  "received-slug1-pyproject.toml",
		"deploy.sh":       "received-slug1-deploy.sh.txt",
		"CON.txt":         "received-slug1-CON.txt",
		"a/b\\c:d.txt":    "a_b_c_d.txt",
		"...":             "file",
		"notes.md ":       "notes.md",
		"id_rsa":          "received-slug1-id_rsa",
	} {
		if got := safeFileName(name, "slug1"); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestExplicitTargetsMustBeSafeNames(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	policy := newPathPolicy([]string{root}, nil, false)
	for _, name := range []string{"CLAUDE.md", ".mcp.json", ".env", "package.json", "deploy.sh", "GEMINI.MD"} {
		_, err := policy.resolveWrite(name)
		refusedPath(t, err, "explicit target "+name)
	}
	if _, err := policy.resolveWrite("notes.txt"); err != nil {
		t.Fatal(err)
	}
}

// fakeGet is a RunCLI that behaves like "get": it writes the given files
// into --out DIR (or the single content into -o FILE) and prints JSON.
type fakeGet struct {
	t     *testing.T
	kind  string
	files map[string]string
	calls int
}

func (f *fakeGet) run(_ context.Context, args []string, _ []byte) CLIResult {
	f.calls++
	if args[0] != "get" {
		f.t.Errorf("unexpected command %v", args)
		return CLIResult{Exit: 1}
	}
	result := map[string]any{"slug": "slug1", "kind": f.kind, "size_bytes": 1, "burned": true, "views_remaining": 0}
	for index, arg := range args {
		switch arg {
		case "--out":
			for name, content := range f.files {
				if err := os.WriteFile(filepath.Join(args[index+1], name), []byte(content), 0o600); err != nil {
					f.t.Error(err)
				}
			}
		case "-o":
			for _, content := range f.files {
				if err := os.WriteFile(args[index+1], []byte(content), 0o600); err != nil {
					f.t.Error(err)
				}
			}
		case "--save":
			result["saved_as"] = "pv://secret/" + args[index+1]
		}
	}
	body, _ := json.Marshal(result)
	return CLIResult{Stdout: body}
}

func TestReceiveChoosesSafeNames(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	realRoot, _ := filepath.EvalSymlinks(root)
	fake := &fakeGet{t: t, kind: "file_share", files: map[string]string{".mcp.json": "{}", "CLAUDE.md": "do bad things", "notes.txt": "ok", "install.sh": "rm -rf"}}
	session := connect(t, testSetup{options: Options{RunCLI: fake.run, Roots: []string{root}}})

	result := structured(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "output_path": "inbox/"}))
	inbox := filepath.Join(realRoot, "inbox")
	for _, risky := range []string{".mcp.json", "CLAUDE.md", "install.sh"} {
		if _, err := os.Lstat(filepath.Join(inbox, risky)); err == nil {
			t.Fatalf("%s was planted", risky)
		}
	}
	for name, content := range map[string]string{"received-slug1-mcp.json": "{}", "received-slug1-CLAUDE.md": "do bad things", "notes.txt": "ok", "received-slug1-install.sh.txt": "rm -rf"} {
		data, err := os.ReadFile(filepath.Join(inbox, name))
		if err != nil || string(data) != content {
			t.Fatalf("%s: %q %v", name, data, err)
		}
		if runtime.GOOS != "windows" {
			if info, _ := os.Stat(filepath.Join(inbox, name)); info.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode %v", name, info.Mode().Perm())
			}
		}
	}
	if files, _ := result["files"].([]any); len(files) != 4 {
		t.Fatalf("files = %v", result["files"])
	}
	entries, _ := os.ReadDir(inbox)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), stagingPrefix) {
			t.Fatal("staging directory left behind")
		}
	}

	// A second share with the same names: renamed, never replaced.
	fake.files = map[string]string{"notes.txt": "second"}
	structured(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "output_path": "inbox", "overwrite": true}))
	if data, _ := os.ReadFile(filepath.Join(inbox, "notes.txt")); string(data) != "ok" {
		t.Fatal("a directory receive replaced a file")
	}
	if data, _ := os.ReadFile(filepath.Join(inbox, "notes (1).txt")); string(data) != "second" {
		t.Fatal("clash not renamed")
	}
}

func TestReceiveDefaultDirectory(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	realRoot, _ := filepath.EvalSymlinks(root)
	fake := &fakeGet{t: t, kind: "paste", files: map[string]string{"Notes.txt": "hello"}}
	session := connect(t, testSetup{options: Options{RunCLI: fake.run, Roots: []string{root}}})
	result := structured(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl"}))
	want := filepath.Join(realRoot, defaultReceiveDir, "Notes.txt")
	if result["written_to"] != want {
		t.Fatalf("written_to = %v, want %s", result["written_to"], want)
	}
}

func TestReceiveOverwriteOnlyOwnFiles(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	realRoot, _ := filepath.EvalSymlinks(root)
	fake := &fakeGet{t: t, kind: "paste", files: map[string]string{"x": "one"}}
	session := connect(t, testSetup{options: Options{RunCLI: fake.run, Roots: []string{root}}})

	// A file receive did not write: never replaced, nothing opened.
	writeTestFile(t, filepath.Join(root, "existing.txt"), "user's")
	failure := toolError(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "output_path": "existing.txt", "overwrite": true}))
	if failure.Code != CodePathRefused || fake.calls != 0 || !strings.Contains(failure.Message, "earlier in this session") {
		t.Fatalf("overwrite of a foreign file: %+v (calls %d)", failure, fake.calls)
	}

	structured(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "output_path": "out.txt"}))
	failure = toolError(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "output_path": "out.txt"}))
	if failure.ExitCode != pv.ExitLocalFile || fake.calls != 1 {
		t.Fatalf("existing without overwrite: %+v", failure)
	}
	fake.files = map[string]string{"x": "two"}
	structured(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "output_path": "out.txt", "overwrite": true}))
	if data, _ := os.ReadFile(filepath.Join(realRoot, "out.txt")); string(data) != "two" {
		t.Fatalf("own file not replaced: %q", data)
	}

	// Swapped for another file (e.g. a symlink) after receive wrote it: refused.
	if runtime.GOOS != "windows" {
		target := filepath.Join(realRoot, "out.txt")
		_ = os.Remove(target)
		_ = os.Symlink(filepath.Join(realRoot, "existing.txt"), target)
		failure = toolError(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "output_path": "out.txt", "overwrite": true}))
		if failure.ExitCode != pv.ExitLocalFile {
			t.Fatalf("symlink swapped in: %+v", failure)
		}
		if data, _ := os.ReadFile(filepath.Join(realRoot, "existing.txt")); string(data) != "user's" {
			t.Fatal("wrote through a symlink")
		}
	}
}

// ── M3: save_as never replaces another secret ─────────────────────────────

func TestReceiveSaveAsKeepsOtherSecrets(t *testing.T) {
	isolate(t)
	server := "http://127.0.0.1:9"
	identity := newAgent(t, server, "tester", "agent-1")
	target, _ := store.Open(server, identity)
	payload, _ := pv.NewTextPayload("OPENAI_API_KEY", []byte("real-key"))
	if _, err := target.Put("OPENAI_API_KEY", payload, store.Source{Type: store.SourceRequest, Ref: "req"}, false); err != nil {
		t.Fatal(err)
	}
	fake := &fakeGet{t: t, kind: "paste"}
	session := connect(t, testSetup{options: Options{Server: server, RunCLI: fake.run}})

	failure := toolError(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "save_as": "OPENAI_API_KEY", "overwrite": true}))
	if failure.ExitCode != pv.ExitLocalFile || fake.calls != 0 || !strings.Contains(failure.Message, "another save_as name") {
		t.Fatalf("overwrite of a requested secret: %+v", failure)
	}

	// A secret saved from the same share may be replaced.
	shared, _ := pv.NewTextPayload("FROM_SHARE", []byte("v1"))
	if _, err := target.Put("FROM_SHARE", shared, store.Source{Type: store.SourceShare, Ref: "abcdefghijkl"}, false); err != nil {
		t.Fatal(err)
	}
	structured(t, callTool(t, session, ToolReceive, map[string]any{"ref": "abcdefghijkl", "save_as": "FROM_SHARE", "overwrite": true}))
	if fake.calls != 1 {
		t.Fatalf("calls = %d", fake.calls)
	}
}

// ── M4: only the configured server's shares ───────────────────────────────

func TestReceiveRefusesOtherHosts(t *testing.T) {
	isolate(t)
	fake := &fakeGet{t: t, kind: "paste"}
	session := connect(t, testSetup{options: Options{Server: "https://api.pastevault.dev", PublicBaseURL: "https://pastevault.dev", RunCLI: fake.run, Roots: []string{t.TempDir()}}})
	failure := toolError(t, callTool(t, session, ToolReceive, map[string]any{"ref": "https://evil.example/p/abcdefghijkl", "output_path": "x.txt"}))
	if failure.Code != "host_not_allowed" || fake.calls != 0 {
		t.Fatalf("other host: %+v", failure)
	}
	// The web origin of the configured server is fine.
	fake.files = map[string]string{"x": "ok"}
	structured(t, callTool(t, session, ToolReceive, map[string]any{"ref": "https://pastevault.dev/p/abcdefghijkl", "output_path": "y.txt"}))

	anyHost := connect(t, testSetup{options: Options{Server: "https://api.pastevault.dev", RunCLI: fake.run, Roots: []string{t.TempDir()}, AllowAnyHost: true}})
	structured(t, callTool(t, anyHost, ToolReceive, map[string]any{"ref": "https://other.example/p/abcdefghijkl", "output_path": "z.txt"}))
}

// ── L2: signed requestState is bound to its tool ──────────────────────────

func TestRequestStateBoundToTool(t *testing.T) {
	server, err := New(Options{RunCLI: noCLI(t), NewClient: func(context.Context) (*pv.Client, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	state := server.signState(ToolRequestSecret, rootsInputKey)
	if _, ok := server.verifyState(ToolSendFile, state); ok {
		t.Fatal("a request_secret state was accepted by send_file")
	}
	if value, ok := server.verifyState(ToolRequestSecret, state); !ok || value != rootsInputKey {
		t.Fatal("state does not verify for its own tool")
	}
	if _, ok := server.verifyState(ToolRequestSecret, state+"x"); ok {
		t.Fatal("tampered state accepted")
	}

	isolate(t)
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "a.txt"), "a")
	session := connect(t, testSetup{options: Options{Roots: []string{root}}})
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:           ToolSendFile,
		Arguments:      map[string]any{"paths": []string{"a.txt"}},
		InputResponses: mcp.InputResponseMap{rootsInputKey: &mcp.ListRootsResult{Roots: []*mcp.Root{{URI: fileURI(string(filepath.Separator))}}}},
		RequestState:   state,
	})
	if err != nil {
		t.Fatal(err)
	}
	if failure := toolError(t, result); failure.ExitCode != pv.ExitUsage {
		t.Fatalf("replayed roots response: %+v", failure)
	}
}

// ── M2: detector cases ────────────────────────────────────────────────────

func TestSecretLikeFormats(t *testing.T) {
	detected := []string{
		"password = hunter2hunter2",
		"db:\n  password: \"correct horse\"",
		`{"api_key": "abcd1234efgh"}`,
		"[auth]\nclient_secret=xyz12345",
		"export SECRET_TOKEN = abcdef123",
		"aws_access_key\t: AKIAEXAMPLE",
		"DB_PASS = s3cret!",
		"-----begin rsa private key-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"pk_live_abcdefgh12345678",
		"rk_live_abcdefgh12345678",
		"whsec_abcdefghijklmnop",
		"ѕk-ргоj-аbcdefghijklmnopqrst",              // Cyrillic homoglyphs
		"ｓｋ－ｐｒｏｊ－ａｂｃｄｅｆｇｈｉｊｋｌ",                      // full-width
		"gh​p_abcdefghijklmnopqrstuvwxyz0123456789", // zero-width space
		"key: \"ghp_abcdefghijklmnop\"\n  \"qrstuvwxyz0123456789\"",
		"token part one: sk-abc\n  defghijklmnop",
		"Authorization: Bearer abcdefghijklmnopqrstuvwx",
	}
	for _, text := range detected {
		if !IsSecretLike(text) {
			t.Errorf("not detected: %q", text)
		}
	}
	for _, text := range []string{"hello world", "The release is on Friday.\nBring snacks.", "x = 5", "see the docs at https://example.com/docs"} {
		if reason := SecretLikeReason(text); reason != "" {
			t.Errorf("%q flagged (%s)", text, reason)
		}
	}
}

// ── L3: request_status is not read-only ───────────────────────────────────

func TestRequestStatusAnnotations(t *testing.T) {
	isolate(t)
	session := connect(t, testSetup{})
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(listed.Tools, func(tool *mcp.Tool) bool { return tool.Name == ToolRequestStatus })
	if listed.Tools[index].Annotations.ReadOnlyHint {
		t.Fatal("request_status writes the store; it is not read-only")
	}
	receive := slices.IndexFunc(listed.Tools, func(tool *mcp.Tool) bool { return tool.Name == ToolReceive })
	if hint := listed.Tools[receive].Annotations.OpenWorldHint; hint == nil || !*hint {
		t.Fatal("receive talks to a server: openWorld")
	}
}
