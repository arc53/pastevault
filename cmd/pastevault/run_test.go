package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

const offlineServer = "http://127.0.0.1:9"

// withAgent isolates the config dir and creates a default agent key, so
// the local store works (no server is involved).
func withAgent(t *testing.T) *pv.AgentIdentity {
	t.Helper()
	isolate(t, offlineServer)
	t.Setenv(pv.EnvAgent, "")
	t.Setenv(pv.EnvAgentKey, "")
	keys, err := pv.GenerateAgentKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	identity := pv.NewAgentIdentity(offlineServer, "tester", keys)
	path, _ := pv.AgentKeyPath(offlineServer, "tester")
	if err := pv.SaveAgentIdentity(identity, path, false); err != nil {
		t.Fatal(err)
	}
	return identity
}

func importSecret(t *testing.T, name, value string) {
	t.Helper()
	result := runCLI(t, value, false, "secret", "import", name, "--from-stdin")
	if result.exit != 0 {
		t.Fatalf("secret import %s: exit %d: %s", name, result.exit, result.stderr)
	}
}

func writeFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
}

func TestRunMasksAndStripsCredentials(t *testing.T) {
	requireShell(t)
	identity := withAgent(t)
	secret := "sk-live-0123456789abcdef"
	importSecret(t, "API_KEY", secret)
	importSecret(t, "SHORT", "abc")
	importSecret(t, "PARENT", "parent-secret-value")

	// The CLI's own credentials never reach the child. The agent key is the
	// same as the key file, so the store still resolves.
	t.Setenv(pv.EnvToken, "pv_pat_"+strings.Repeat("a", 52))
	t.Setenv(pv.EnvPassword, "share-password")
	t.Setenv(pv.EnvAgentKey, identity.PrivateKey)
	t.Setenv("FROM_PARENT", "pv://secret/PARENT")

	envFile := writeFile(t, ".env.pv", "X=pv://secret/API_KEY\nS=pv://secret/SHORT\nLITERAL=plain value\n", 0o600)
	result := runCLI(t, "", false, "run", "--env-file", envFile, "--", "sh", "-c",
		`echo "$X"; printf %s "$X" | base64; echo "$X" | base64; echo "$FROM_PARENT"; echo "$S $LITERAL"; echo "t=${PASTEVAULT_TOKEN:-unset} p=${PASTEVAULT_PASSWORD:-unset} k=${PASTEVAULT_AGENT_KEY:-unset}"; echo "$X" >&2`)
	if result.exit != 0 {
		t.Fatalf("exit %d: %s", result.exit, result.stderr)
	}
	for _, leak := range []string{secret, "parent-secret-value", base64.StdEncoding.EncodeToString([]byte(secret)), base64.StdEncoding.EncodeToString([]byte(secret + "\n"))} {
		if strings.Contains(result.stdout+result.stderr, leak) {
			t.Fatalf("output leaks %q:\n%s\n%s", leak, result.stdout, result.stderr)
		}
	}
	lines := strings.Split(result.stdout, "\n")
	if lines[0] != "[masked:X]" || !strings.HasPrefix(lines[1], "[masked:X]") || !strings.HasPrefix(lines[2], "[masked:X]") {
		t.Fatalf("stdout:\n%s", result.stdout)
	}
	if lines[3] != "[masked:FROM_PARENT]" {
		t.Fatalf("inherited handle: %q", lines[3])
	}
	// A value under 6 bytes is not masked, with a warning naming it.
	if lines[4] != "abc plain value" || !strings.Contains(result.stderr, "S is shorter than 6 bytes") {
		t.Fatalf("short value: %q / %s", lines[4], result.stderr)
	}
	if lines[5] != "t=unset p=unset k=unset" {
		t.Fatalf("credentials reached the child: %q", lines[5])
	}
	if !strings.Contains(result.stderr, "[masked:X]") {
		t.Fatalf("stderr is masked too: %s", result.stderr)
	}

	// --no-inherit keeps PATH but drops the rest.
	t.Setenv("MARKER", "inherited")
	isolated := runCLI(t, "", false, "run", "--no-inherit", "--env-file", envFile, "--no-mask", "--", "sh", "-c", `echo "${MARKER:-none} $X"`)
	if isolated.exit != 0 || isolated.stdout != "none "+secret+"\n" {
		t.Fatalf("--no-inherit: exit %d %q %s", isolated.exit, isolated.stdout, isolated.stderr)
	}
}

func TestRunExitCodes(t *testing.T) {
	requireShell(t)
	withAgent(t)

	for name, test := range map[string]struct {
		args []string
		exit int
	}{
		"child status":     {[]string{"run", "--", "sh", "-c", "exit 7"}, 7},
		"success":          {[]string{"run", "sh", "-c", "true"}, 0},
		"killed by signal": {[]string{"run", "--", "sh", "-c", "kill -KILL $$"}, 128 + int(syscall.SIGKILL)},
		"not found":        {[]string{"run", "--", "pastevault-test-no-such-command"}, 127},
		"not executable":   {[]string{"run", "--", writeFile(t, "plain.sh", "echo hi\n", 0o600)}, 126},
		"no command":       {[]string{"run"}, 2},
		"unresolved":       {[]string{"run", "--env-file", writeFile(t, "missing.env.pv", "A=pv://secret/NOPE\n", 0o600), "--", "true"}, 125},
		"bad handle":       {[]string{"run", "--env-file", writeFile(t, "bad.env.pv", "A=pv://nope/x\n", 0o600), "--", "true"}, 125},
		"bad env file":     {[]string{"run", "--env-file", writeFile(t, "broken.env.pv", "A='open\n", 0o600), "--", "true"}, 125},
	} {
		t.Run(name, func(t *testing.T) {
			result := runCLI(t, "", false, test.args...)
			if result.exit != test.exit {
				t.Fatalf("exit %d, want %d: %s", result.exit, test.exit, result.stderr)
			}
		})
	}

	// JSON mode: the error object carries the run exit code.
	result := runCLI(t, "", false, "run", "--json", "--env-file", writeFile(t, "missing.env.pv", "A=pv://secret/NOPE\n", 0o600), "--", "true")
	if result.exit != 125 || !strings.Contains(result.stdout, `"exit_code":125`) || !strings.Contains(result.stderr, "NOPE") {
		t.Fatalf("json: exit %d %s %s", result.exit, result.stdout, result.stderr)
	}

	// stdin is passed through.
	piped := runCLI(t, "from stdin\n", false, "run", "--", "sh", "-c", "cat")
	if piped.exit != 0 || piped.stdout != "from stdin\n" {
		t.Fatalf("stdin: %d %q", piped.exit, piped.stdout)
	}
}

func TestInject(t *testing.T) {
	withAgent(t)
	importSecret(t, "API_KEY", "sk-inject-value")
	importSecret(t, "ENV", "A=1\nB=two words\n")

	template := writeFile(t, "app.tmpl", "key: {{ pv://secret/API_KEY }}\nb: {{pv://secret/ENV?var=B}}\nagain: {{ pv://secret/API_KEY }}\nother: {{ value }}\n", 0o600)
	output := filepath.Join(t.TempDir(), "app.yml")

	result := runCLI(t, "", false, "inject", "-i", template, "-o", output, "--json")
	if result.exit != 0 || !strings.Contains(result.stdout, `"placeholders":2`) {
		t.Fatalf("inject: exit %d %s %s", result.exit, result.stdout, result.stderr)
	}
	data, _ := os.ReadFile(output)
	if string(data) != "key: sk-inject-value\nb: two words\nagain: sk-inject-value\nother: {{ value }}\n" {
		t.Fatalf("output:\n%s", data)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(output); info.Mode().Perm() != 0o600 {
			t.Fatalf("output mode %o", info.Mode().Perm())
		}
	}

	if again := runCLI(t, "", false, "inject", "-i", template, "-o", output); again.exit != pv.ExitLocalFile {
		t.Fatalf("existing output: exit %d", again.exit)
	}
	if stdoutResult := runCLI(t, "x={{ pv://secret/API_KEY }}", false, "inject", "-i", "-", "--stdout"); stdoutResult.exit != 0 || stdoutResult.stdout != "x=sk-inject-value" {
		t.Fatalf("stdin to stdout: %d %q", stdoutResult.exit, stdoutResult.stdout)
	}
	if missing := runCLI(t, "{{ pv://secret/NOPE }}", false, "inject", "-i", "-", "--stdout"); missing.exit != 125 || missing.stdout != "" {
		t.Fatalf("unresolved: exit %d %q", missing.exit, missing.stdout)
	}
	if neither := runCLI(t, "", false, "inject", "-i", template); neither.exit != pv.ExitUsage {
		t.Fatalf("no destination: exit %d", neither.exit)
	}
}

func TestSecretCommands(t *testing.T) {
	withAgent(t)
	importSecret(t, "TOKEN", "tok-1234567890\n")

	list := runCLI(t, "", false, "secret", "list", "--json")
	if list.exit != 0 || !strings.Contains(list.stdout, `"handle":"pv://secret/TOKEN"`) || strings.Contains(list.stdout, "tok-1234567890") {
		t.Fatalf("list: %d %s", list.exit, list.stdout)
	}
	if again := runCLI(t, "x", false, "secret", "import", "TOKEN", "--from-stdin"); again.exit != pv.ExitLocalFile {
		t.Fatalf("import over existing: exit %d", again.exit)
	}
	if bad := runCLI(t, "x", false, "secret", "import", "1BAD", "--from-stdin"); bad.exit != pv.ExitUsage {
		t.Fatalf("bad name: exit %d", bad.exit)
	}

	// reveal needs a terminal on both ends.
	if reveal := runCLI(t, "", true, "secret", "reveal", "TOKEN"); reveal.exit != pv.ExitUsage || strings.Contains(reveal.stdout, "tok-") {
		t.Fatalf("reveal without a terminal stdout: exit %d %q", reveal.exit, reveal.stdout)
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		stdinIsTerminal: func() bool { return true }, stdoutIsTerminal: func() bool { return true },
		promptPassword: func(string) (string, error) { return "", nil },
	}
	if exit := a.run(context.Background(), []string{"secret", "reveal", "TOKEN"}); exit != 0 || stdout.String() != "tok-1234567890\n" {
		t.Fatalf("reveal on a terminal: exit %d %q %s", exit, stdout.String(), stderr.String())
	}

	if rm := runCLI(t, "", false, "secret", "rm", "TOKEN"); rm.exit != 0 {
		t.Fatalf("rm: exit %d", rm.exit)
	}
	if rm := runCLI(t, "", false, "secret", "rm", "TOKEN"); rm.exit != pv.ExitNotFound {
		t.Fatalf("rm missing: exit %d", rm.exit)
	}

	// Without an agent key there is no store (exit 2 with a hint).
	isolate(t, offlineServer)
	if none := runCLI(t, "", false, "secret", "list"); none.exit != pv.ExitUsage || !strings.Contains(none.stderr, "agent init") {
		t.Fatalf("no agent: exit %d %s", none.exit, none.stderr)
	}
}

func TestRunInheritedHandles(t *testing.T) {
	requireShell(t)
	withAgent(t)
	importSecret(t, "LOCAL", "inherited-local-secret")

	// pv://secret resolves; pv://share passes through (no network) unless
	// --resolve-inherited; a malformed pv:// value passes through.
	t.Setenv("A", "pv://secret/LOCAL")
	t.Setenv("B", "pv://share/abcdefABCDEF#k="+strings.Repeat("A", 43))
	t.Setenv("C", "pv://not-a-handle")
	result := runCLI(t, "", false, "run", "--", "sh", "-c", `echo "$A|$B|$C"`)
	if result.exit != 0 {
		t.Fatalf("exit %d: %s", result.exit, result.stderr)
	}
	if result.stdout != "[masked:A]|pv://share/abcdefABCDEF#k="+strings.Repeat("A", 43)+"|pv://not-a-handle\n" {
		t.Fatalf("stdout %q", result.stdout)
	}
	if !strings.Contains(result.stderr, "B in the environment is a pv://share handle") || !strings.Contains(result.stderr, "C in the environment looks like a pv:// handle") {
		t.Fatalf("stderr %s", result.stderr)
	}

	// With --resolve-inherited the share handle is resolved (and fails here:
	// there is no server), so nothing runs.
	resolved := runCLI(t, "", false, "run", "--resolve-inherited", "--", "true")
	if resolved.exit == 0 {
		t.Fatalf("--resolve-inherited must resolve B: %s", resolved.stderr)
	}

	// A missing inherited secret is still an error.
	t.Setenv("A", "pv://secret/MISSING")
	if missing := runCLI(t, "", false, "run", "--", "true"); missing.exit != 125 {
		t.Fatalf("missing inherited secret: exit %d", missing.exit)
	}
}

func TestTerminalSafe(t *testing.T) {
	if got := terminalSafe("ok\x1b[2J\u202enot\u2028x\u0085y\tz"); got != "ok[2Jnotxyz" {
		t.Fatalf("terminalSafe = %q", got)
	}
}
