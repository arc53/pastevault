package pastevault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func exitOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return ExitOK
	}

	return Classify(err).Exit
}

func TestParseExpiry(t *testing.T) {
	t.Parallel()

	valid := map[string]int{"15m": 15, "1m": 1, "2h": 120, "7d": 10080, "365d": 525600, "8760h": 525600, "525600m": 525600}
	for input, want := range valid {
		got, err := ParseExpiry(input)
		if err != nil || got != want {
			t.Errorf("ParseExpiry(%q) = %d, %v; want %d", input, got, err, want)
		}
	}

	for _, input := range []string{"", "0m", "15", "1w", "1.5h", "-1h", "366d", "8761h", "525601m", "h", "15 m", "99999999999999999999d"} {
		if _, err := ParseExpiry(input); exitOf(t, err) != ExitUsage {
			t.Errorf("ParseExpiry(%q) = %v; want a usage error", input, err)
		}
	}
}

func TestResolveExpiryFallsBackToHoursOnOldServers(t *testing.T) {
	t.Parallel()

	modern := CapabilitiesResponse{Features: FeatureFlags{ExpiresInMinutes: true}}
	if got, err := ResolveExpiry(15, modern); err != nil || got != (ExpiryFields{Minutes: 15}) {
		t.Fatalf("modern server: %+v, %v", got, err)
	}

	old := CapabilitiesResponse{}
	if got, err := ResolveExpiry(120, old); err != nil || got != (ExpiryFields{Hours: 2}) {
		t.Fatalf("old server whole hours: %+v, %v", got, err)
	}
	if _, err := ResolveExpiry(90, old); exitOf(t, err) != ExitUnsupported {
		t.Fatalf("old server 90m: want exit 14, got %v", err)
	}
}

func TestParseWaitDurationAndSince(t *testing.T) {
	t.Parallel()

	cases := map[string]time.Duration{"30s": 30 * time.Second, "10m": 10 * time.Minute, "2h": 2 * time.Hour, "1d": 24 * time.Hour, "1m30s": 90 * time.Second, "500ms": 500 * time.Millisecond}
	for input, want := range cases {
		if got, err := ParseWaitDuration("--timeout", input); err != nil || got != want {
			t.Errorf("ParseWaitDuration(%q) = %v, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "0s", "-5m", "soon"} {
		if _, err := ParseWaitDuration("--timeout", input); exitOf(t, err) != ExitUsage {
			t.Errorf("ParseWaitDuration(%q) should fail", input)
		}
	}

	for _, input := range []string{"24h", "15m", "7d", "2026-10-01T00:00:00Z"} {
		if err := ValidateSince(input); err != nil {
			t.Errorf("ValidateSince(%q): %v", input, err)
		}
	}
	if err := ValidateSince("yesterday"); exitOf(t, err) != ExitUsage {
		t.Error("ValidateSince(yesterday) should fail")
	}

	if days, err := ParseTokenExpiry("90d"); err != nil || days == nil || *days != 90 {
		t.Errorf("ParseTokenExpiry(90d) = %v, %v", days, err)
	}
	if days, err := ParseTokenExpiry("never"); err != nil || days != nil {
		t.Errorf("ParseTokenExpiry(never) = %v, %v", days, err)
	}
	for _, input := range []string{"0d", "366d", "90", "2w"} {
		if _, err := ParseTokenExpiry(input); exitOf(t, err) != ExitUsage {
			t.Errorf("ParseTokenExpiry(%q) should fail", input)
		}
	}
}

const testKey = "bFL-OMRbUfar5MkwE0WrkhunoT2k_jwB5HKL_OxGpGY"

func TestParseShareReferenceForms(t *testing.T) {
	t.Parallel()

	const api = "https://api.pastevault.dev"
	const public = "https://pastevault.dev"

	cases := []struct {
		input  string
		server string
		slug   string
		kind   ShareKind
		hasKey bool
		params map[string]string
	}{
		{"https://pastevault.dev/p/AbC123xyz_-0#k=" + testKey, api, "AbC123xyz_-0", ShareKindPaste, true, nil},
		{"https://pastevault.dev/f/w5SfkQSGJAZS", api, "w5SfkQSGJAZS", ShareKindFileShare, false, nil},
		{"https://self.example/vault/p/abcdef#k=" + testKey, "https://self.example/vault", "abcdef", ShareKindPaste, true, nil},
		{"http://127.0.0.1:3000/f/abcdef", "http://127.0.0.1:3000", "abcdef", ShareKindFileShare, false, nil},
		{"abcdef#k=" + testKey, api, "abcdef", ShareKindUnknown, true, nil},
		{"abcdef", api, "abcdef", ShareKindUnknown, false, nil},
		{"pv://share/abcdef", api, "abcdef", ShareKindUnknown, false, nil},
		{"pv://share/abcdef?server=self.example#k=" + testKey, "self.example", "abcdef", ShareKindUnknown, true, nil},
		{"pv://share/abcdef?var=API_KEY&agent=ci", api, "abcdef", ShareKindUnknown, false, map[string]string{"var": "API_KEY", "agent": "ci"}},
	}

	for _, testCase := range cases {
		ref, err := ParseShareReference(testCase.input, api, public)
		if err != nil {
			t.Errorf("%s: %v", testCase.input, err)
			continue
		}
		if ref.Server != testCase.server || ref.Slug != testCase.slug || ref.Kind != testCase.kind || (len(ref.Key) == 32) != testCase.hasKey {
			t.Errorf("%s: got %+v", testCase.input, ref)
		}
		for name, value := range testCase.params {
			if ref.Params[name] != value {
				t.Errorf("%s: param %s = %q", testCase.input, name, ref.Params[name])
			}
		}
	}
}

func TestParseShareReferenceRejectsBadInput(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"",
		"https://pastevault.dev/x/abcdef",
		"https://pastevault.dev/",
		"ftp://pastevault.dev/p/abcdef",
		"pv://secret/OPENAI_API_KEY",
		"pv://request/abc",
		"pv://share/abc?bogus=1",
		"a/b",
		"bad slug!",
		"abcdef#k=short",
		"abcdef#k=" + strings.Repeat("!", 43),
	} {
		_, err := ParseShareReference(input, "https://api.pastevault.dev", "https://pastevault.dev")
		if exitOf(t, err) != ExitUsage {
			t.Errorf("%q: want a usage error, got %v", input, err)
		}
		if err != nil && strings.Contains(err.Error(), "short") {
			t.Errorf("%q: error echoes key material: %v", input, err)
		}
	}
}

func TestReadShareKeySources(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte(testKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	urlFile := filepath.Join(dir, "url")
	if err := os.WriteFile(urlFile, []byte("https://pastevault.dev/p/abc#k="+testKey), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PV_TEST_KEY", "k="+testKey)

	for name, source := range map[string]KeySource{
		"file":     {File: keyFile},
		"url-file": {File: urlFile},
		"env":      {Env: "PV_TEST_KEY"},
		"stdin":    {Stdin: true},
		"flag":     {Flag: testKey},
	} {
		key, err := ReadShareKey(source, strings.NewReader(testKey+"\r\n"))
		if err != nil || EncodeBase64URL(key) != testKey {
			t.Errorf("%s: key %x, err %v", name, key, err)
		}
	}

	if key, err := ReadShareKey(KeySource{}, nil); key != nil || err != nil {
		t.Errorf("no source: %v %v", key, err)
	}
	if _, err := ReadShareKey(KeySource{File: keyFile, Stdin: true}, nil); exitOf(t, err) != ExitUsage {
		t.Errorf("two sources must be a usage error: %v", err)
	}
	if _, err := ReadShareKey(KeySource{Env: "PV_TEST_MISSING"}, nil); exitOf(t, err) != ExitUsage {
		t.Errorf("missing env: %v", err)
	}
	if _, err := ReadShareKey(KeySource{File: filepath.Join(dir, "nope")}, nil); exitOf(t, err) != ExitLocalFile {
		t.Errorf("missing file: %v", err)
	}
}

func TestResolvePasswordPrecedence(t *testing.T) {
	dir := t.TempDir()
	passwordFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(passwordFile, []byte(" spaced secret \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noPrompt := func(string) (string, error) { t.Fatal("unexpected prompt"); return "", nil }

	t.Setenv(EnvPassword, "from-env")
	if got, _ := ResolvePassword(PasswordSource{File: passwordFile, Prompt: true}, true, noPrompt); got != " spaced secret " {
		t.Errorf("file should win and keep inner whitespace, got %q", got)
	}
	if got, _ := ResolvePassword(PasswordSource{Prompt: true}, true, noPrompt); got != "from-env" {
		t.Errorf("env should beat the prompt, got %q", got)
	}

	t.Setenv(EnvPassword, "")
	prompted := func(string) (string, error) { return "typed", nil }
	if got, _ := ResolvePassword(PasswordSource{Prompt: true}, true, prompted); got != "typed" {
		t.Errorf("prompt: got %q", got)
	}
	if _, err := ResolvePassword(PasswordSource{Prompt: true}, false, prompted); exitOf(t, err) != ExitUsage {
		t.Errorf("prompt without a terminal must fail: %v", err)
	}
	if got, err := ResolvePassword(PasswordSource{}, true, noPrompt); got != "" || err != nil {
		t.Errorf("no source: %q %v", got, err)
	}
}

func TestReadTextInput(t *testing.T) {
	t.Parallel()

	if data, err := ReadTextInput(strings.NewReader("hello\n"), 100); err != nil || string(data) != "hello\n" {
		t.Fatalf("got %q, %v", data, err)
	}
	if _, err := ReadTextInput(strings.NewReader(strings.Repeat("x", 101)), 100); exitOf(t, err) != ExitUsage {
		t.Fatalf("over the limit: %v", err)
	}
	if _, err := ReadTextInput(strings.NewReader(" \n\t"), 100); exitOf(t, err) != ExitUsage {
		t.Fatalf("blank: %v", err)
	}
	if _, err := ReadTextInput(strings.NewReader("\xff\xfe"), 100); exitOf(t, err) != ExitUsage {
		t.Fatalf("invalid UTF-8: %v", err)
	}
}

func TestWritePrivateFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key.txt")
	if err := WritePrivateFile(path, []byte("one"), false); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, %v", info.Mode(), err)
		}
	}
	if err := WritePrivateFile(path, []byte("two"), false); exitOf(t, err) != ExitLocalFile {
		t.Fatalf("existing file: %v", err)
	}
	if err := CheckWritableTarget(path, false); exitOf(t, err) != ExitLocalFile {
		t.Fatalf("CheckWritableTarget existing: %v", err)
	}
	if err := CheckWritableTarget(filepath.Join(t.TempDir(), "missing", "x"), false); exitOf(t, err) != ExitLocalFile {
		t.Fatalf("CheckWritableTarget missing dir: %v", err)
	}
	if err := WritePrivateFile(path, []byte("two"), true); err != nil {
		t.Fatal(err)
	}
}

func TestEnvFileDetectionAndOutputNames(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]bool{".env": true, ".env.local": true, "prod.env": true, "dir/.env.production": true, "env": false, ".envrc": false, "notes.txt": false, ".env.": false} {
		if IsEnvFileName(name) != want {
			t.Errorf("IsEnvFileName(%q) = %v", name, !want)
		}
	}

	for title, want := range map[string]string{".env": ".env", "notes.txt": "notes.txt", "My notes": "slug.txt", "../x": "slug.txt", "..": "slug.txt", "": "slug.txt"} {
		if got := PasteOutputFileName(PasteContent{Title: title, RenderMode: "plain"}, "slug"); got != want {
			t.Errorf("PasteOutputFileName(%q) = %q, want %q", title, got, want)
		}
	}
	if got := PasteOutputFileName(PasteContent{RenderMode: "markdown"}, "slug"); got != "slug.md" {
		t.Errorf("markdown name = %q", got)
	}
}

func TestGeneratePasteSlug(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for range 200 {
		slug, err := GeneratePasteSlug()
		if err != nil {
			t.Fatal(err)
		}
		if len(slug) != 12 || !IsValidSlug(slug) || seen[slug] || slug[0] == '-' {
			t.Fatalf("bad slug %q", slug)
		}
		seen[slug] = true
	}
}

func TestPasteRoundTripWithPassword(t *testing.T) {
	t.Parallel()

	encryption, err := PrepareFileShareEncryption("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	content := PasteContent{Title: "t", Body: "<b>&</b>", RenderMode: "plain"}
	ciphertext, nonce, err := EncryptPaste(content, encryption.Key, "slug-abc")
	if err != nil {
		t.Fatal(err)
	}

	key, err := DerivePasteKey(nil, encryption.Salt, encryption.KDFParams, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptPaste(ciphertext, nonce, key, "slug-abc"); err != nil || got != content {
		t.Fatalf("round trip: %+v, %v", got, err)
	}

	wrong, _ := DerivePasteKey(nil, encryption.Salt, encryption.KDFParams, "hunter3")
	if _, err := DecryptPaste(ciphertext, nonce, wrong, "slug-abc"); exitOf(t, err) != ExitDecrypt {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := DerivePasteKey(nil, encryption.Salt, encryption.KDFParams, ""); Classify(err).Code != CodePasswordNeeded {
		t.Fatalf("missing password: %v", err)
	}
	if _, err := DerivePasteKey(nil, "", "", ""); Classify(err).Code != CodeKeyRequired {
		t.Fatalf("missing key: %v", err)
	}
}

// The status table runs through a real HTTP round trip, so the mapping from
// server answers to exit codes is what users see.
func TestStatusToExitCode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		status int
		body   string
		exit   int
		code   string
	}{
		{400, `{"error":"Invalid request: slug"}`, ExitUsage, CodeInvalidRequest},
		{401, `{"error":"invalid_token"}`, ExitAuth, CodeAuth},
		{403, `{"error":"insufficient_scope","required":"shares:create"}`, ExitAuth, CodeAuth},
		{403, `{"error":"recipient_auth_required"}`, ExitAuth, CodeAuth},
		{404, `{"error":"Paste not found"}`, ExitNotFound, CodeNotFound},
		{409, `{"error":"A paste with this slug already exists"}`, ExitConflict, CodeConflict},
		{410, `{"error":"Paste has been burned"}`, ExitGone, CodeGone},
		{413, `{"error":"Paste too large"}`, ExitUsage, CodeTooLarge},
		{429, `{"error":"slow_down"}`, ExitRateLimited, CodeRateLimited},
		{500, `{"error":"Internal server error"}`, ExitNetwork, CodeNetwork},
		{502, `bad gateway`, ExitNetwork, CodeNetwork},
		{503, ``, ExitNetwork, CodeNetwork},
		{418, `{}`, ExitInternal, CodeInternal},
	}

	for _, testCase := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(testCase.status)
			_, _ = io.WriteString(w, testCase.body)
		}))
		client, err := NewClient(server.URL, "test")
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.GetPasteMeta(context.Background(), "abcdef")
		server.Close()

		cliErr := Classify(err)
		if cliErr.Exit != testCase.exit || cliErr.Code != testCase.code {
			t.Errorf("HTTP %d: exit %d code %s, want %d %s (%v)", testCase.status, cliErr.Exit, cliErr.Code, testCase.exit, testCase.code, err)
		}
	}

	// Scope errors name the missing scope.
	if !strings.Contains(Classify(&APIRequestError{StatusCode: 403, ErrorCode: "insufficient_scope", Required: "audit:read"}).Error(), "audit:read") {
		t.Error("insufficient_scope message should name the scope")
	}
}

func TestClassifyTransportAndCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.NotFoundHandler())
	baseURL := server.URL
	server.Close()

	client, err := NewClient(baseURL, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetPasteMeta(context.Background(), "abcdef")
	if got := Classify(err); got.Exit != ExitNetwork {
		t.Fatalf("connection refused: exit %d (%v)", got.Exit, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.GetPasteMeta(ctx, "abcdef")
	if got := Classify(err); got.Exit != ExitInterrupted {
		t.Fatalf("cancelled: exit %d (%v)", got.Exit, err)
	}

	wrapped := fmt.Errorf("outer: %w", NewError(ExitGone, CodeGone, "gone"))
	if Classify(wrapped).Exit != ExitGone {
		t.Fatal("wrapped CLIError must keep its exit code")
	}
	if Classify(errors.New("boom")).Exit != ExitInternal {
		t.Fatal("plain errors are internal")
	}
}

func TestAttachCredentialsPrecedence(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	const server = "https://vault.example"
	token := APITokenPrefix + strings.Repeat("a", 52)
	stored := APITokenPrefix + strings.Repeat("b", 52)

	attach := func(target, configured string) (CredentialSource, string) {
		client, err := NewClient(target, "test")
		if err != nil {
			t.Fatal(err)
		}
		source, err := AttachCredentials(client, configured)
		if err != nil {
			t.Fatal(err)
		}
		return source, client.authToken
	}

	t.Setenv(EnvToken, "")
	if source, _ := attach(server, server); source != CredentialNone {
		t.Fatalf("nothing stored: %s", source)
	}

	if err := SaveStoredAuthToken(server, "session-token"); err != nil {
		t.Fatal(err)
	}
	if source, value := attach(server, server); source != CredentialSession || value != "session-token" {
		t.Fatalf("session: %s %s", source, value)
	}

	if err := SaveStoredAPIToken(server, stored); err != nil {
		t.Fatal(err)
	}
	if source, value := attach(server, server); source != CredentialStoredToken || value != stored {
		t.Fatalf("stored token beats session: %s", source)
	}

	t.Setenv(EnvToken, token)
	if source, value := attach(server, server); source != CredentialEnvToken || value != token {
		t.Fatalf("env token wins: %s", source)
	}

	// The env token is never sent to a server other than the configured one.
	if source, value := attach("https://other.example", server); source == CredentialEnvToken || value == token {
		t.Fatalf("env token leaked to another server: %s", source)
	}

	// Removing the session keeps the stored token, and vice versa.
	if _, err := DeleteStoredAuthToken(server); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadStoredAPIToken(server); got != stored {
		t.Fatal("deleting the session removed the stored token")
	}
	if _, err := DeleteStoredAPIToken(server); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(os.Getenv(EnvConfigDir), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "vault.example") {
		t.Fatalf("empty server entry left behind: %s", data)
	}
}

func TestLooksLikeAPIToken(t *testing.T) {
	t.Parallel()

	if !LooksLikeAPIToken(APITokenPrefix + strings.Repeat("a2", 26)) {
		t.Fatal("valid token rejected")
	}
	for _, value := range []string{"", "pv_pat_", APITokenPrefix + strings.Repeat("A", 52), APITokenPrefix + strings.Repeat("a", 51), "ghp_" + strings.Repeat("a", 52)} {
		if LooksLikeAPIToken(value) {
			t.Errorf("accepted %q", value)
		}
	}
}
