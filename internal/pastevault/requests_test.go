package pastevault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestParseDotenv(t *testing.T) {
	input := strings.Join([]string{
		"\uFEFF# comment",
		"",
		"PLAIN=value",
		"SPACED = spaced value   ",
		"export EXPORTED=pv://secret/NAME",
		"INLINE=abc # comment",
		"HASH=abc#not-a-comment",
		`DOUBLE="a \"quoted\"\nline\t$x \$y"`,
		`SINGLE='literal \n $HOME'`,
		`MULTI="first`,
		`second" # trailing comment`,
		"EMPTY=",
		"EMPTY_QUOTED=''",
		"exportNOT=1",
		"DUP=1",
		"DUP=2",
		"WINDOWS=crlf\r",
	}, "\n")

	entries, err := ParseDotenv([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, entry := range entries {
		got[entry.Key] = entry.Value
	}
	want := map[string]string{
		"PLAIN":        "value",
		"SPACED":       "spaced value",
		"EXPORTED":     "pv://secret/NAME",
		"INLINE":       "abc",
		"HASH":         "abc#not-a-comment",
		"DOUBLE":       "a \"quoted\"\nline\t$x $y",
		"SINGLE":       `literal \n $HOME`,
		"MULTI":        "first\nsecond",
		"EMPTY":        "",
		"EMPTY_QUOTED": "",
		"exportNOT":    "1",
		"DUP":          "2",
		"WINDOWS":      "crlf",
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d keys, want %d: %v", len(got), len(want), got)
	}

	if value, found, err := LookupDotenv([]byte(input), "DUP"); err != nil || !found || value != "2" {
		t.Fatalf("LookupDotenv(DUP) = %q %v %v", value, found, err)
	}
	if _, found, _ := LookupDotenv([]byte(input), "MISSING"); found {
		t.Fatal("LookupDotenv found a missing key")
	}

	for name, bad := range map[string]string{
		"no equals":          "JUST_A_WORD",
		"bad key":            "1KEY=x",
		"unterminated":       `KEY="never closed`,
		"text after quote":   `KEY="a" b`,
		"space in key":       "MY KEY=x",
		"unterminated multi": "KEY='a\nb",
	} {
		_, err := ParseDotenv([]byte(bad))
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if strings.Contains(err.Error(), "never closed") || strings.Contains(err.Error(), `"a" b`) {
			t.Errorf("%s: the error echoes the value: %v", name, err)
		}
		if Classify(err).Exit != ExitUsage {
			t.Errorf("%s: exit %d, want 2", name, Classify(err).Exit)
		}
	}
}

func TestParseHandle(t *testing.T) {
	const server = "https://api.example.com"
	const public = "https://example.com"
	key := EncodeBase64URL(bytes.Repeat([]byte{7}, 32))

	secret, err := ParseHandle("pv://secret/OPENAI_API_KEY", server, public, false)
	if err != nil || secret.Kind != HandleSecret || secret.Name != "OPENAI_API_KEY" || secret.Agent != "" || secret.Var != "" {
		t.Fatalf("secret handle: %+v %v", secret, err)
	}
	if secret.String() != "pv://secret/OPENAI_API_KEY" || SecretHandle("X") != "pv://secret/X" {
		t.Fatalf("String() = %q", secret.String())
	}

	withParams, err := ParseHandle("pv://secret/ENV_FILE?agent=ci-bot&var=TOKEN", server, public, false)
	if err != nil || withParams.Agent != "ci-bot" || withParams.Var != "TOKEN" {
		t.Fatalf("secret handle with params: %+v %v", withParams, err)
	}

	share, err := ParseHandle("pv://share/abcDEF123456?var=API_KEY#k="+key, server, public, false)
	if err != nil || share.Kind != HandleShare || share.Share.Slug != "abcDEF123456" || share.Var != "API_KEY" || len(share.Share.Key) != 32 || share.Share.Server != server {
		t.Fatalf("share handle: %+v %v", share, err)
	}
	if strings.Contains(share.String(), key) {
		t.Fatal("Handle.String must not contain the key")
	}

	otherServer, err := ParseHandle("pv://share/abcDEF123456?server=https://other.example#k="+key, server, public, false)
	if err != nil || otherServer.Share.Server != "https://other.example" {
		t.Fatalf("share handle with server: %+v %v", otherServer, err)
	}

	// Legacy URLs only where allowed (inject); a URL on the public origin
	// maps back to the API server.
	if _, err := ParseHandle(public+"/p/abcDEF123456#k="+key, server, public, false); err == nil {
		t.Fatal("URLs must not be handles in .env.pv")
	}
	legacy, err := ParseHandle(public+"/p/abcDEF123456#k="+key, server, public, true)
	if err != nil || legacy.Kind != HandleShare || legacy.Share.Kind != ShareKindPaste || legacy.Share.Server != server {
		t.Fatalf("legacy URL: %+v %v", legacy, err)
	}

	for _, bad := range []string{
		"pv://secret/",
		"pv://secret/1BAD",
		"pv://secret/A B",
		"pv://secret/NAME#k=" + key,
		"pv://secret/NAME?unknown=1",
		"pv://secret/NAME?agent=Bad_Agent",
		"pv://secret/NAME?var=1x",
		"pv://share/bad*slug",
		"pv://share/abcDEF123456?agent=x",
		"pv://other/thing",
		"plain text",
	} {
		_, err := ParseHandle(bad, server, public, true)
		if err == nil {
			t.Errorf("%q: expected an error", bad)
		} else if strings.Contains(err.Error(), key) {
			t.Errorf("%q: the error echoes the key", bad)
		}
	}

	if !LooksLikeHandle(" PV://secret/X") || LooksLikeHandle("https://x/p/abc") || LooksLikeHandle("value") {
		t.Fatal("LooksLikeHandle")
	}
}

func TestRequestCodes(t *testing.T) {
	for input, want := range map[string]string{
		"ABCD-EFGH":  "ABCD-EFGH",
		"abcdefgh":   "ABCD-EFGH",
		" abcd efgh": "ABCD-EFGH",
		"2345-6789":  "2345-6789",
	} {
		if got, ok := NormalizeRequestCode(input); !ok || got != want {
			t.Errorf("NormalizeRequestCode(%q) = %q %v", input, got, ok)
		}
	}
	for _, bad := range []string{"ABCD-EFG0", "ABCD-EFGI", "ABCDEFG", "ABCDEFGHJ", "", "ABCD_EFGH"} {
		if _, ok := NormalizeRequestCode(bad); ok {
			t.Errorf("NormalizeRequestCode(%q) accepted", bad)
		}
	}

	fp := Fingerprint(bytes.Repeat([]byte{9}, 32))
	code, fingerprint, err := ParseRequestReference("https://pastevault.dev/r/abcd-efgh#fp=" + fp)
	if err != nil || code != "ABCD-EFGH" || fingerprint != fp {
		t.Fatalf("ParseRequestReference(URL) = %q %q %v", code, fingerprint, err)
	}
	if code, fingerprint, err := ParseRequestReference("ABCDEFGH"); err != nil || code != "ABCD-EFGH" || fingerprint != "" {
		t.Fatalf("ParseRequestReference(code) = %q %q %v", code, fingerprint, err)
	}
	for _, bad := range []string{"https://x/p/ABCD-EFGH", "https://x/r/ABCD-EFGH#fp=pvk1_short", "nonsense"} {
		if _, _, err := ParseRequestReference(bad); err == nil {
			t.Errorf("ParseRequestReference(%q) accepted", bad)
		}
	}
	if got := RequestURL("https://pastevault.dev/", "ABCD-EFGH", fp); got != "https://pastevault.dev/r/ABCD-EFGH#fp="+fp {
		t.Fatalf("RequestURL = %q", got)
	}

	for name, valid := range map[string]bool{"OPENAI_API_KEY": true, "_x": true, "a.b-c": true, "1abc": false, "": false, "a b": false, strings.Repeat("a", 129): false} {
		if ValidSecretName(name) != valid {
			t.Errorf("ValidSecretName(%q) != %v", name, valid)
		}
	}
}

// The request response format (spec §3.3), rebuilt from primitives: the
// payload JSON encrypted under AAD "pastevault:request:<id>:v1" with a key
// wrapped to the request key for context "request:<id>".
func TestRequestPayloadCrypto(t *testing.T) {
	recipient := newKeyPair(t)
	other := newKeyPair(t)
	const id = "3f2a1c4e-0000-4000-8000-000000000001"

	payload, err := NewTextPayload("OPENAI_API_KEY", []byte("sk-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealSecretPayload(payload, recipient.PublicKey, RequestWrapContext(id), RequestPayloadAAD(id))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed.Ciphertext+sealed.WrappedKey, "sk-secret") {
		t.Fatal("the sealed payload contains the plaintext")
	}

	// By hand: unwrap with context request:<id>, open with the request AAD.
	key, err := UnwrapKey(sealed.WrappedKey, recipient.PrivateKey, "request:"+id)
	if err != nil {
		t.Fatalf("unwrap with request:<id>: %v", err)
	}
	aead, _ := chacha20poly1305.NewX(key)
	ciphertext, _ := DecodeBase64URL(sealed.Ciphertext)
	nonce, _ := DecodeBase64URL(sealed.Nonce)
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte("pastevault:request:"+id+":v1"))
	if err != nil {
		t.Fatalf("open with the request AAD: %v", err)
	}
	if string(plaintext) != `{"v":1,"name":"OPENAI_API_KEY","kind":"text","value":"sk-secret-value"}` {
		t.Fatalf("payload JSON = %s", plaintext)
	}
	if sealed.SealedSize() != len(ciphertext) {
		t.Fatalf("SealedSize = %d, want %d", sealed.SealedSize(), len(ciphertext))
	}

	opened, err := OpenSecretPayload(sealed, recipient.PrivateKey, RequestWrapContext(id), RequestPayloadAAD(id))
	if err != nil || opened != payload {
		t.Fatalf("OpenSecretPayload = %+v %v", opened, err)
	}

	tamperedCiphertext := []byte(sealed.Ciphertext)
	tamperedCiphertext[5] ^= 1
	for name, attempt := range map[string]func() (SecretPayload, error){
		"other key": func() (SecretPayload, error) {
			return OpenSecretPayload(sealed, other.PrivateKey, RequestWrapContext(id), RequestPayloadAAD(id))
		},
		"other request id (wrap)": func() (SecretPayload, error) {
			return OpenSecretPayload(sealed, recipient.PrivateKey, RequestWrapContext(id+"x"), RequestPayloadAAD(id))
		},
		"other request id (AAD)": func() (SecretPayload, error) {
			return OpenSecretPayload(sealed, recipient.PrivateKey, RequestWrapContext(id), RequestPayloadAAD(id+"x"))
		},
		"store context": func() (SecretPayload, error) {
			return OpenSecretPayload(sealed, recipient.PrivateKey, StoreWrapContext("OPENAI_API_KEY"), StorePayloadAAD("OPENAI_API_KEY"))
		},
		"tampered": func() (SecretPayload, error) {
			copy := sealed
			copy.Ciphertext = string(tamperedCiphertext)
			return OpenSecretPayload(copy, recipient.PrivateKey, RequestWrapContext(id), RequestPayloadAAD(id))
		},
	} {
		if _, err := attempt(); Classify(err).Exit != ExitDecrypt {
			t.Errorf("%s: got %v, want a decryption error (exit 7)", name, err)
		}
	}

	file := NewFilePayload("CERT", "cert.pem", "application/x-pem-file", []byte{0, 1, 2, 0xff})
	sealedFile, err := SealSecretPayload(file, recipient.PublicKey, StoreWrapContext("CERT"), StorePayloadAAD("CERT"))
	if err != nil {
		t.Fatal(err)
	}
	openedFile, err := OpenSecretPayload(sealedFile, recipient.PrivateKey, StoreWrapContext("CERT"), StorePayloadAAD("CERT"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := openedFile.Bytes()
	if err != nil || !bytes.Equal(data, []byte{0, 1, 2, 0xff}) || openedFile.Filename != "cert.pem" {
		t.Fatalf("file payload: %+v %v", openedFile, err)
	}

	if _, err := NewTextPayload("X", []byte{0xff, 0xfe}); err == nil {
		t.Fatal("invalid UTF-8 must not be a text payload")
	}
}

// A browser-made response decrypts in Go: built here exactly as the web page
// must build it (random K, XChaCha20-Poly1305 over the payload JSON with the
// request AAD, K wrapped with PVWRAP1).
func TestRequestPayloadFromPrimitives(t *testing.T) {
	recipient := newKeyPair(t)
	const id = "req-1"
	key := bytes.Repeat([]byte{3}, 32)
	nonce := bytes.Repeat([]byte{4}, 24)
	plaintext := []byte(`{"v":1,"name":"TOKEN","kind":"text","value":"abcé"}`)
	aead, _ := chacha20poly1305.NewX(key)
	wrapped, err := WrapKey(key, recipient.PublicKey, "request:"+id)
	if err != nil {
		t.Fatal(err)
	}
	sealed := SealedSecret{
		Ciphertext: EncodeBase64URL(aead.Seal(nil, nonce, plaintext, []byte("pastevault:request:req-1:v1"))),
		Nonce:      EncodeBase64URL(nonce),
		WrappedKey: wrapped,
	}
	payload, err := OpenSecretPayload(sealed, recipient.PrivateKey, RequestWrapContext(id), RequestPayloadAAD(id))
	if err != nil || payload.Value != "abcé" || payload.Name != "TOKEN" {
		t.Fatalf("payload = %+v %v", payload, err)
	}

	// Unknown versions and kinds are refused.
	for _, body := range []string{`{"v":2,"name":"T","kind":"text","value":"x"}`, `{"v":1,"name":"T","kind":"blob"}`, `{"v":1,"name":"T","kind":"file","data":"***"}`, `not json`} {
		sealed.Ciphertext = EncodeBase64URL(aead.Seal(nil, nonce, []byte(body), []byte("pastevault:request:req-1:v1")))
		if _, err := OpenSecretPayload(sealed, recipient.PrivateKey, RequestWrapContext(id), RequestPayloadAAD(id)); Classify(err).Exit != ExitDecrypt {
			t.Errorf("%s: got %v, want exit 7", body, err)
		}
	}
}

func TestPendingRequestFiles(t *testing.T) {
	dir := isolateConfig(t)
	keys := newKeyPair(t)

	request := &PendingRequest{
		ID:          "0b6d6f3e-1111-4222-8333-944455556666",
		Code:        "ABCD-EFGH",
		Server:      "https://api.example.com",
		Name:        "TOKEN",
		SaveAs:      "TOKEN",
		PollToken:   "poll-token",
		PrivateKey:  EncodeBase64URL(keys.PrivateKey),
		PublicKey:   EncodeBase64URL(keys.PublicKey),
		Fingerprint: keys.Fingerprint,
		CreatedAt:   "2026-10-16T00:00:00Z",
		ExpiresAt:   "2026-10-16T00:10:00Z",
	}
	if err := SavePendingRequest(request); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "requests", request.ID+".json")
	if request.Path != path {
		t.Fatalf("Path = %q, want %q", request.Path, path)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("request file mode %o", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
			t.Fatalf("requests dir mode %o", info.Mode().Perm())
		}
	}

	for _, reference := range []string{request.ID, "abcd-efgh", "ABCDEFGH"} {
		found, err := FindPendingRequest(reference)
		if err != nil || found == nil || found.ID != request.ID {
			t.Fatalf("FindPendingRequest(%q) = %+v %v", reference, found, err)
		}
		if _, err := found.Keys(); err != nil {
			t.Fatal(err)
		}
	}
	if found, err := FindPendingRequest("WXYZ-2345"); err != nil || found != nil {
		t.Fatalf("unknown code: %+v %v", found, err)
	}
	if _, err := FindPendingRequest("../../etc/passwd"); err == nil {
		t.Fatal("a path must not be accepted as a request id")
	}

	// A damaged key is detected, and damaged files are skipped in listings.
	var raw map[string]any
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &raw)
	raw["fingerprint"] = Fingerprint(bytes.Repeat([]byte{1}, 32))
	data, _ = json.Marshal(raw)
	_ = os.WriteFile(path, data, 0o600)
	damaged, _ := FindPendingRequest(request.ID)
	if _, err := damaged.Keys(); err == nil {
		t.Fatal("a key mismatch must be detected")
	}
	_ = os.WriteFile(filepath.Join(dir, "requests", "broken.json"), []byte("{"), 0o600)
	listed, warnings, err := ListPendingRequests()
	if err != nil || len(listed) != 1 || len(warnings) != 1 {
		t.Fatalf("ListPendingRequests = %d entries, %d warnings, %v", len(listed), len(warnings), err)
	}

	if err := DeletePendingRequest(request); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the request file must be gone")
	}
	if err := DeletePendingRequest(request); err != nil {
		t.Fatal("deleting twice is fine")
	}
}

func TestTrimTrailingNewline(t *testing.T) {
	for input, want := range map[string]string{
		"v\n":   "v",
		"v\r\n": "v",
		"v\r":   "v\r",
		"v\n\n": "v\n",
		"v":     "v",
		"\r\n":  "",
		"v\n\r": "v\n\r",
	} {
		if got := string(TrimTrailingNewline([]byte(input))); got != want {
			t.Errorf("TrimTrailingNewline(%q) = %q, want %q", input, got, want)
		}
	}
}
