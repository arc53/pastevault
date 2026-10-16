package pastevault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "config")
	t.Setenv(EnvConfigDir, dir)
	t.Setenv(EnvAgent, "")
	t.Setenv(EnvAgentKey, "")
	return dir
}

func newKeyPair(t *testing.T) AgentKeyPair {
	t.Helper()
	keys, err := GenerateAgentKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestWrapRoundTripAndBindings(t *testing.T) {
	recipient := newKeyPair(t)
	other := newKeyPair(t)
	contentKey := bytes.Repeat([]byte{0x42}, ContentKeySize)
	context := PasteWrapContext("slug-123")

	envelope, err := WrapKey(contentKey, recipient.PublicKey, context)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope) != 140 {
		t.Fatalf("envelope is %d characters, want 140", len(envelope))
	}
	second, _ := WrapKey(contentKey, recipient.PublicKey, context)
	if second == envelope {
		t.Fatal("two wraps of the same key must differ (fresh ephemeral key and nonce)")
	}

	opened, err := UnwrapKey(envelope, recipient.PrivateKey, context)
	if err != nil || !bytes.Equal(opened, contentKey) {
		t.Fatalf("unwrap: %v", err)
	}

	for name, attempt := range map[string]func() ([]byte, error){
		"other recipient": func() ([]byte, error) { return UnwrapKey(envelope, other.PrivateKey, context) },
		"other slug":      func() ([]byte, error) { return UnwrapKey(envelope, recipient.PrivateKey, PasteWrapContext("slug-124")) },
		"file share context": func() ([]byte, error) {
			return UnwrapKey(envelope, recipient.PrivateKey, FileShareWrapContext("slug-123"))
		},
		"request context": func() ([]byte, error) {
			return UnwrapKey(envelope, recipient.PrivateKey, RequestWrapContext("slug-123"))
		},
		"garbage": func() ([]byte, error) { return UnwrapKey("not-an-envelope", recipient.PrivateKey, context) },
	} {
		if key, err := attempt(); !errors.Is(err, ErrUnwrapFailed) || key != nil {
			t.Errorf("%s: err = %v, want ErrUnwrapFailed", name, err)
		}
	}

	if _, err := WrapKey(contentKey[:16], recipient.PublicKey, context); err == nil {
		t.Error("a short content key was wrapped")
	}
	if _, err := WrapKey(contentKey, recipient.PublicKey, ""); err == nil {
		t.Error("an empty context was accepted")
	}
}

// Low-order X25519 points (libsodium's blocklist): every one gives an
// all-zero shared secret and must be refused for wrapping and as an
// ephemeral key when unwrapping.
var lowOrderPoints = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

func TestWrapRejectsZeroSharedSecret(t *testing.T) {
	recipient := newKeyPair(t)
	contentKey := bytes.Repeat([]byte{7}, ContentKeySize)
	valid, err := WrapKey(contentKey, recipient.PublicKey, "paste:x")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := DecodeBase64URL(valid)

	for _, point := range lowOrderPoints {
		publicKey, _ := hex.DecodeString(point)
		if _, err := WrapKey(contentKey, publicKey, "paste:x"); !isUnusableKey(err) {
			t.Errorf("wrap to %s: err = %v, want ErrLowOrderKey or ErrNonCanonicalKey", point[:8], err)
		}
		if _, err := DecodeAgentPublicKey(EncodeBase64URL(publicKey)); err == nil {
			t.Errorf("DecodeAgentPublicKey accepted %s", point[:8])
		}

		forged := bytes.Clone(raw)
		copy(forged[1:33], publicKey)
		if _, err := UnwrapKey(EncodeBase64URL(forged), recipient.PrivateKey, "paste:x"); !errors.Is(err, ErrUnwrapFailed) {
			t.Errorf("unwrap with ephemeral %s: err = %v", point[:8], err)
		}
	}
}

func TestFingerprintHelpers(t *testing.T) {
	keys := newKeyPair(t)
	fingerprint := keys.Fingerprint
	if !IsFingerprint(fingerprint) || len(fingerprint) != FingerprintLength {
		t.Fatalf("bad fingerprint %q", fingerprint)
	}
	if !IsFingerprintPrefix(fingerprint[:13]) || IsFingerprintPrefix(fingerprint[:12]) || IsFingerprintPrefix("pvk1_ABCDEFGH") {
		t.Fatal("IsFingerprintPrefix accepts or rejects the wrong lengths or characters")
	}
	if strings.ReplaceAll(FormatFingerprint(fingerprint), " ", "") != fingerprint {
		t.Fatal("FormatFingerprint changed more than spacing")
	}
	if IsFingerprint(strings.ToUpper(fingerprint)) || IsFingerprint(fingerprint[:36]) {
		t.Fatal("IsFingerprint accepted a malformed value")
	}
}

func TestVerifyAgentKeyPinsThenRefusesChangedKey(t *testing.T) {
	isolateConfig(t)
	server := "https://pv.example.com"
	first := newKeyPair(t)
	second := newKeyPair(t)

	newlyPinned, err := VerifyAgentKey(server, "bot", first.PublicKey)
	if err != nil || !newlyPinned {
		t.Fatalf("first use: pinned=%v err=%v", newlyPinned, err)
	}
	if newlyPinned, err = VerifyAgentKey(server, "bot", first.PublicKey); err != nil || newlyPinned {
		t.Fatalf("same key again: pinned=%v err=%v", newlyPinned, err)
	}

	_, err = VerifyAgentKey(server, "bot", second.PublicKey)
	var cliErr *CLIError
	if !errors.As(err, &cliErr) || cliErr.Exit != ExitFingerprint || cliErr.Code != CodeFingerprint {
		t.Fatalf("changed key: err = %v, want exit %d", err, ExitFingerprint)
	}
	if !strings.Contains(cliErr.Message, "pastevault agent trust bot "+second.Fingerprint) {
		t.Fatalf("the error should explain how to recover: %s", cliErr.Message)
	}
	if exit := Classify(err).Exit; exit != ExitFingerprint {
		t.Fatalf("Classify exit = %d", exit)
	}

	// Pins are per server.
	if _, err := VerifyAgentKey("https://other.example.com", "bot", second.PublicKey); err != nil {
		t.Fatalf("another server's agent of the same name: %v", err)
	}

	// After a manual trust the new key is accepted and the old one refused.
	if _, err := PinAgent(server, "bot", second.PublicKey, PinSourceManual); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAgentKey(server, "bot", second.PublicKey); err != nil {
		t.Fatalf("trusted key: %v", err)
	}
	if _, err := VerifyAgentKey(server, "bot", first.PublicKey); !errors.As(err, &cliErr) || cliErr.Exit != ExitFingerprint {
		t.Fatalf("old key after trust: %v", err)
	}
}

func TestVerifyAgentKeyPrefersOwnKeyFile(t *testing.T) {
	isolateConfig(t)
	server := "http://127.0.0.1:3001"
	own := newKeyPair(t)
	path, err := AgentKeyPath(server, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAgentIdentity(NewAgentIdentity(server, "laptop", own), path, false); err != nil {
		t.Fatal(err)
	}

	// No pin, but this machine holds laptop's key: a different server key is
	// a mismatch, not a first use.
	_, err = VerifyAgentKey(server, "laptop", newKeyPair(t).PublicKey)
	var cliErr *CLIError
	if !errors.As(err, &cliErr) || cliErr.Exit != ExitFingerprint {
		t.Fatalf("err = %v, want exit 8", err)
	}
	if _, err := VerifyAgentKey(server, "laptop", own.PublicKey); err != nil {
		t.Fatalf("own key: %v", err)
	}
}

func TestAgentIdentityFiles(t *testing.T) {
	configDir := isolateConfig(t)
	server := "http://127.0.0.1:3001"
	keys := newKeyPair(t)

	path, err := AgentKeyPath(server, "build-bot")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(configDir, "agents", "http_127.0.0.1_3001", "build-bot.json"); path != want {
		t.Fatalf("path = %s, want %s", path, want)
	}
	if _, err := AgentKeyPath(server, "../escape"); err == nil {
		t.Fatal("an invalid agent name was accepted as a file name")
	}

	identity := NewAgentIdentity(server, "build-bot", keys)
	identity.AgentID = "agent-1"
	if err := SaveAgentIdentity(identity, path, false); err != nil {
		t.Fatal(err)
	}
	if err := SaveAgentIdentity(identity, path, false); err == nil {
		t.Fatal("an existing key file was overwritten")
	}

	if runtime.GOOS != "windows" {
		for file, want := range map[string]os.FileMode{
			path:                               0o600,
			filepath.Dir(path):                 0o700,
			filepath.Join(configDir, "agents"): 0o700,
		} {
			info, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != want {
				t.Errorf("%s mode = %o, want %o", file, got, want)
			}
		}

		// Loosened permissions are tightened again when the key is loaded.
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	loaded, err := LoadAgentIdentity(server, "build-bot")
	if err != nil || loaded == nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.AgentID != "agent-1" || loaded.Fingerprint != keys.Fingerprint || !bytes.Equal(loaded.Keys().PrivateKey, keys.PrivateKey) {
		t.Fatalf("loaded identity differs: %+v", loaded)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("mode after load = %o, want 600", info.Mode().Perm())
		}
	}

	// A file whose public key doesn't belong to its private key is refused.
	var raw map[string]any
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &raw)
	raw["public_key"] = EncodeBase64URL(newKeyPair(t).PublicKey)
	tampered, _ := json.Marshal(raw)
	tamperedPath := filepath.Join(filepath.Dir(path), "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentIdentity(server, "tampered"); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("tampered file: err = %v", err)
	}
	identities, warnings, err := LocalAgentIdentities(server)
	if err != nil || len(identities) != 1 || len(warnings) != 1 {
		t.Fatalf("listing: %d identities, %d warnings, err %v", len(identities), len(warnings), err)
	}
	_ = os.Remove(tamperedPath)

	// Matching by fingerprint, including after a retire (revoke).
	found, err := FindIdentityByFingerprint("http://other.example", keys.Fingerprint)
	if err != nil || found == nil || found.Name != "build-bot" {
		t.Fatalf("find across servers: %v %v", found, err)
	}
	retired, err := RetireAgentIdentity(loaded)
	if err != nil || !strings.Contains(retired, filepath.Join("revoked", "build-bot-")) {
		t.Fatalf("retire: %s %v", retired, err)
	}
	if again, _ := LoadAgentIdentity(server, "build-bot"); again != nil {
		t.Fatal("a retired key still answers to its name")
	}
	if listed, _, _ := LocalAgentIdentities(server); len(listed) != 1 || !listed[0].Revoked() {
		t.Fatalf("the retired key is listed as revoked: %+v", listed)
	}

	// A file whose content names another agent is not that agent's key.
	impostor := NewAgentIdentity(server, "other", newKeyPair(t))
	impostorPath, _ := AgentKeyPath(server, "renamed")
	if err := SaveAgentIdentity(impostor, impostorPath, false); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadAgentIdentity(server, "renamed"); err == nil || got != nil {
		t.Fatalf("a key file for another name was accepted: %v", err)
	}
	_ = os.Remove(impostorPath)
	found, err = FindIdentityByFingerprint(server, keys.Fingerprint)
	if err != nil || found == nil || !found.Revoked() {
		t.Fatalf("retired key is still found by fingerprint: %v %v", found, err)
	}
	if missing, err := FindIdentityByFingerprint(server, newKeyPair(t).Fingerprint); err != nil || missing != nil {
		t.Fatalf("unknown fingerprint: %v %v", missing, err)
	}
}

func TestEnvAgentKeyAndDefaultAgent(t *testing.T) {
	isolateConfig(t)
	server := "https://pv.example.com"
	keys := newKeyPair(t)

	t.Setenv(EnvAgentKey, EncodeBase64URL(keys.PrivateKey))
	found, err := FindIdentityByFingerprint(server, keys.Fingerprint)
	if err != nil || found == nil || found.Source != IdentitySourceEnv || found.Path != "" {
		t.Fatalf("env identity: %+v %v", found, err)
	}
	t.Setenv(EnvAgentKey, "not-a-key")
	var cliErr *CLIError
	if _, err := EnvAgentIdentity(); !errors.As(err, &cliErr) || cliErr.Exit != ExitUsage {
		t.Fatalf("bad env key: %v", err)
	}
	if strings.Contains(cliErr.Message, "not-a-key") {
		t.Fatal("the error repeats the key")
	}
	t.Setenv(EnvAgentKey, "")

	if name, source, err := DefaultAgentName(server); err != nil || name != "" || source != DefaultAgentNone {
		t.Fatalf("no default: %q %q %v", name, source, err)
	}
	if err := SetDefaultAgent(server, "laptop"); err != nil {
		t.Fatal(err)
	}
	if name, source, _ := DefaultAgentName(server + "/"); name != "laptop" || source != DefaultAgentSettings {
		t.Fatalf("saved default: %q %q", name, source)
	}
	t.Setenv(EnvAgent, "ci-bot")
	if name, source, _ := DefaultAgentName(server); name != "ci-bot" || source != DefaultAgentEnv {
		t.Fatalf("env default: %q %q", name, source)
	}
	t.Setenv(EnvAgent, "")
	if err := SetDefaultAgent(server, ""); err != nil {
		t.Fatal(err)
	}
	if name, _, _ := DefaultAgentName(server); name != "" {
		t.Fatalf("cleared default: %q", name)
	}
}

func TestServerDirName(t *testing.T) {
	for server, want := range map[string]string{
		"https://api.pastevault.dev": "https_api.pastevault.dev",
		"http://127.0.0.1:3001":      "http_127.0.0.1_3001",
		"localhost:3001":             "http_localhost_3001",
		"https://Example.com/pv/":    "https_example.com_pv",
	} {
		got, err := ServerDirName(server)
		if err != nil || got != want {
			t.Errorf("ServerDirName(%q) = %q, %v; want %q", server, got, err, want)
		}
	}
}

func isUnusableKey(err error) bool {
	return errors.Is(err, ErrLowOrderKey) || errors.Is(err, ErrNonCanonicalKey)
}

func TestNonCanonicalPublicKeys(t *testing.T) {
	recipient := newKeyPair(t)
	contentKey := bytes.Repeat([]byte{9}, ContentKeySize)

	topBit := bytes.Clone(recipient.PublicKey)
	topBit[31] |= 0x80
	// p + 9 is a second encoding of the base point u = 9.
	basePointPlusP, _ := hex.DecodeString("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	for name, publicKey := range map[string][]byte{"top bit": topBit, "u >= p": basePointPlusP} {
		if IsCanonicalX25519PublicKey(publicKey) {
			t.Errorf("%s: reported canonical", name)
		}
		if _, err := WrapKey(contentKey, publicKey, "paste:x"); !errors.Is(err, ErrNonCanonicalKey) {
			t.Errorf("%s: wrap err = %v", name, err)
		}
		if _, err := DecodeAgentPublicKey(EncodeBase64URL(publicKey)); err == nil {
			t.Errorf("%s: DecodeAgentPublicKey accepted it", name)
		}
	}
	if !IsCanonicalX25519PublicKey(recipient.PublicKey) {
		t.Error("a generated key is not canonical")
	}
	almostP, _ := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if !IsCanonicalX25519PublicKey(almostP) {
		t.Error("p - 1 is canonical (though low order)")
	}

	// Non-canonical base64url (padding bits set) is refused for keys and
	// envelopes.
	encoded := EncodeBase64URL(recipient.PublicKey)
	last := strings.IndexByte(strictAlphabet, encoded[len(encoded)-1])
	if last%4 == 0 {
		mangled := encoded[:len(encoded)-1] + string(strictAlphabet[last+1])
		if _, err := DecodeAgentPublicKey(mangled); err == nil {
			t.Error("a key with padding bits set was accepted")
		}
	}
}

const strictAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
