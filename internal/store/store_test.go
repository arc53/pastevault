package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

const testServer = "http://127.0.0.1:3001"

func newIdentity(t *testing.T, name string) *pv.AgentIdentity {
	t.Helper()
	keys, err := pv.GenerateAgentKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	identity := pv.NewAgentIdentity(testServer, name, keys)
	path, err := pv.AgentKeyPath(testServer, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := pv.SaveAgentIdentity(identity, path, true); err != nil {
		t.Fatal(err)
	}
	return identity
}

func isolate(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "config")
	t.Setenv(pv.EnvConfigDir, dir)
	t.Setenv(pv.EnvAgent, "")
	t.Setenv(pv.EnvAgentKey, "")
	return dir
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestStoreRoundTrip(t *testing.T) {
	config := isolate(t)
	identity := newIdentity(t, "laptop")
	store, err := Open(testServer, identity)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(config, "store", "http_127.0.0.1_3001", "laptop"); store.Dir != want {
		t.Fatalf("Dir = %q, want %q", store.Dir, want)
	}

	payload, _ := pv.NewTextPayload("ignored", []byte("s3cr3t-value"))
	entry, err := store.Put("API_KEY", payload, Source{Type: SourceImport}, false)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Handle() != "pv://secret/API_KEY" || entry.Fingerprint != identity.Fingerprint {
		t.Fatalf("entry = %+v", entry)
	}
	data, _ := os.ReadFile(entry.Path)
	if strings.Contains(string(data), "s3cr3t") {
		t.Fatal("the store file contains the plaintext")
	}
	if runtime.GOOS != "windows" {
		if got := mode(t, entry.Path); got != 0o600 {
			t.Fatalf("entry mode %o, want 600", got)
		}
		for _, dir := range []string{store.Dir, filepath.Dir(store.Dir), filepath.Join(config, "store")} {
			if got := mode(t, dir); got != 0o700 {
				t.Fatalf("%s mode %o, want 700", dir, got)
			}
		}
	}

	_, opened, err := store.Get("API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := opened.Bytes(); string(value) != "s3cr3t-value" || opened.Name != "API_KEY" {
		t.Fatalf("Get = %+v", opened)
	}

	if _, err := store.Put("API_KEY", payload, Source{Type: SourceImport}, false); pv.Classify(err).Exit != pv.ExitLocalFile {
		t.Fatalf("Put over an existing entry: %v, want exit 13", err)
	}
	if _, err := store.Put("API_KEY", payload, Source{Type: SourceImport}, true); err != nil {
		t.Fatal(err)
	}

	file := pv.NewFilePayload("x", "id_ed25519", "application/octet-stream", []byte{0, 1, 2})
	if _, err := store.Put("SSH_KEY", file, Source{Type: SourceShare, Ref: "abc"}, false); err != nil {
		t.Fatal(err)
	}
	entries, warnings, err := store.List()
	if err != nil || len(warnings) != 0 || len(entries) != 2 || entries[0].Name != "API_KEY" || entries[1].Kind != pv.SecretKindFile {
		t.Fatalf("List = %+v %v %v", entries, warnings, err)
	}

	// An entry copied under another name is refused (the AAD and wrap
	// context bind the name), and listed with a warning.
	copied := filepath.Join(store.Dir, "OTHER.pvs")
	original, _ := os.ReadFile(filepath.Join(store.Dir, "API_KEY.pvs"))
	_ = os.WriteFile(copied, original, 0o600)
	if _, _, err := store.Get("OTHER"); pv.Classify(err).Exit != pv.ExitDecrypt {
		t.Fatalf("Get(renamed) = %v, want exit 7", err)
	}
	var raw map[string]any
	_ = json.Unmarshal(original, &raw)
	raw["name"] = "OTHER"
	relabelled, _ := json.Marshal(raw)
	_ = os.WriteFile(copied, relabelled, 0o600)
	if _, _, err := store.Get("OTHER"); pv.Classify(err).Exit != pv.ExitDecrypt {
		t.Fatalf("Get(relabelled) = %v, want exit 7", err)
	}
	_ = os.Remove(copied)

	if err := store.Remove("SSH_KEY"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("SSH_KEY"); pv.Classify(err).Exit != pv.ExitNotFound {
		t.Fatalf("Remove twice: %v", err)
	}
	if _, _, err := store.Get("MISSING"); pv.Classify(err).Exit != pv.ExitNotFound {
		t.Fatalf("Get(missing): %v", err)
	}
	if _, err := store.Exists("../escape"); err == nil {
		t.Fatal("names must not be paths")
	}

	// A loosened file is re-tightened on read.
	if runtime.GOOS != "windows" {
		path := filepath.Join(store.Dir, "API_KEY.pvs")
		_ = os.Chmod(path, 0o644)
		if _, _, err := store.Get("API_KEY"); err != nil {
			t.Fatal(err)
		}
		if got := mode(t, path); got != 0o600 {
			t.Fatalf("mode after read %o", got)
		}
	}
}

func TestStoreAfterAgentReinit(t *testing.T) {
	isolate(t)
	old := newIdentity(t, "laptop")
	store, _ := Open(testServer, old)
	payload, _ := pv.NewTextPayload("x", []byte("value-sealed-to-old-key"))
	if _, err := store.Put("OLD", payload, Source{Type: SourceImport}, false); err != nil {
		t.Fatal(err)
	}

	// Re-initialised: the old key is retired, a new one takes the name.
	if _, err := pv.RetireAgentIdentity(old); err != nil {
		t.Fatal(err)
	}
	fresh := newIdentity(t, "laptop")
	reopened, _ := Open(testServer, fresh)
	if reopened.Dir != store.Dir {
		t.Fatal("the store follows the agent name")
	}
	_, opened, err := reopened.Get("OLD")
	if err != nil {
		t.Fatalf("an entry sealed to the retired key still opens: %v", err)
	}
	if value, _ := opened.Bytes(); string(value) != "value-sealed-to-old-key" {
		t.Fatal("wrong value")
	}
}

func TestStoreWithEnvAgentKey(t *testing.T) {
	isolate(t)
	keys, _ := pv.GenerateAgentKeyPair()
	t.Setenv(pv.EnvAgentKey, pv.EncodeBase64URL(keys.PrivateKey))
	identity, err := pv.ResolveLocalAgent(testServer, "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(testServer, identity)
	if err != nil {
		t.Fatal(err)
	}
	if store.Agent != keys.Fingerprint {
		t.Fatalf("an unnamed env key's store is named by its fingerprint, got %q", store.Agent)
	}
	payload, _ := pv.NewTextPayload("x", []byte("ci-secret"))
	if _, err := store.Put("CI", payload, Source{Type: SourceImport}, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get("CI"); err != nil {
		t.Fatal(err)
	}
}
