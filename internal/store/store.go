// Package store is the sealed local secret store (spec §3.4, §4):
//
//	<ConfigDir>/store/<server dir>/<agent>/<NAME>.pvs   0600, directories 0700
//	{v:1, name, kind, created_at, source:{type, ref}, fingerprint,
//	 wrapped_key, nonce, ciphertext}
//
// Each entry is a SecretPayload encrypted with its own content key under AAD
// "pastevault:store:<NAME>:v1"; the key is wrapped (PVWRAP1, context
// "store:<NAME>") to the agent identity that owns the store. Entries are
// referenced as pv://secret/NAME and never printed by the CLI (except
// "secret reveal" on a terminal).
//
// The store keeps secrets out of transcripts and off the server; it is not a
// boundary against code running as the same OS user, which can read the
// agent key next to it.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

const (
	entryVersion = 1
	entrySuffix  = ".pvs"
	// MaxValueBytes caps one entry's secret (a text value or a file).
	MaxValueBytes = 10 * 1024 * 1024
)

// Source types: where an entry came from.
const (
	SourceRequest = "request"
	SourceShare   = "share"
	SourceImport  = "import"
)

// Source records an entry's origin. Ref never contains a key.
type Source struct {
	Type string `json:"type"`
	Ref  string `json:"ref,omitempty"`
}

// Entry is one .pvs file.
type Entry struct {
	V         int    `json:"v"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"created_at"`
	Source    Source `json:"source"`
	// Fingerprint of the agent key the entry is sealed to (an addition to
	// the spec: it finds the key again after the agent is re-initialised).
	Fingerprint string `json:"fingerprint"`
	pv.SealedSecret

	Path string `json:"-"`
}

// Handle is the entry's pv://secret handle.
func (e Entry) Handle() string {
	return pv.SecretHandle(e.Name)
}

// Store is one agent's store on one server.
type Store struct {
	Server   string
	Agent    string
	Dir      string
	Identity *pv.AgentIdentity
}

// Open returns the store of identity on server. Nothing is created until an
// entry is written.
func Open(server string, identity *pv.AgentIdentity) (*Store, error) {
	if identity == nil {
		return nil, errors.New("the store needs an agent identity")
	}

	serverDir, err := pv.ServerDirName(server)
	if err != nil {
		return nil, pv.UsageError("invalid server URL %q: %v", server, err)
	}
	configDir, err := pv.ConfigDir()
	if err != nil {
		return nil, err
	}

	agent := AgentDirName(server, identity)
	return &Store{
		Server:   server,
		Agent:    agent,
		Dir:      filepath.Join(configDir, "store", serverDir, agent),
		Identity: identity,
	}, nil
}

// AgentDirName is the store directory of an identity: its agent name, or for
// a bare PASTEVAULT_AGENT_KEY the name of a local key file with the same key,
// else its fingerprint.
func AgentDirName(server string, identity *pv.AgentIdentity) string {
	if identity.Name != "" {
		return identity.Name
	}
	if locals, _, err := pv.LocalAgentIdentities(server); err == nil {
		for _, local := range locals {
			if local.Fingerprint == identity.Fingerprint && !local.Revoked() {
				return local.Name
			}
		}
	}

	return identity.Fingerprint
}

func (s *Store) path(name string) (string, error) {
	if !pv.ValidSecretName(name) {
		return "", pv.UsageError("invalid secret name %q (letters, digits, _ . -, starting with a letter or _, at most 128)", name)
	}

	return filepath.Join(s.Dir, name+entrySuffix), nil
}

// Exists reports whether name has an entry.
func (s *Store) Exists(name string) (bool, error) {
	target, err := s.path(name)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(target)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}

	return false, err
}

// CheckWritable fails (exit 13) when name exists and may not be replaced.
// Run it before consuming anything that is to be saved.
func (s *Store) CheckWritable(name string, overwrite bool) error {
	exists, err := s.Exists(name)
	if err != nil {
		return err
	}
	if exists && !overwrite {
		return pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "the secret %s already exists in the local store; remove it (pastevault secret rm %s) or pass --overwrite", name, name)
	}

	return nil
}

// Put seals payload as entry name (the payload's name is set to name).
func (s *Store) Put(name string, payload pv.SecretPayload, source Source, overwrite bool) (*Entry, error) {
	target, err := s.path(name)
	if err != nil {
		return nil, err
	}
	if err := s.CheckWritable(name, overwrite); err != nil {
		return nil, err
	}
	value, err := payload.Bytes()
	if err != nil {
		return nil, err
	}
	if len(value) > MaxValueBytes {
		return nil, pv.NewError(pv.ExitUsage, pv.CodeTooLarge, "the secret is larger than %d bytes", MaxValueBytes)
	}

	payload.Name = name
	sealed, err := pv.SealSecretPayload(payload, s.Identity.Keys().PublicKey, pv.StoreWrapContext(name), pv.StorePayloadAAD(name))
	if err != nil {
		return nil, err
	}

	entry := &Entry{
		V:            entryVersion,
		Name:         name,
		Kind:         payload.Kind,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Source:       source,
		Fingerprint:  s.Identity.Fingerprint,
		SealedSecret: sealed,
	}
	if err := writePrivateJSON(target, entry); err != nil {
		return nil, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "could not write the local store")
	}
	entry.Path = target

	return entry, nil
}

func readEntry(target string) (*Entry, error) {
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	tighten(target, 0o600)

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", target, err)
	}
	if entry.V != entryVersion || !pv.ValidSecretName(entry.Name) || entry.WrappedKey == "" {
		return nil, fmt.Errorf("%s is not a valid store entry", target)
	}
	entry.Path = target

	return &entry, nil
}

// Entry returns name's entry without decrypting it.
func (s *Store) Entry(name string) (*Entry, error) {
	target, err := s.path(name)
	if err != nil {
		return nil, err
	}
	entry, err := readEntry(target)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no secret %s in the local store of agent %s (pastevault secret list)", name, s.Agent)
	}
	if err != nil {
		return nil, err
	}
	if entry.Name != name {
		return nil, pv.DecryptError("the store file for %s holds %s; refusing it", name, entry.Name)
	}

	return entry, nil
}

// Get decrypts name's entry.
func (s *Store) Get(name string) (*Entry, pv.SecretPayload, error) {
	entry, err := s.Entry(name)
	if err != nil {
		return nil, pv.SecretPayload{}, err
	}

	identity := s.Identity
	if entry.Fingerprint != "" && entry.Fingerprint != identity.Fingerprint {
		// Sealed to an earlier key of this agent (re-initialised or revoked).
		if identity, err = pv.FindIdentityByFingerprint(s.Server, entry.Fingerprint); err != nil {
			return nil, pv.SecretPayload{}, err
		}
		if identity == nil {
			return nil, pv.SecretPayload{}, pv.DecryptError("the secret %s is sealed to agent key %s, which is not on this machine", name, pv.ShortFingerprint(entry.Fingerprint))
		}
	}

	payload, err := pv.OpenSecretPayload(entry.SealedSecret, identity.Keys().PrivateKey, pv.StoreWrapContext(name), pv.StorePayloadAAD(name))
	if err != nil {
		return nil, pv.SecretPayload{}, err
	}
	if payload.Name != name || payload.Kind != entry.Kind {
		return nil, pv.SecretPayload{}, pv.DecryptError("the secret %s does not match its store entry", name)
	}

	return entry, payload, nil
}

// List returns the entries sorted by name. Damaged files are skipped and
// reported as warnings.
func (s *Store) List() ([]*Entry, []string, error) {
	files, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	var entries []*Entry
	var warnings []string
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), entrySuffix) || strings.HasPrefix(file.Name(), ".") {
			continue
		}
		entry, err := readEntry(filepath.Join(s.Dir, file.Name()))
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		if entry.Name+entrySuffix != file.Name() {
			warnings = append(warnings, fmt.Sprintf("%s holds %s; skipped", file.Name(), entry.Name))
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	return entries, warnings, nil
}

// Remove deletes name's entry.
func (s *Store) Remove(name string) error {
	target, err := s.path(name)
	if err != nil {
		return err
	}
	err = os.Remove(target)
	if errors.Is(err, fs.ErrNotExist) {
		return pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no secret %s in the local store of agent %s", name, s.Agent)
	}

	return err
}

func tighten(target string, mode fs.FileMode) {
	if runtime.GOOS == "windows" {
		return
	}
	if info, err := os.Stat(target); err == nil && info.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(target, mode)
	}
}

// writePrivateJSON atomically writes value readable only by the owner,
// creating directories 0700 (re-tightened if they exist).
func writePrivateJSON(target string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// The store root and server directory too, in case they were created
	// with a looser umask by something else.
	for current, steps := dir, 0; steps < 3; current, steps = filepath.Dir(current), steps+1 {
		tighten(current, 0o700)
	}

	temp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}

	return os.Rename(tempPath, target)
}
