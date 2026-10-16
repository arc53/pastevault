package pastevault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Agent identities on disk (spec §4):
//
//	<ConfigDir>/agents/<server dir>/<name>.json   0600, directories 0700
//	{v:1, name, server, agent_id, public_key, private_key, fingerprint, created_at}
//
// The server dir is the server URL made filesystem-safe (ServerDirName). A
// revoked agent's file is renamed to <name>.revoked-<unix>.json: its key can
// still open shares sealed to it before the revoke, and the name is free for
// a new agent.
//
// PASTEVAULT_AGENT_KEY supplies a private key (base64url) instead of a file,
// for CI and containers. PASTEVAULT_AGENT selects the default agent by name.
const (
	EnvAgent    = "PASTEVAULT_AGENT"
	EnvAgentKey = "PASTEVAULT_AGENT_KEY"

	identityFileVersion = 1
	// IdentitySourceFile and IdentitySourceEnv say where a key came from.
	IdentitySourceFile = "file"
	IdentitySourceEnv  = "env"
)

var agentNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidAgentName reports whether name is a valid agent name (the server's rule).
func ValidAgentName(name string) bool {
	return agentNamePattern.MatchString(name)
}

// AgentIdentity is an agent key held on this machine.
type AgentIdentity struct {
	V           int    `json:"v"`
	Name        string `json:"name"`
	Server      string `json:"server"`
	AgentID     string `json:"agent_id"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
	// RevokedAt is set locally by "agent revoke".
	RevokedAt string `json:"revoked_at,omitempty"`

	// Path is the key file ("" for PASTEVAULT_AGENT_KEY); Source is
	// IdentitySourceFile or IdentitySourceEnv.
	Path   string `json:"-"`
	Source string `json:"-"`
	keys   AgentKeyPair
}

// Keys returns the identity's key pair (validated on load).
func (identity *AgentIdentity) Keys() AgentKeyPair {
	return identity.keys
}

// Revoked reports whether "agent revoke" retired this key locally.
func (identity *AgentIdentity) Revoked() bool {
	return identity.RevokedAt != ""
}

// NewAgentIdentity builds the file record for a freshly generated key pair.
func NewAgentIdentity(server, name string, keys AgentKeyPair) *AgentIdentity {
	return &AgentIdentity{
		V:           identityFileVersion,
		Name:        name,
		Server:      server,
		PublicKey:   EncodeBase64URL(keys.PublicKey),
		PrivateKey:  EncodeBase64URL(keys.PrivateKey),
		Fingerprint: keys.Fingerprint,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:      IdentitySourceFile,
		keys:        keys,
	}
}

// validate checks the file against its own private key: the stored public
// key and fingerprint must be the ones the private key derives.
func (identity *AgentIdentity) validate() error {
	if identity.V != identityFileVersion {
		return fmt.Errorf("unsupported agent key file version %d", identity.V)
	}
	keys, err := DecodeAgentPrivateKey(identity.PrivateKey)
	if err != nil {
		return err
	}
	if EncodeBase64URL(keys.PublicKey) != identity.PublicKey || keys.Fingerprint != identity.Fingerprint {
		return errors.New("the public key or fingerprint does not match the private key")
	}
	identity.keys = keys

	return nil
}

// ServerDirName turns a server URL into a directory name, e.g.
// https://api.pastevault.dev -> https_api.pastevault.dev and
// http://127.0.0.1:3001 -> http_127.0.0.1_3001.
func ServerDirName(server string) (string, error) {
	key, err := normalizeServerKey(server)
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	for _, r := range strings.Replace(strings.ToLower(key), "://", "_", 1) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			builder.WriteRune(r)
		default:
			builder.WriteRune('_')
		}
	}

	return strings.Trim(builder.String(), "_."), nil
}

func agentsRootDir() (string, error) {
	configDir, err := ConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "agents"), nil
}

// AgentKeyDir is the directory holding the server's agent key files.
func AgentKeyDir(server string) (string, error) {
	root, err := agentsRootDir()
	if err != nil {
		return "", err
	}
	name, err := ServerDirName(server)
	if err != nil {
		return "", err
	}

	return filepath.Join(root, name), nil
}

// AgentKeyPath is where the key of agent name lives.
func AgentKeyPath(server, name string) (string, error) {
	if !ValidAgentName(name) {
		return "", UsageError("invalid agent name %q: use 1-63 characters of a-z, 0-9, '.', '_' or '-'", name)
	}
	dir, err := AgentKeyDir(server)
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, name+".json"), nil
}

func readAgentIdentity(path string) (*AgentIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	identity := &AgentIdentity{}
	if err := json.Unmarshal(data, identity); err != nil {
		return nil, fmt.Errorf("could not parse agent key file %s: %w", path, err)
	}
	if err := identity.validate(); err != nil {
		return nil, fmt.Errorf("agent key file %s is damaged: %w", path, err)
	}
	identity.Path = path
	identity.Source = IdentitySourceFile
	tightenPermissions(path, 0o600)

	return identity, nil
}

// tightenPermissions restores owner-only access if something loosened it.
// Windows has no Unix modes; files there inherit the profile directory's ACLs.
func tightenPermissions(path string, mode fs.FileMode) {
	if runtime.GOOS == "windows" {
		return
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(path, mode)
	}
}

// LoadAgentIdentity returns the active key of agent name, or nil when this
// machine has none.
func LoadAgentIdentity(server, name string) (*AgentIdentity, error) {
	path, err := AgentKeyPath(server, name)
	if err != nil {
		return nil, err
	}

	identity, err := readAgentIdentity(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	return identity, err
}

// EnvAgentIdentity returns the identity given by PASTEVAULT_AGENT_KEY, or nil.
// Its name and agent id are unknown until matched against the server.
func EnvAgentIdentity() (*AgentIdentity, error) {
	value := strings.TrimSpace(os.Getenv(EnvAgentKey))
	if value == "" {
		return nil, nil
	}

	keys, err := DecodeAgentPrivateKey(value)
	if err != nil {
		return nil, UsageError("%s is not a valid agent private key: %v", EnvAgentKey, err)
	}

	return &AgentIdentity{
		V:           identityFileVersion,
		PublicKey:   EncodeBase64URL(keys.PublicKey),
		Fingerprint: keys.Fingerprint,
		Source:      IdentitySourceEnv,
		keys:        keys,
	}, nil
}

// LocalAgentIdentities lists the key files for server, active ones first by
// name, then retired (revoked) ones. Damaged files are skipped and reported
// in the returned warnings.
func LocalAgentIdentities(server string) ([]*AgentIdentity, []string, error) {
	dir, err := AgentKeyDir(server)
	if err != nil {
		return nil, nil, err
	}

	return readIdentityDir(dir)
}

func readIdentityDir(dir string) ([]*AgentIdentity, []string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	var identities []*AgentIdentity
	var warnings []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		identity, err := readAgentIdentity(filepath.Join(dir, entry.Name()))
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		identities = append(identities, identity)
	}

	sort.SliceStable(identities, func(i, j int) bool {
		if identities[i].Revoked() != identities[j].Revoked() {
			return !identities[i].Revoked()
		}
		return identities[i].Name < identities[j].Name
	})

	return identities, warnings, nil
}

// FindIdentityByFingerprint returns the local key whose fingerprint is
// exactly fingerprint: PASTEVAULT_AGENT_KEY first, then key files for
// server, then key files for any other server (fingerprints are unique, and a
// share link may name the web origin rather than the API server).
func FindIdentityByFingerprint(server, fingerprint string) (*AgentIdentity, error) {
	if !IsFingerprint(fingerprint) {
		return nil, nil
	}

	envIdentity, err := EnvAgentIdentity()
	if err != nil {
		return nil, err
	}
	if envIdentity != nil && envIdentity.Fingerprint == fingerprint {
		return envIdentity, nil
	}

	preferred, err := AgentKeyDir(server)
	if err != nil {
		return nil, err
	}
	dirs := []string{preferred}
	root, err := agentsRootDir()
	if err != nil {
		return nil, err
	}
	if entries, err := os.ReadDir(root); err == nil {
		for _, entry := range entries {
			if candidate := filepath.Join(root, entry.Name()); entry.IsDir() && candidate != preferred {
				dirs = append(dirs, candidate)
			}
		}
	}

	for _, dir := range dirs {
		identities, _, err := readIdentityDir(dir)
		if err != nil {
			continue
		}
		for _, identity := range identities {
			if identity.Fingerprint == fingerprint {
				return identity, nil
			}
		}
	}

	return nil, nil
}

// SaveAgentIdentity writes identity to path (0600, directories 0700),
// replacing an existing file only when overwrite is set.
func SaveAgentIdentity(identity *AgentIdentity, path string, overwrite bool) error {
	if !overwrite {
		if _, err := os.Lstat(path); err == nil {
			return NewError(ExitLocalFile, CodeLocalFile, "%s already exists", path)
		}
	}
	if err := writePrivateJSON(path, identity); err != nil {
		return WrapError(ExitLocalFile, CodeLocalFile, err, "could not write the agent key file")
	}
	identity.Path = path
	identity.Source = IdentitySourceFile

	return nil
}

// RetireAgentIdentity marks a key file revoked and renames it out of the
// way, keeping the key for shares that were sealed to it.
func RetireAgentIdentity(identity *AgentIdentity) (string, error) {
	if identity.Source != IdentitySourceFile || identity.Path == "" {
		return "", nil
	}

	identity.RevokedAt = time.Now().UTC().Format(time.RFC3339)
	target := strings.TrimSuffix(identity.Path, ".json") + fmt.Sprintf(".revoked-%d.json", time.Now().Unix())
	if err := writePrivateJSON(target, identity); err != nil {
		return "", WrapError(ExitLocalFile, CodeLocalFile, err, "could not retire the agent key file")
	}
	if err := os.Remove(identity.Path); err != nil {
		return "", WrapError(ExitLocalFile, CodeLocalFile, err, "could not remove %s", identity.Path)
	}
	identity.Path = target

	return target, nil
}

// writePrivateJSON atomically writes value as JSON readable only by the
// owner, creating parent directories with mode 0700.
func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tightenPermissions(dir, 0o700)

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
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}

	return nil
}

// CLI settings that belong to this CLI rather than the updater, which keeps
// its own config.json (internal/update) outside PASTEVAULT_CONFIG_DIR:
//
//	<ConfigDir>/cli.json  {"servers": {"<server>": {"default_agent": "name"}}}
type cliSettings struct {
	Servers map[string]cliServerSettings `json:"servers"`
}

type cliServerSettings struct {
	DefaultAgent string `json:"default_agent,omitempty"`
}

func cliSettingsPath() (string, error) {
	configDir, err := ConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "cli.json"), nil
}

func readCLISettings() (cliSettings, string, error) {
	path, err := cliSettingsPath()
	if err != nil {
		return cliSettings{}, "", err
	}

	settings := cliSettings{}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return cliSettings{}, "", err
	default:
		if err := json.Unmarshal(data, &settings); err != nil {
			return cliSettings{}, "", fmt.Errorf("could not parse %s: %w", path, err)
		}
	}
	if settings.Servers == nil {
		settings.Servers = map[string]cliServerSettings{}
	}

	return settings, path, nil
}

// DefaultAgentSource says where the default agent name came from.
type DefaultAgentSource string

const (
	DefaultAgentNone     DefaultAgentSource = ""
	DefaultAgentEnv      DefaultAgentSource = "env"
	DefaultAgentSettings DefaultAgentSource = "settings"
)

// DefaultAgentName returns the agent to use when none is named:
// PASTEVAULT_AGENT, then the default saved for server in cli.json.
func DefaultAgentName(server string) (string, DefaultAgentSource, error) {
	if name := strings.TrimSpace(os.Getenv(EnvAgent)); name != "" {
		return name, DefaultAgentEnv, nil
	}

	key, err := normalizeServerKey(server)
	if err != nil {
		return "", DefaultAgentNone, err
	}
	settings, _, err := readCLISettings()
	if err != nil {
		return "", DefaultAgentNone, err
	}
	if name := settings.Servers[key].DefaultAgent; name != "" {
		return name, DefaultAgentSettings, nil
	}

	return "", DefaultAgentNone, nil
}

// SetDefaultAgent saves name as server's default agent; "" clears it.
func SetDefaultAgent(server, name string) error {
	key, err := normalizeServerKey(server)
	if err != nil {
		return err
	}
	settings, path, err := readCLISettings()
	if err != nil {
		return err
	}

	entry := settings.Servers[key]
	entry.DefaultAgent = name
	if entry == (cliServerSettings{}) {
		delete(settings.Servers, key)
	} else {
		settings.Servers[key] = entry
	}

	return writePrivateJSON(path, settings)
}
