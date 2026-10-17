package pastevault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const CLIClientID = "pastevault-cli"

type storedAuthConfig struct {
	Servers map[string]storedAuthServer `json:"servers"`
}

// storedAuthServer holds the credentials saved for one server: the session
// from the device login (AccessToken) and an API token from
// "login --with-token" (Token). Either may be empty.
type storedAuthServer struct {
	AccessToken string `json:"access_token,omitempty"`
	Token       string `json:"token,omitempty"`
}

func (s storedAuthServer) empty() bool {
	return strings.TrimSpace(s.AccessToken) == "" && strings.TrimSpace(s.Token) == ""
}

// EnvToken is the environment variable holding an API token. It takes
// precedence over stored credentials, but only for the configured server.
const EnvToken = "PASTEVAULT_TOKEN"

// APITokenPrefix starts every PasteVault API token.
const APITokenPrefix = "pv_pat_"

func loadStoredAuthServer(server string) (storedAuthServer, error) {
	serverKey, err := normalizeServerKey(server)
	if err != nil {
		return storedAuthServer{}, err
	}

	config, err := readStoredAuthConfig()
	if err != nil {
		return storedAuthServer{}, err
	}

	return config.Servers[serverKey], nil
}

func updateStoredAuthServer(server string, update func(*storedAuthServer) bool) (bool, error) {
	serverKey, err := normalizeServerKey(server)
	if err != nil {
		return false, err
	}

	config, err := readStoredAuthConfig()
	if err != nil {
		return false, err
	}

	entry := config.Servers[serverKey]
	if !update(&entry) {
		return false, nil
	}
	if entry.empty() {
		delete(config.Servers, serverKey)
	} else {
		config.Servers[serverKey] = entry
	}

	return true, writeStoredAuthConfig(config)
}

// LoadStoredAuthToken returns the stored login session for server.
func LoadStoredAuthToken(server string) (string, error) {
	entry, err := loadStoredAuthServer(server)
	return strings.TrimSpace(entry.AccessToken), err
}

// SaveStoredAuthToken stores a login session for server, keeping any stored
// API token.
func SaveStoredAuthToken(server, token string) error {
	_, err := updateStoredAuthServer(server, func(entry *storedAuthServer) bool {
		entry.AccessToken = strings.TrimSpace(token)
		return true
	})
	return err
}

// DeleteStoredAuthToken forgets the stored login session for server. A stored
// API token is kept.
func DeleteStoredAuthToken(server string) (bool, error) {
	return updateStoredAuthServer(server, func(entry *storedAuthServer) bool {
		if entry.AccessToken == "" {
			return false
		}
		entry.AccessToken = ""
		return true
	})
}

// LoadStoredAPIToken returns the API token saved by "login --with-token".
func LoadStoredAPIToken(server string) (string, error) {
	entry, err := loadStoredAuthServer(server)
	return strings.TrimSpace(entry.Token), err
}

func SaveStoredAPIToken(server, token string) error {
	_, err := updateStoredAuthServer(server, func(entry *storedAuthServer) bool {
		entry.Token = strings.TrimSpace(token)
		return true
	})
	return err
}

func DeleteStoredAPIToken(server string) (bool, error) {
	return updateStoredAuthServer(server, func(entry *storedAuthServer) bool {
		if entry.Token == "" {
			return false
		}
		entry.Token = ""
		return true
	})
}

// LooksLikeAPIToken reports whether value has the shape of a PasteVault API
// token (pv_pat_ followed by 52 base32 characters).
func LooksLikeAPIToken(value string) bool {
	if !strings.HasPrefix(value, APITokenPrefix) || len(value) != len(APITokenPrefix)+52 {
		return false
	}
	for _, r := range value[len(APITokenPrefix):] {
		if !(r >= 'a' && r <= 'z') && !(r >= '2' && r <= '7') {
			return false
		}
	}

	return true
}

// CredentialSource says where the credential attached to a client came from.
type CredentialSource string

const (
	CredentialNone        CredentialSource = ""
	CredentialEnvToken    CredentialSource = "env_token"
	CredentialStoredToken CredentialSource = "stored_token"
	CredentialSession     CredentialSource = "session"
)

// IsAPIToken reports whether the credential is an API token (not a session).
func (s CredentialSource) IsAPIToken() bool {
	return s == CredentialEnvToken || s == CredentialStoredToken
}

// AttachCredentials attaches the highest-precedence credential for the
// client's server: PASTEVAULT_TOKEN, then a token stored by
// "login --with-token", then the stored login session.
//
// PASTEVAULT_TOKEN is not bound to a server, so it is only sent to
// configuredServer (--server or PASTEVAULT_SERVER). A share URL pointing at
// another host never receives it.
func AttachCredentials(client *Client, configuredServer string) (CredentialSource, error) {
	if token := strings.TrimSpace(os.Getenv(EnvToken)); token != "" && SameServer(client.BaseURL(), configuredServer) {
		client.SetAuthToken(token)
		return CredentialEnvToken, nil
	}

	entry, err := loadStoredAuthServer(client.BaseURL())
	if err != nil {
		return CredentialNone, err
	}
	if token := strings.TrimSpace(entry.Token); token != "" {
		client.SetAuthToken(token)
		return CredentialStoredToken, nil
	}
	if session := strings.TrimSpace(entry.AccessToken); session != "" {
		client.SetAuthToken(session)
		return CredentialSession, nil
	}

	return CredentialNone, nil
}

// SameServer reports whether two server URLs name the same PasteVault server.
func SameServer(left, right string) bool {
	leftKey, err := normalizeServerKey(left)
	if err != nil {
		return false
	}
	rightKey, err := normalizeServerKey(right)
	if err != nil {
		return false
	}

	return strings.EqualFold(leftKey, rightKey)
}

func AttachStoredAuthToken(client *Client) (bool, error) {
	token, err := LoadStoredAuthToken(client.BaseURL())
	if err != nil {
		return false, err
	}

	if token == "" {
		return false, nil
	}

	client.SetAuthToken(token)
	return true, nil
}

func FormatAuthIdentity(user AuthUser) string {
	email := strings.TrimSpace(user.Email)
	username := strings.TrimSpace(user.Username)
	name := strings.TrimSpace(user.Name)

	switch {
	case email != "" && username != "":
		return fmt.Sprintf("%s (%s)", username, email)
	case email != "":
		return email
	case username != "":
		return username
	case name != "":
		return name
	default:
		return user.ID
	}
}

func normalizeServerKey(server string) (string, error) {
	baseURL, _, err := normalizeServerURL(server)
	if err != nil {
		return "", err
	}

	return strings.TrimRight(baseURL.String(), "/"), nil
}

// EnvConfigDir overrides the directory holding auth.json (and, in later
// versions, agent keys and the local store).
const EnvConfigDir = "PASTEVAULT_CONFIG_DIR"

// ConfigDir returns the PasteVault config directory:
// $PASTEVAULT_CONFIG_DIR, or <os.UserConfigDir>/pastevault.
func ConfigDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv(EnvConfigDir)); dir != "" {
		return filepath.Clean(dir), nil
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "pastevault"), nil
}

func authConfigPath() (string, error) {
	configDir, err := ConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "auth.json"), nil
}

func readStoredAuthConfig() (storedAuthConfig, error) {
	configPath, err := authConfigPath()
	if err != nil {
		return storedAuthConfig{}, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return storedAuthConfig{
				Servers: make(map[string]storedAuthServer),
			}, nil
		}

		return storedAuthConfig{}, err
	}

	config := storedAuthConfig{}
	if err := json.Unmarshal(data, &config); err != nil {
		return storedAuthConfig{}, fmt.Errorf("failed to parse %s: %w", configPath, err)
	}

	if config.Servers == nil {
		config.Servers = make(map[string]storedAuthServer)
	}

	return config, nil
}

func writeStoredAuthConfig(config storedAuthConfig) error {
	configPath, err := authConfigPath()
	if err != nil {
		return err
	}

	if config.Servers == nil {
		config.Servers = make(map[string]storedAuthServer)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return err
	}

	if err := os.Rename(tempPath, configPath); err != nil {
		return err
	}

	return os.Chmod(configPath, 0o600)
}
