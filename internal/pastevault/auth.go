package pastevault

import (
	"context"
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

type storedAuthServer struct {
	AccessToken string `json:"access_token"`
}

func LoadStoredAuthToken(server string) (string, error) {
	serverKey, err := normalizeServerKey(server)
	if err != nil {
		return "", err
	}

	config, err := readStoredAuthConfig()
	if err != nil {
		return "", err
	}

	serverConfig, ok := config.Servers[serverKey]
	if !ok {
		return "", nil
	}

	return strings.TrimSpace(serverConfig.AccessToken), nil
}

func SaveStoredAuthToken(server, token string) error {
	serverKey, err := normalizeServerKey(server)
	if err != nil {
		return err
	}

	config, err := readStoredAuthConfig()
	if err != nil {
		return err
	}

	if config.Servers == nil {
		config.Servers = make(map[string]storedAuthServer)
	}

	config.Servers[serverKey] = storedAuthServer{
		AccessToken: strings.TrimSpace(token),
	}

	return writeStoredAuthConfig(config)
}

func DeleteStoredAuthToken(server string) (bool, error) {
	serverKey, err := normalizeServerKey(server)
	if err != nil {
		return false, err
	}

	config, err := readStoredAuthConfig()
	if err != nil {
		return false, err
	}

	if _, ok := config.Servers[serverKey]; !ok {
		return false, nil
	}

	delete(config.Servers, serverKey)
	return true, writeStoredAuthConfig(config)
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

func ValidateStoredAuthSession(
	ctx context.Context,
	client *Client,
) (*AuthSessionResponse, bool, error) {
	hasStoredToken, err := AttachStoredAuthToken(client)
	if err != nil {
		return nil, false, err
	}

	if !hasStoredToken {
		return nil, false, nil
	}

	session, err := client.GetAuthSession(ctx)
	if err != nil {
		return nil, true, err
	}

	return session, true, nil
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

func authConfigPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "pastevault", "auth.json"), nil
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
