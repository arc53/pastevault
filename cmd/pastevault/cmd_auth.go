package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

func runLogin(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("login", "pastevault login [--with-token] [flags]")
	withToken := fs.Bool("with-token", false, "Read an API token (pv_pat_...) from stdin and store it")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("login does not take positional arguments; pipe the token on stdin with --with-token")
	}

	client, err := newClient(common.server)
	if err != nil {
		return err
	}

	if *withToken {
		return loginWithToken(ctx, a, out, client)
	}

	return loginWithDevice(ctx, out, client)
}

// loginWithToken stores an API token read from stdin, after checking it
// with the server. The token never appears in argv or output.
func loginWithToken(ctx context.Context, a *app, out *output, client *pv.Client) error {
	var data string
	var err error
	if a.stdinIsTerminal() {
		// Read without echo, so the token doesn't stay on screen.
		data, err = a.promptPassword("API token: ")
	} else {
		data, err = readLine(a.stdin, 4096)
	}
	if err != nil {
		return err
	}
	token := strings.TrimSpace(data)
	if token == "" {
		return pv.UsageError("no token on stdin; pipe it in, e.g. pastevault login --with-token < token.txt")
	}
	if !pv.LooksLikeAPIToken(token) {
		return pv.UsageError("that is not a PasteVault API token (expected pv_pat_ followed by 52 characters)")
	}

	client.SetAuthToken(token)
	me, err := client.GetMe(ctx)
	if err != nil {
		if pv.IsStatus(err, 404) {
			return pv.UnsupportedError("this server does not support API tokens")
		}
		return err
	}

	if err := pv.SaveStoredAPIToken(client.BaseURL(), token); err != nil {
		return err
	}

	if out.json() {
		return out.emitJSON(whoamiResult(client, me, pv.CredentialStoredToken))
	}
	out.printf("Stored API token for %s (%s)\n", displayUser(me), client.BaseURL())
	return nil
}

func loginWithDevice(ctx context.Context, out *output, client *pv.Client) error {
	if _, err := pv.AttachStoredAuthToken(client); err != nil {
		return err
	}
	if client.HasAuthToken() {
		session, err := client.GetAuthSession(ctx)
		if err != nil {
			return err
		}
		if session != nil {
			if out.json() {
				return out.emitJSON(map[string]any{"server": client.BaseURL(), "user": session.User, "already_linked": true})
			}
			out.printf("Already linked as %s\n", pv.FormatAuthIdentity(session.User))
			return nil
		}
		_, _ = pv.DeleteStoredAuthToken(client.BaseURL())
		client.SetAuthToken("")
	}

	deviceCode, err := client.RequestDeviceCode(ctx, pv.CLIClientID)
	if err != nil {
		return err
	}

	// The approval instructions go to stderr in JSON mode, so stdout keeps
	// exactly one JSON object.
	instructions := out.printf
	if out.json() {
		instructions = func(format string, args ...any) { out.infof(strings.TrimSuffix(format, "\n"), args...) }
	}
	instructions("Open: %s\n", deviceCode.VerificationURI)
	instructions("Code: %s\n", deviceCode.UserCode)
	instructions("Or open: %s\n", deviceCode.VerificationURIComplete)
	out.infof("Waiting for approval...")

	pollInterval := time.Duration(deviceCode.Interval) * time.Second
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}

	timer := time.NewTimer(pollInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}

		tokenResponse, err := client.ExchangeDeviceToken(ctx, deviceCode.DeviceCode, pv.CLIClientID)
		if err != nil {
			var apiErr *pv.APIRequestError
			if errors.As(err, &apiErr) {
				switch apiErr.ErrorCode {
				case "authorization_pending":
					timer.Reset(pollInterval)
					continue
				case "slow_down":
					pollInterval += time.Second
					timer.Reset(pollInterval)
					continue
				case "expired_token":
					return pv.NewError(pv.ExitTimeout, pv.CodeTimeout, "login code expired; run pastevault login again")
				case "access_denied":
					return pv.NewError(pv.ExitAuth, pv.CodeAuth, "device approval was denied")
				}
			}

			return err
		}

		client.SetAuthToken(tokenResponse.AccessToken)
		if err := pv.SaveStoredAuthToken(client.BaseURL(), tokenResponse.AccessToken); err != nil {
			return err
		}

		session, err := client.GetAuthSession(ctx)
		if err != nil {
			return err
		}
		if session == nil {
			return errors.New("login completed but the server did not return a session")
		}

		if out.json() {
			return out.emitJSON(map[string]any{"server": client.BaseURL(), "user": session.User, "already_linked": false})
		}
		out.printf("Linked as %s\n", pv.FormatAuthIdentity(session.User))
		return nil
	}
}

type whoamiOutput struct {
	Server string     `json:"server"`
	User   whoamiUser `json:"user"`
	Auth   whoamiAuth `json:"auth"`
}

type whoamiUser struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
}

type whoamiAuth struct {
	// Kind is "session" or "token"; Source says where the CLI found it.
	Kind    string        `json:"kind"`
	Source  string        `json:"source"`
	TokenID string        `json:"token_id,omitempty"`
	Scopes  []string      `json:"scopes,omitempty"`
	Agent   *pv.AgentInfo `json:"agent,omitempty"`
}

func whoamiResult(client *pv.Client, me pv.MeResponse, source pv.CredentialSource) whoamiOutput {
	return whoamiOutput{
		Server: client.BaseURL(),
		User:   whoamiUser{ID: me.User.ID, Username: me.User.Username, Name: me.User.Name},
		Auth: whoamiAuth{
			Kind:    me.Auth.Kind,
			Source:  string(source),
			TokenID: me.Auth.TokenID,
			Scopes:  me.Auth.Scopes,
			Agent:   me.Auth.Agent,
		},
	}
}

func displayUser(me pv.MeResponse) string {
	return pv.FormatAuthIdentity(pv.AuthUser{ID: me.User.ID, Username: me.User.Username, Name: me.User.Name})
}

func runWhoAmI(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("whoami", "pastevault whoami [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("whoami does not take positional arguments")
	}

	client, source, _, err := accountClient(ctx, common, featureAccounts)
	if err != nil {
		return err
	}

	result := whoamiOutput{Server: client.BaseURL(), Auth: whoamiAuth{Source: string(source)}}
	if source == pv.CredentialSession {
		// Sessions work on every server version; /me (scopes) is newer.
		session, err := client.GetAuthSession(ctx)
		if err != nil {
			return err
		}
		if session == nil {
			return pv.NewError(pv.ExitAuth, pv.CodeAuth, "stored login has expired; run pastevault login again")
		}
		result.User = whoamiUser{ID: session.User.ID, Username: session.User.Username, Name: session.User.Name, Email: session.User.Email}
		result.Auth.Kind = "session"
		if me, err := client.GetMe(ctx); err == nil {
			result.Auth.Scopes = me.Auth.Scopes
		}
	} else {
		me, err := client.GetMe(ctx)
		if err != nil {
			return err
		}
		result = whoamiResult(client, me, source)
	}

	if out.json() {
		return out.emitJSON(result)
	}

	out.printf("%s\n", pv.FormatAuthIdentity(pv.AuthUser{ID: result.User.ID, Username: result.User.Username, Name: result.User.Name, Email: result.User.Email}))
	out.printf("server %s\n", result.Server)
	if !common.quiet {
		switch source {
		case pv.CredentialEnvToken:
			out.printf("auth token from %s\n", pv.EnvToken)
		case pv.CredentialStoredToken:
			out.printf("auth stored API token\n")
		default:
			out.printf("auth login session\n")
		}
		if len(result.Auth.Scopes) > 0 {
			out.printf("scopes %s\n", strings.Join(result.Auth.Scopes, " "))
		}
	}
	return nil
}

func runLogout(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("logout", "pastevault logout [--revoke] [flags]")
	revoke := fs.Bool("revoke", false, "Also revoke the stored API token on the server (needs the login session)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("logout does not take positional arguments")
	}

	client, err := newClient(common.server)
	if err != nil {
		return err
	}
	server := client.BaseURL()

	storedToken, err := pv.LoadStoredAPIToken(server)
	if err != nil {
		return err
	}
	session, err := pv.LoadStoredAuthToken(server)
	if err != nil {
		return err
	}

	result := map[string]any{"server": server, "removed_session": false, "removed_token": false, "revoked_token": false}

	// Token revocation is session-only on the server, so it runs first,
	// while the session still exists.
	if *revoke {
		if storedToken == "" {
			return pv.UsageError("--revoke: no API token is stored for %s", server)
		}
		if session == "" {
			return pv.NewError(pv.ExitAuth, pv.CodeSessionRequired, "--revoke needs the login session (pastevault login) because API tokens cannot revoke tokens; revoke it on the account page instead, or run logout without --revoke")
		}
		if err := revokeStoredToken(ctx, client, storedToken, session); err != nil {
			return err
		}
		result["revoked_token"] = true
	}

	if storedToken != "" {
		if _, err := pv.DeleteStoredAPIToken(server); err != nil {
			return err
		}
		result["removed_token"] = true
	}

	if session != "" {
		// Revoke the session server-side so a copied token stops working too.
		// This is best effort: the local login is removed even if the server
		// is unreachable.
		client.SetAuthToken(session)
		revokeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err := client.SignOut(revokeCtx); err != nil {
			out.warnf("could not revoke the session on the server: %v", err)
		}
		cancel()
		if _, err := pv.DeleteStoredAuthToken(server); err != nil {
			return err
		}
		result["removed_session"] = true
	}

	if out.json() {
		return out.emitJSON(result)
	}
	if storedToken == "" && session == "" {
		out.printf("No saved login for %s\n", server)
		return nil
	}
	if result["revoked_token"] == true {
		out.printf("Revoked the stored API token\n")
	}
	out.printf("Removed saved login for %s\n", server)
	if os.Getenv(pv.EnvToken) != "" {
		out.warnf("%s is still set in the environment", pv.EnvToken)
	}
	return nil
}

// revokeStoredToken finds the stored token's id with the token itself, then
// revokes it with the session.
func revokeStoredToken(ctx context.Context, client *pv.Client, token, session string) error {
	client.SetAuthToken(token)
	me, err := client.GetMe(ctx)
	if err != nil {
		if pv.IsStatus(err, 401) {
			// Already revoked or expired: nothing left to revoke.
			return nil
		}
		return err
	}
	if me.Auth.TokenID == "" {
		return errors.New("the server did not identify the stored token")
	}

	client.SetAuthToken(session)
	_, err = client.RevokeAPIToken(ctx, me.Auth.TokenID)
	return err
}
