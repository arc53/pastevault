package main

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

// Token management is session-only on the server: these commands use the
// login session from "pastevault login" and never PASTEVAULT_TOKEN or a
// stored API token, so a leaked token cannot mint or revoke tokens.
func runToken(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return pv.UsageError("usage: pastevault token <create|list|revoke> [flags]")
	}

	switch args[0] {
	case "create":
		return runTokenCreate(ctx, a, args[1:])
	case "list", "ls":
		return runTokenList(ctx, a, args[1:])
	case "revoke", "rm":
		return runTokenRevoke(ctx, a, args[1:])
	case "--help", "-h", "help":
		fmt.Fprintln(a.stderr, "Usage:\n  pastevault token create --name N [--scopes a,b] [--expires 90d|never] [--agent NAME]\n  pastevault token list\n  pastevault token revoke <id | prefix>")
		return errHelpShown
	default:
		return pv.UsageError("unknown token command %q (expected create, list or revoke)", args[0])
	}
}

// knownScopes mirrors the server's scopes (docs/cli-reference.md).
var knownScopes = []string{
	"shares:create", "shares:read", "shares:revoke", "shares:receive",
	"agents:read", "agents:write", "requests:create", "audit:read",
}

func runTokenCreate(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("token create", "pastevault token create --name N [--scopes a,b] [--expires 90d|never] [--agent NAME] [flags]")
	name := fs.String("name", "", "Token name, e.g. ci or laptop-agent")
	scopes := fs.String("scopes", "", "Comma-separated scopes (default: all except agents:write)")
	expires := fs.String("expires", "90d", "Lifetime in days (1d-365d) or never")
	agent := fs.String("agent", "", "Bind the token to this agent (name or pvk1_ fingerprint); revoking the agent revokes the token")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("token create does not take positional arguments")
	}
	if strings.TrimSpace(*name) == "" {
		return pv.UsageError("--name is required")
	}

	request := pv.CreateAPITokenRequest{Name: strings.TrimSpace(*name)}
	if *scopes != "" {
		for _, scope := range strings.Split(*scopes, ",") {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			if !containsString(knownScopes, scope) {
				return pv.UsageError("unknown scope %q (known: %s)", scope, strings.Join(knownScopes, ", "))
			}
			request.Scopes = append(request.Scopes, scope)
		}
		if len(request.Scopes) == 0 {
			return pv.UsageError("--scopes is empty")
		}
	}
	request.ExpiresInDays, err = pv.ParseTokenExpiry(*expires)
	if err != nil {
		return err
	}

	client, err := sessionClient(ctx, common)
	if err != nil {
		return err
	}
	if *agent != "" {
		request.AgentID, err = resolveTokenAgent(ctx, client, strings.TrimSpace(*agent))
		if err != nil {
			return err
		}
	}
	created, err := client.CreateAPIToken(ctx, request)
	if err != nil {
		return tokenAPIError(err)
	}

	if out.json() {
		return out.emitJSON(created)
	}

	// The token alone on stdout, so "token create -q > file" works.
	out.printf("%s\n", created.Token)
	expiry := "never expires"
	if created.ExpiresAt != nil {
		expiry = "expires " + formatTime(*created.ExpiresAt)
	}
	out.infof("Created token %q (%s, id %s, %s) with scopes: %s", created.Name, created.Prefix, created.ID, expiry, strings.Join(created.Scopes, " "))
	out.infof("This is the only time the token is shown. Use it as PASTEVAULT_TOKEN or with pastevault login --with-token.")
	return nil
}

func runTokenList(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("token list", "pastevault token list [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("token list does not take positional arguments")
	}

	client, err := sessionClient(ctx, common)
	if err != nil {
		return err
	}
	response, err := client.ListAPITokens(ctx)
	if err != nil {
		return tokenAPIError(err)
	}
	if response.Tokens == nil {
		response.Tokens = []pv.APITokenSummary{}
	}

	if out.json() {
		return out.emitJSON(response)
	}
	if len(response.Tokens) == 0 {
		out.infof("No API tokens.")
		return nil
	}

	table := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	if !common.quiet {
		fmt.Fprintln(table, "ID\tPREFIX\tNAME\tSTATUS\tEXPIRES\tLAST USED\tSCOPES")
	}
	for _, token := range response.Tokens {
		status := "active"
		if token.RevokedAt != nil {
			status = "revoked"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			token.ID, token.Prefix, token.Name, status,
			formatOptionalTime(token.ExpiresAt, "never"), formatOptionalTime(token.LastUsedAt, "-"),
			strings.Join(token.Scopes, ","))
	}
	return table.Flush()
}

func runTokenRevoke(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("token revoke", "pastevault token revoke [flags] <id | prefix>")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("name exactly one token by id or prefix (see pastevault token list)")
	}
	target := strings.TrimSpace(positional[0])

	client, err := sessionClient(ctx, common)
	if err != nil {
		return err
	}
	tokens, err := client.ListAPITokens(ctx)
	if err != nil {
		return tokenAPIError(err)
	}

	id, err := matchToken(tokens.Tokens, target)
	if err != nil {
		return err
	}

	response, err := client.RevokeAPIToken(ctx, id)
	if err != nil {
		return tokenAPIError(err)
	}

	if out.json() {
		return out.emitJSON(response)
	}
	out.printf("Revoked token %q (%s)\n", response.Token.Name, response.Token.Prefix)
	return nil
}

// matchToken finds a token by id, by its 12-character prefix, or by the full
// token value (only its prefix is compared; the token itself never leaves
// this process).
func matchToken(tokens []pv.APITokenSummary, target string) (string, error) {
	prefix := target
	if strings.HasPrefix(target, pv.APITokenPrefix) && len(target) > 12 {
		prefix = target[:12]
	}

	var matches []pv.APITokenSummary
	for _, token := range tokens {
		if token.ID == target {
			return token.ID, nil
		}
		if token.Prefix == prefix {
			matches = append(matches, token)
		}
	}

	switch {
	case len(matches) == 1:
		return matches[0].ID, nil
	case len(matches) > 1:
		active := matches[:0]
		for _, token := range matches {
			if token.RevokedAt == nil {
				active = append(active, token)
			}
		}
		if len(active) == 1 {
			return active[0].ID, nil
		}
		return "", pv.UsageError("prefix %s matches %d tokens; use the token id from pastevault token list", prefix, len(matches))
	default:
		return "", pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no token with id or prefix %s", redactToken(target))
	}
}

// tokenAPIError explains a 404 from an old server without token support.
func tokenAPIError(err error) error {
	if pv.IsStatus(err, 404) && !strings.Contains(err.Error(), "Token not found") {
		return pv.UnsupportedError("this server does not support API tokens")
	}

	return err
}

func redactToken(value string) string {
	if strings.HasPrefix(value, pv.APITokenPrefix) && len(value) > 12 {
		return value[:12] + "…"
	}

	return value
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}

	return false
}

// resolveTokenAgent maps token create --agent (name, full fingerprint or
// id) to an active agent's id.
func resolveTokenAgent(ctx context.Context, client *pv.Client, target string) (string, error) {
	agents, err := fetchServerAgents(ctx, client, false)
	if err != nil {
		return "", err
	}

	for _, agent := range agents {
		if agent.Name == target || agent.ID == target || (agent.fingerprint != "" && agent.fingerprint == target) {
			return agent.ID, nil
		}
	}

	return "", pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no active agent %s in this account (pastevault agent list)", target)
}
