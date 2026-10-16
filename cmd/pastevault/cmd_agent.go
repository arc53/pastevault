package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

// Agent identities: X25519 key pairs whose private key stays on this machine
// (ConfigDir/agents/<server>/<name>.json, 0600) and whose public key is
// registered with the account, so shares can be sealed to them (put --to).
func runAgent(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return pv.UsageError("usage: pastevault agent <init|list|show|revoke|trust|pubkey|default> [flags]")
	}

	switch args[0] {
	case "init":
		return runAgentInit(ctx, a, args[1:])
	case "list", "ls":
		return runAgentList(ctx, a, args[1:])
	case "show":
		return runAgentShow(ctx, a, args[1:])
	case "revoke", "rm":
		return runAgentRevoke(ctx, a, args[1:])
	case "trust":
		return runAgentTrust(ctx, a, args[1:])
	case "pubkey":
		return runAgentPubkey(ctx, a, args[1:])
	case "default":
		return runAgentDefault(ctx, a, args[1:])
	case "--help", "-h", "help":
		fmt.Fprintln(a.stderr, `Usage:
  pastevault agent init [--name N] [--force] [--default]   Create this machine's agent key and register it
  pastevault agent list [--all]                            Agents of the account (* = key on this machine)
  pastevault agent show [NAME]                             Fingerprint and key file of an agent
  pastevault agent revoke NAME                             Revoke an agent and the API tokens bound to it
  pastevault agent trust NAME FINGERPRINT                  Accept an agent's new key after verifying it
  pastevault agent pubkey [NAME]                           Print a public key (for put --to-key)
  pastevault agent default [NAME]                          Show or set the default agent`)
		return errHelpShown
	default:
		return pv.UsageError("unknown agent command %q (expected init, list, show, revoke, trust, pubkey or default)", args[0])
	}
}

// agentJSON is how agent commands describe an agent with --json.
type agentJSON struct {
	ID          string  `json:"id,omitempty"`
	Name        string  `json:"name"`
	Fingerprint string  `json:"fingerprint"`
	PublicKey   string  `json:"public_key"`
	CreatedAt   string  `json:"created_at,omitempty"`
	LastUsedAt  *string `json:"last_used_at,omitempty"`
	RevokedAt   *string `json:"revoked_at,omitempty"`
	LocalKey    bool    `json:"local_key"`
	KeyFile     string  `json:"key_file,omitempty"`
	Default     bool    `json:"default"`
	// Pin is self, tofu, manual, none or mismatch (see known_agents.json).
	Pin string `json:"pin"`
	// FingerprintMismatch: the fingerprint the server claims is not the one
	// its public key has. Never trust such an agent.
	FingerprintMismatch bool `json:"fingerprint_mismatch,omitempty"`
}

// serverAgent is an agent as listed by the server, with its key decoded and
// its fingerprint recomputed here: the server's fingerprint field is never
// trusted.
type serverAgent struct {
	pv.AgentSummary
	publicKey   []byte
	fingerprint string
	keyErr      error
}

func (agent serverAgent) active() bool {
	return agent.RevokedAt == nil
}

func fetchServerAgents(ctx context.Context, client *pv.Client, includeRevoked bool) ([]serverAgent, error) {
	response, err := client.ListAgents(ctx, includeRevoked)
	if err != nil {
		return nil, agentAPIError(err)
	}

	agents := make([]serverAgent, 0, len(response.Agents))
	for _, summary := range response.Agents {
		agent := serverAgent{AgentSummary: summary}
		agent.publicKey, agent.keyErr = pv.DecodeAgentPublicKey(summary.PublicKey)
		if agent.keyErr == nil {
			agent.fingerprint = pv.Fingerprint(agent.publicKey)
		}
		agents = append(agents, agent)
	}

	return agents, nil
}

// agentAPIError explains a 404 from a server without the agents API.
func agentAPIError(err error) error {
	if pv.IsStatus(err, 404) && !strings.Contains(err.Error(), "Agent not found") {
		return pv.UnsupportedError("this server does not support agents; update the server")
	}

	return err
}

func requireAgentsFeature(ctx context.Context, client *pv.Client) error {
	capabilities, err := fetchCapabilities(ctx, client)
	if err != nil {
		return err
	}
	if !capabilities.Features.Agents {
		return pv.UnsupportedError("this server does not support agents (it is too old, or accounts are disabled)")
	}

	return nil
}

func findActiveAgentByName(agents []serverAgent, name string) *serverAgent {
	for index := range agents {
		if agents[index].active() && agents[index].Name == name {
			return &agents[index]
		}
	}

	return nil
}

// defaultAgentNameFromHost derives an agent name from the host name.
func defaultAgentNameFromHost() string {
	host, _ := os.Hostname()
	host = strings.ToLower(strings.SplitN(host, ".", 2)[0])

	var builder strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	name := strings.Trim(builder.String(), "-_")
	if len(name) > 63 {
		name = name[:63]
	}
	if !pv.ValidAgentName(name) {
		return "agent"
	}

	return name
}

func runAgentInit(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("agent init", "pastevault agent init [--name N] [--force] [--default] [flags]")
	name := fs.String("name", "", "Agent name (default: this machine's host name)")
	force := fs.Bool("force", false, "Replace this machine's existing key for the name (revokes the old agent)")
	makeDefault := fs.Bool("default", false, "Make it the default agent even if another one is")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("agent init does not take positional arguments (use --name)")
	}
	if *name == "" {
		*name = defaultAgentNameFromHost()
	}
	if !pv.ValidAgentName(*name) {
		return pv.UsageError("invalid agent name %q: use 1-63 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit", *name)
	}

	client, _, err := authenticatedClient(ctx, common, true)
	if err != nil {
		return err
	}
	server := client.BaseURL()

	existing, err := pv.LoadAgentIdentity(server, *name)
	if err != nil {
		return err
	}
	if existing != nil && !*force {
		return pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "this machine already has a key for agent %s (%s, %s); pass --force to replace it (the old agent is revoked)", *name, pv.ShortFingerprint(existing.Fingerprint), existing.Path)
	}
	if err := requireAgentsFeature(ctx, client); err != nil {
		return err
	}

	keys, err := pv.GenerateAgentKeyPair()
	if err != nil {
		return err
	}
	identity := pv.NewAgentIdentity(server, *name, keys)
	finalPath, err := pv.AgentKeyPath(server, *name)
	if err != nil {
		return err
	}

	// The new key is on disk before it is registered, so a registered agent
	// never lacks its private key.
	pendingPath := finalPath + ".pending"
	if err := pv.SaveAgentIdentity(identity, pendingPath, true); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(pendingPath)
		}
	}()

	if *force {
		if err := revokeAgentsNamed(ctx, client, out, *name, existing); err != nil {
			return err
		}
	}

	created, err := client.CreateAgent(ctx, pv.CreateAgentRequest{
		Name:        *name,
		PublicKey:   identity.PublicKey,
		Fingerprint: identity.Fingerprint,
	})
	if err != nil {
		if pv.IsStatus(err, 409) {
			return pv.WrapError(pv.ExitConflict, pv.CodeConflict, err, "could not register agent %s (if the name belongs to an agent on another machine, pick another --name, or use --force to replace it)", *name)
		}
		return agentAPIError(err)
	}
	if created.Agent.PublicKey != identity.PublicKey {
		return pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "the server registered a different public key than the one sent; refusing to use it")
	}

	identity.AgentID = created.Agent.ID
	if existing != nil {
		if _, err := pv.RetireAgentIdentity(existing); err != nil {
			return err
		}
	}
	if err := pv.SaveAgentIdentity(identity, finalPath, true); err != nil {
		return err
	}
	committed = true
	_ = os.Remove(pendingPath)

	if _, err := pv.PinAgent(server, *name, keys.PublicKey, pv.PinSourceSelf); err != nil {
		return err
	}
	isDefault := *makeDefault
	if current, _, err := pv.DefaultAgentName(server); err == nil && (current == "" || current == *name) {
		isDefault = true
	}
	if isDefault {
		if err := pv.SetDefaultAgent(server, *name); err != nil {
			return err
		}
	}

	if out.json() {
		return out.emitJSON(map[string]any{
			"agent": agentJSON{
				ID:          created.Agent.ID,
				Name:        *name,
				Fingerprint: identity.Fingerprint,
				PublicKey:   identity.PublicKey,
				CreatedAt:   created.Agent.CreatedAt,
				LocalKey:    true,
				KeyFile:     finalPath,
				Default:     isDefault,
				Pin:         pv.PinSourceSelf,
			},
			"server":      server,
			"token_bound": created.TokenBound,
		})
	}

	out.printf("%s\n", identity.Fingerprint)
	out.infof("Registered agent %s on %s", *name, server)
	out.infof("Fingerprint: %s", pv.FormatFingerprint(identity.Fingerprint))
	out.infof("Private key: %s (keep it private; it never leaves this machine)", finalPath)
	if isDefault {
		out.infof("%s is the default agent for this server.", *name)
	}
	if created.TokenBound {
		out.infof("The API token used is now bound to agent %s.", *name)
	}
	out.infof("Others in your account can now share with it: pastevault put --to %s FILE", *name)
	return nil
}

// revokeAgentsNamed revokes the active server agent called name (and the old
// local agent id) before agent init --force registers a replacement.
func revokeAgentsNamed(ctx context.Context, client *pv.Client, out *output, name string, existing *pv.AgentIdentity) error {
	agents, err := fetchServerAgents(ctx, client, false)
	if err != nil {
		return err
	}

	ids := map[string]bool{}
	if existing != nil && existing.AgentID != "" {
		ids[existing.AgentID] = true
	}
	if agent := findActiveAgentByName(agents, name); agent != nil {
		ids[agent.ID] = true
	}

	for id := range ids {
		response, err := client.RevokeAgent(ctx, id)
		if pv.IsStatus(err, 404) {
			continue
		}
		if err != nil {
			return agentAPIError(err)
		}
		out.infof("Revoked the previous agent %s (%s)", response.Agent.Name, pv.ShortFingerprint(pv.Fingerprint(mustDecodeKey(response.Agent.PublicKey))))
	}

	return nil
}

func mustDecodeKey(value string) []byte {
	key, _ := pv.DecodeBase64URL(value)
	return key
}

// pinState compares an agent's recomputed fingerprint with its pin.
func pinState(pins map[string]pv.KnownAgent, name, fingerprint string) string {
	pin, ok := pins[name]
	switch {
	case !ok:
		return "none"
	case pin.Fingerprint != fingerprint:
		return "mismatch"
	default:
		return pin.Source
	}
}

func runAgentList(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("agent list", "pastevault agent list [--all] [flags]")
	all := fs.Bool("all", false, "Include revoked agents")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("agent list does not take positional arguments")
	}

	client, _, err := authenticatedClient(ctx, common, true)
	if err != nil {
		return err
	}
	server := client.BaseURL()
	agents, err := fetchServerAgents(ctx, client, *all)
	if err != nil {
		return err
	}

	pins, err := pv.LoadPins(server)
	if err != nil {
		return err
	}
	locals, warnings, err := pv.LocalAgentIdentities(server)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		out.warnf("%s", warning)
	}
	localByFingerprint := map[string]*pv.AgentIdentity{}
	for _, identity := range locals {
		localByFingerprint[identity.Fingerprint] = identity
	}
	if envIdentity, err := pv.EnvAgentIdentity(); err == nil && envIdentity != nil {
		localByFingerprint[envIdentity.Fingerprint] = envIdentity
	}
	defaultName, _, _ := pv.DefaultAgentName(server)

	result := make([]agentJSON, 0, len(agents))
	for _, agent := range agents {
		entry := agentJSON{
			ID:          agent.ID,
			Name:        agent.Name,
			Fingerprint: agent.fingerprint,
			PublicKey:   agent.PublicKey,
			CreatedAt:   agent.CreatedAt,
			LastUsedAt:  agent.LastUsedAt,
			RevokedAt:   agent.RevokedAt,
			Default:     agent.active() && agent.Name == defaultName,
		}
		if agent.keyErr != nil {
			entry.FingerprintMismatch = true
			entry.Pin = "mismatch"
			out.warnf("the server lists an unusable public key for agent %s; do not share with it", agent.Name)
		} else {
			entry.FingerprintMismatch = agent.Fingerprint != agent.fingerprint
			entry.Pin = pinState(pins, agent.Name, agent.fingerprint)
			if local := localByFingerprint[agent.fingerprint]; local != nil {
				entry.LocalKey = true
				entry.KeyFile = local.Path
			}
		}
		if entry.FingerprintMismatch && agent.keyErr == nil {
			out.warnf("the server's fingerprint for agent %s does not match its public key; showing the computed one", agent.Name)
		}
		if entry.Pin == "mismatch" && agent.keyErr == nil && agent.active() {
			out.warnf("agent %s's key differs from the one pinned on this machine; see pastevault agent trust", agent.Name)
		}
		result = append(result, entry)
	}

	if out.json() {
		return out.emitJSON(map[string]any{"agents": result})
	}
	if len(result) == 0 {
		out.infof("No agents yet. Create one on the agent's machine: pastevault agent init --name NAME")
		return nil
	}

	table := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	if !common.quiet {
		fmt.Fprintln(table, "NAME\tFINGERPRINT\tLOCAL\tPIN\tSTATUS\tLAST USED")
	}
	for _, entry := range result {
		name := entry.Name
		if entry.Default {
			name += " (default)"
		}
		local := "-"
		if entry.LocalKey {
			local = "*"
		}
		status := "active"
		if entry.RevokedAt != nil {
			status = "revoked"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", name, pv.ShortFingerprint(entry.Fingerprint), local, entry.Pin, status, formatOptionalTime(entry.LastUsedAt, "-"))
	}
	return table.Flush()
}

// resolveLocalAgent picks the local key for NAME, or the default agent
// (PASTEVAULT_AGENT_KEY, PASTEVAULT_AGENT, the saved default, or the only
// key on this machine).
func resolveLocalAgent(server, name string) (*pv.AgentIdentity, error) {
	if name == "" {
		envIdentity, err := pv.EnvAgentIdentity()
		if err != nil || envIdentity != nil {
			return envIdentity, err
		}

		name, _, err = pv.DefaultAgentName(server)
		if err != nil {
			return nil, err
		}
		if name == "" {
			locals, _, err := pv.LocalAgentIdentities(server)
			if err != nil {
				return nil, err
			}
			var active []*pv.AgentIdentity
			for _, identity := range locals {
				if !identity.Revoked() {
					active = append(active, identity)
				}
			}
			if len(active) == 1 {
				return active[0], nil
			}
			return nil, pv.UsageError("no default agent for %s: name one, set PASTEVAULT_AGENT, or run pastevault agent init", server)
		}
	}

	identity, err := pv.LoadAgentIdentity(server, name)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "this machine has no key for agent %s on %s (pastevault agent list shows the account's agents)", name, server)
	}

	return identity, nil
}

func runAgentShow(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("agent show", "pastevault agent show [NAME] [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) > 1 {
		return pv.UsageError("agent show takes at most one agent name")
	}
	name := ""
	if len(positional) == 1 {
		name = positional[0]
	}

	client, err := newClient(common.server)
	if err != nil {
		return err
	}
	server := client.BaseURL()

	entry := agentJSON{Name: name, Pin: "none"}
	local, localErr := resolveLocalAgent(server, name)
	if local != nil {
		entry.Name = local.Name
		entry.ID = local.AgentID
		entry.Fingerprint = local.Fingerprint
		entry.PublicKey = local.PublicKey
		entry.CreatedAt = local.CreatedAt
		entry.LocalKey = true
		entry.KeyFile = local.Path
	} else {
		// Without a local key, a named agent can still be shown from the
		// server's listing.
		var cliErr *pv.CLIError
		if name == "" || !errors.As(localErr, &cliErr) || cliErr.Exit != pv.ExitNotFound {
			return localErr
		}
	}

	// Server status is best effort: show works offline for local keys.
	status := "unknown"
	if _, err := pv.AttachCredentials(client, common.server); err == nil && client.HasAuthToken() {
		if agents, err := fetchServerAgents(ctx, client, true); err == nil {
			status = "missing"
			for _, agent := range agents {
				matches := (entry.LocalKey && agent.fingerprint == entry.Fingerprint) ||
					(!entry.LocalKey && agent.Name == entry.Name && agent.active())
				if !matches {
					continue
				}
				status = "active"
				if !agent.active() {
					status = "revoked"
				}
				if entry.Name == "" {
					entry.Name = agent.Name
				}
				entry.ID = agent.ID
				entry.LastUsedAt = agent.LastUsedAt
				entry.RevokedAt = agent.RevokedAt
				if !entry.LocalKey {
					entry.Fingerprint = agent.fingerprint
					entry.PublicKey = agent.PublicKey
					entry.CreatedAt = agent.CreatedAt
				}
				break
			}
		}
	}
	if !entry.LocalKey && entry.Fingerprint == "" {
		if localErr != nil {
			return localErr
		}
		return pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no agent %s", name)
	}

	if entry.Name != "" {
		pins, err := pv.LoadPins(server)
		if err != nil {
			return err
		}
		entry.Pin = pinState(pins, entry.Name, entry.Fingerprint)
		defaultName, _, _ := pv.DefaultAgentName(server)
		entry.Default = entry.Name == defaultName
	}

	if out.json() {
		return out.emitJSON(map[string]any{"agent": entry, "server_status": status, "server": server})
	}

	label := entry.Name
	if label == "" {
		label = "(" + pv.EnvAgentKey + ")"
	}
	out.printf("%s\n", entry.Fingerprint)
	out.infof("Agent:       %s", label)
	out.infof("Fingerprint: %s", pv.FormatFingerprint(entry.Fingerprint))
	out.infof("Short:       %s", pv.ShortFingerprint(entry.Fingerprint))
	if entry.KeyFile != "" {
		out.infof("Key file:    %s", entry.KeyFile)
	} else if entry.LocalKey {
		out.infof("Key:         from %s", pv.EnvAgentKey)
	} else {
		out.infof("Key:         not on this machine")
	}
	out.infof("Server:      %s (%s)", server, status)
	out.infof("Pin:         %s", entry.Pin)
	return nil
}

func runAgentRevoke(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("agent revoke", "pastevault agent revoke NAME [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("name exactly one agent (by name, full fingerprint or id)")
	}
	target := positional[0]

	client, _, err := authenticatedClient(ctx, common, true)
	if err != nil {
		return err
	}
	server := client.BaseURL()
	agents, err := fetchServerAgents(ctx, client, false)
	if err != nil {
		return err
	}

	var match *serverAgent
	for index := range agents {
		agent := &agents[index]
		if agent.Name == target || agent.ID == target || (agent.fingerprint != "" && agent.fingerprint == target) {
			match = agent
			break
		}
	}
	if match == nil {
		return pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no active agent %s in this account", target)
	}

	response, err := client.RevokeAgent(ctx, match.ID)
	if err != nil {
		return agentAPIError(err)
	}

	// The local key is kept (renamed) so shares already sealed to it can
	// still be opened; the name is free for a new agent.
	retired := ""
	if local, err := pv.LoadAgentIdentity(server, match.Name); err == nil && local != nil && (local.AgentID == match.ID || local.Fingerprint == match.fingerprint) {
		retired, err = pv.RetireAgentIdentity(local)
		if err != nil {
			return err
		}
		if current, source, err := pv.DefaultAgentName(server); err == nil && current == match.Name && source == pv.DefaultAgentSettings {
			_ = pv.SetDefaultAgent(server, "")
		}
	}

	if out.json() {
		return out.emitJSON(map[string]any{
			"agent":          agentJSON{ID: response.Agent.ID, Name: response.Agent.Name, Fingerprint: match.fingerprint, PublicKey: response.Agent.PublicKey, CreatedAt: response.Agent.CreatedAt, RevokedAt: response.Agent.RevokedAt, LocalKey: retired != "", KeyFile: retired, Pin: "none"},
			"tokens_revoked": response.TokensRevoked,
		})
	}

	out.printf("Revoked agent %s (%s)\n", response.Agent.Name, pv.ShortFingerprint(match.fingerprint))
	if response.TokensRevoked > 0 {
		out.infof("Also revoked %d API token(s) bound to it.", response.TokensRevoked)
	}
	if retired != "" {
		out.infof("Its private key was kept as %s for shares already sealed to it.", filepath.Base(retired))
	}
	return nil
}

func runAgentTrust(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("agent trust", "pastevault agent trust NAME FINGERPRINT [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 2 {
		return pv.UsageError("usage: pastevault agent trust NAME FINGERPRINT (the full pvk1_ fingerprint, verified out of band)")
	}
	name, fingerprint := positional[0], strings.ReplaceAll(positional[1], " ", "")
	if !pv.IsFingerprint(fingerprint) {
		return pv.UsageError("%q is not a full fingerprint (pvk1_ followed by 32 characters)", positional[1])
	}

	client, _, err := authenticatedClient(ctx, common, true)
	if err != nil {
		return err
	}
	server := client.BaseURL()
	agents, err := fetchServerAgents(ctx, client, false)
	if err != nil {
		return err
	}

	agent := findActiveAgentByName(agents, name)
	if agent == nil {
		return pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no active agent %s in this account", name)
	}
	if agent.keyErr != nil {
		return pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "the server lists an unusable public key for agent %s", name)
	}
	if agent.fingerprint != fingerprint {
		return pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "the server's key for agent %s has fingerprint %s, not %s; nothing was pinned", name, agent.fingerprint, fingerprint)
	}
	if local, err := pv.LoadAgentIdentity(server, name); err == nil && local != nil && local.Fingerprint != fingerprint {
		return pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "this machine holds a different key for agent %s (%s); run pastevault agent init --name %s --force to replace it instead", name, local.Fingerprint, name)
	}

	pin, err := pv.PinAgent(server, name, agent.publicKey, pv.PinSourceManual)
	if err != nil {
		return err
	}

	if out.json() {
		return out.emitJSON(map[string]any{"name": name, "fingerprint": pin.Fingerprint, "public_key": pin.PublicKey, "source": pin.Source})
	}
	out.printf("Pinned %s %s\n", name, pv.FormatFingerprint(pin.Fingerprint))
	return nil
}

func runAgentPubkey(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("agent pubkey", "pastevault agent pubkey [NAME] [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) > 1 {
		return pv.UsageError("agent pubkey takes at most one agent name")
	}
	name := ""
	if len(positional) == 1 {
		name = positional[0]
	}

	client, err := newClient(common.server)
	if err != nil {
		return err
	}
	identity, err := resolveLocalAgent(client.BaseURL(), name)
	if err != nil {
		return err
	}

	if out.json() {
		return out.emitJSON(map[string]any{"name": identity.Name, "public_key": identity.PublicKey, "fingerprint": identity.Fingerprint})
	}
	out.printf("%s\n", identity.PublicKey)
	out.infof("Fingerprint: %s", pv.FormatFingerprint(identity.Fingerprint))
	out.infof("Senders use: pastevault put --to-key %s FILE", identity.PublicKey)
	return nil
}

func runAgentDefault(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("agent default", "pastevault agent default [NAME] [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) > 1 {
		return pv.UsageError("agent default takes at most one agent name")
	}

	client, err := newClient(common.server)
	if err != nil {
		return err
	}
	server := client.BaseURL()

	if len(positional) == 1 {
		identity, err := pv.LoadAgentIdentity(server, positional[0])
		if err != nil {
			return err
		}
		if identity == nil {
			return pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "this machine has no key for agent %s on %s", positional[0], server)
		}
		if err := pv.SetDefaultAgent(server, positional[0]); err != nil {
			return err
		}
	}

	name, source, err := pv.DefaultAgentName(server)
	if err != nil {
		return err
	}
	if out.json() {
		return out.emitJSON(map[string]any{"default_agent": name, "source": string(source)})
	}
	if name == "" {
		out.infof("No default agent for %s.", server)
		return nil
	}
	out.printf("%s\n", name)
	if source == pv.DefaultAgentEnv {
		out.infof("(from %s)", pv.EnvAgent)
	}
	return nil
}

// shareRecipient is who a sealed share is for: an agent of the account
// (agentID set; the server then requires that account to open it) or a raw
// public key from --to-key.
type shareRecipient struct {
	name        string
	agentID     string
	publicKey   []byte
	fingerprint string
}

// request seals key for one share.
func (recipient *shareRecipient) request(key []byte, context string) (*pv.ShareRecipientRequest, error) {
	wrapped, err := pv.WrapKey(key, recipient.publicKey, context)
	if err != nil {
		return nil, err
	}

	return &pv.ShareRecipientRequest{AgentID: recipient.agentID, Fingerprint: recipient.fingerprint, WrappedKey: wrapped}, nil
}

func (recipient *shareRecipient) output() *putRecipient {
	if recipient == nil {
		return nil
	}

	return &putRecipient{Name: recipient.name, Fingerprint: recipient.fingerprint}
}

// recipientFromKey is put --to-key: a raw X25519 public key.
func recipientFromKey(value string) (*shareRecipient, error) {
	publicKey, err := pv.DecodeAgentPublicKey(strings.TrimSpace(value))
	if err != nil {
		return nil, pv.UsageError("--to-key: %v", err)
	}

	return &shareRecipient{publicKey: publicKey, fingerprint: pv.Fingerprint(publicKey)}, nil
}

// resolveRecipientAgent is put --to: an agent of the account, by name, full
// fingerprint, or a unique fingerprint prefix (pvk1_ plus at least 8
// characters). Keys come from the server's listing but fingerprints are
// recomputed here, and a key named by anything less than its full
// fingerprint must match this machine's pin (or is pinned on first use), so
// a server can't swap in its own key without exit 8.
func resolveRecipientAgent(ctx context.Context, client *pv.Client, out *output, to string) (*shareRecipient, error) {
	server := client.BaseURL()
	agents, err := fetchServerAgents(ctx, client, false)
	if err != nil {
		return nil, err
	}

	var match *serverAgent
	switch {
	case pv.IsFingerprint(to):
		for index := range agents {
			if agents[index].keyErr == nil && agents[index].fingerprint == to {
				match = &agents[index]
				break
			}
		}
		if match == nil {
			return nil, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no active agent with fingerprint %s in this account", to)
		}
		recipient := &shareRecipient{name: match.Name, agentID: match.ID, publicKey: match.publicKey, fingerprint: match.fingerprint}
		// The full fingerprint was given, so the key is verified; remember it.
		if pins, err := pv.LoadPins(server); err == nil {
			if _, pinned := pins[match.Name]; !pinned {
				_, _ = pv.PinAgent(server, match.Name, match.publicKey, pv.PinSourceManual)
			}
		}
		return recipient, nil

	case strings.HasPrefix(to, pv.FingerprintPrefix):
		if !pv.IsFingerprintPrefix(to) {
			return nil, pv.UsageError("--to %s: a fingerprint prefix needs at least %d characters after %s", to, pv.ShortFingerprintChars, pv.FingerprintPrefix)
		}
		var candidates []*serverAgent
		for index := range agents {
			if agents[index].keyErr == nil && strings.HasPrefix(agents[index].fingerprint, to) {
				candidates = append(candidates, &agents[index])
			}
		}
		switch len(candidates) {
		case 0:
			return nil, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no active agent with a fingerprint starting %s in this account", to)
		case 1:
			match = candidates[0]
		default:
			return nil, pv.UsageError("--to %s matches %d agents; give more of the fingerprint or the agent name", to, len(candidates))
		}

	default:
		if !pv.ValidAgentName(to) {
			return nil, pv.UsageError("--to %q is neither an agent name nor a pvk1_ fingerprint", to)
		}
		match = findActiveAgentByName(agents, to)
		if match == nil {
			return nil, pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no agent named %s in this account (pastevault agent list)", to)
		}
		if match.keyErr != nil {
			return nil, pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "the server lists an unusable public key for agent %s; nothing was shared", to)
		}
	}

	newlyPinned, err := pv.VerifyAgentKey(server, match.Name, match.publicKey)
	if err != nil {
		return nil, err
	}
	if newlyPinned {
		out.infof("Pinned %s %s (first use). Compare it with `pastevault agent show %s` on the agent's machine.", match.Name, pv.FormatFingerprint(match.fingerprint), match.Name)
	}

	return &shareRecipient{name: match.Name, agentID: match.ID, publicKey: match.publicKey, fingerprint: match.fingerprint}, nil
}
