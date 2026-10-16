package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"golang.org/x/term"
)

// app carries the process environment so commands can be driven from tests.
type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	stdinIsTerminal  func() bool
	stdoutIsTerminal func() bool
	promptPassword   func(prompt string) (string, error)

	// jsonMode is resolved once per run from --json and PASTEVAULT_JSON.
	jsonMode bool
	// helpText collects usage text in JSON mode, where it is printed as
	// {"usage": ...} instead of on stderr.
	helpText bytes.Buffer
}

// helpOutput is where usage and flag-parsing text goes: stderr, or in JSON
// mode a buffer (stdout must hold exactly one JSON object).
func (a *app) helpOutput() io.Writer {
	if a.jsonMode {
		return &a.helpText
	}

	return a.stderr
}

func newApp() *app {
	return &app{
		stdin:            os.Stdin,
		stdout:           os.Stdout,
		stderr:           os.Stderr,
		stdinIsTerminal:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		stdoutIsTerminal: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		promptPassword:   pv.PromptForPassword,
	}
}

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, a *app, args []string) error
}

// commands is the dispatch table. Later features (agents, requests, secrets,
// run, inject, mcp) add their entries here.
var commands = []command{
	{"put", "Share text, a .env file or files", runPut},
	{"get", "Open a share", runGet},
	{"list", "List shares you own", runList},
	{"status", "Show a share's views and activity; --wait for a read receipt", runStatus},
	{"revoke", "Delete shares you own", runRevoke},
	{"audit", "Show the account audit log", runAudit},
	{"token", "Create, list and revoke API tokens", runToken},
	{"agent", "Create and manage agent keys for sealed shares", runAgent},
	{"login", "Link this CLI to an account (browser approval or --with-token)", runLogin},
	{"whoami", "Show the account and credential in use", runWhoAmI},
	{"logout", "Forget (and revoke) stored credentials", runLogout},
	{"update", "Update the CLI", runUpdate},
	{"config", "Show or change CLI settings", runConfig},
}

func findCommand(name string) *command {
	for index := range commands {
		if commands[index].name == name {
			return &commands[index]
		}
	}

	return nil
}

// run executes one CLI invocation and returns the process exit code.
func (a *app) run(ctx context.Context, args []string) int {
	a.jsonMode = envJSONEnabled()
	if value, explicit := argsJSONSetting(args); explicit {
		a.jsonMode = value
	}

	if len(args) == 0 {
		a.usage()
		return a.reportError(pv.UsageError("no command given; run pastevault help"))
	}

	var err error
	switch name := args[0]; name {
	case "version", "--version", "-v":
		a.printVersion()
	case "help", "--help", "-h":
		if len(args) > 1 && findCommand(args[1]) != nil {
			err = findCommand(args[1]).run(ctx, a, []string{"--help"})
		} else {
			a.usage()
			err = errHelpShown
		}
	default:
		cmd := findCommand(name)
		if cmd == nil {
			a.usage()
			err = pv.UsageError("unknown command %q", name)
		} else {
			err = cmd.run(ctx, a, args[1:])
		}
	}

	if errors.Is(err, errHelpShown) {
		if a.jsonMode {
			_ = writeJSON(a.stdout, map[string]string{"usage": a.helpText.String()})
		}
		return pv.ExitOK
	}
	if err == nil {
		return pv.ExitOK
	}
	if ctx.Err() != nil && !errors.As(err, new(*pv.CLIError)) {
		err = ctx.Err()
	}

	return a.reportError(err)
}

// reportError prints err (one line on stderr; with --json also the error
// object on stdout) and returns its exit code.
func (a *app) reportError(err error) int {
	cliErr := pv.Classify(err)
	message := strings.TrimSpace(cliErr.Error())
	if a.jsonMode {
		payload := map[string]any{
			"error": map[string]any{
				"code":      cliErr.Code,
				"message":   message,
				"exit_code": cliErr.Exit,
			},
		}
		_ = writeJSON(a.stdout, payload)
	}
	fmt.Fprintf(a.stderr, "Error: %s\n", message)

	return cliErr.Exit
}

func envJSONEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PASTEVAULT_JSON"))) {
	case "1", "true", "yes", "on":
		return true
	}

	return false
}

// argsJSONSetting spots --json / --json=BOOL before flags are parsed, so
// even flag errors are reported as JSON, and --json=false overrides
// PASTEVAULT_JSON. The last occurrence wins, as in flag parsing.
func argsJSONSetting(args []string) (value bool, explicit bool) {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
		if name == arg {
			continue
		}
		if name == "json" {
			value, explicit = true, true
		} else if raw, found := strings.CutPrefix(name, "json="); found {
			if parsed, err := strconv.ParseBool(raw); err == nil {
				value, explicit = parsed, true
			}
		}
	}

	return value, explicit
}

// errHelpShown ends a command after -h/--help printed its usage.
var errHelpShown = errors.New("help shown")

// commonFlags are accepted by every command that talks to a server.
type commonFlags struct {
	server string
	json   bool
	quiet  bool
}

// newFlagSet creates a command's flag set with --server, --json and -q.
func (a *app) newFlagSet(name, usageLine string) (*flag.FlagSet, *commonFlags) {
	fs := a.newBareFlagSet(name, usageLine)
	common := &commonFlags{}
	fs.StringVar(&common.server, "server", pv.DefaultServerURL(), "PasteVault server base URL (or PASTEVAULT_SERVER)")
	fs.BoolVar(&common.json, "json", false, "Print one JSON object on stdout (or PASTEVAULT_JSON=1)")
	fs.BoolVar(&common.quiet, "quiet", false, "Print only the essential result")
	fs.BoolVar(&common.quiet, "q", false, "Shorthand for --quiet")
	return fs, common
}

func (a *app) newBareFlagSet(name, usageLine string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.helpOutput())
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  %s\n\nFlags:\n", usageLine)
		fs.PrintDefaults()
	}
	return fs
}

// parseArgs parses flags anywhere on the command line ("put file --json"
// works), stopping at "--". It returns the positional arguments.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	remaining := args

	for {
		if err := fs.Parse(remaining); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, errHelpShown
			}
			if name, found := strings.CutPrefix(err.Error(), "flag provided but not defined: -"); found && len(name) >= 6 && pv.IsValidSlug(strings.SplitN(name, "#", 2)[0]) {
				return nil, pv.UsageError(`%v (a share slug that starts with "-" must come after --, e.g. pastevault get -- <slug>)`, err)
			}
			return nil, pv.UsageError("%v", err)
		}

		rest := fs.Args()
		consumed := len(remaining) - len(rest)
		if consumed > 0 && remaining[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}

		positional = append(positional, rest[0])
		remaining = rest[1:]
	}
}

// flagWasSet reports whether name was given on the command line.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})

	return set
}

// output wraps a command's stdout/stderr conventions: results on stdout,
// progress and notices on stderr, exactly one JSON object with --json.
type output struct {
	a      *app
	common *commonFlags
}

func (a *app) output(common *commonFlags) *output {
	if common.json {
		a.jsonMode = true
	}
	common.json = a.jsonMode
	return &output{a: a, common: common}
}

func (o *output) json() bool {
	return o.common.json
}

// infof prints progress to stderr unless --quiet.
func (o *output) infof(format string, args ...any) {
	if o.common.quiet {
		return
	}
	fmt.Fprintf(o.a.stderr, format+"\n", args...)
}

// warnf prints a warning to stderr, even with --quiet.
func (o *output) warnf(format string, args ...any) {
	fmt.Fprintf(o.a.stderr, "Warning: "+format+"\n", args...)
}

// printf writes human output to stdout.
func (o *output) printf(format string, args ...any) {
	fmt.Fprintf(o.a.stdout, format, args...)
}

func (o *output) emitJSON(value any) error {
	return writeJSON(o.a.stdout, value)
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

// readLine reads the first line of r (at most limit bytes). It returns at
// the newline, so a terminal user only has to press Enter.
func readLine(r io.Reader, limit int64) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, limit+1)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if int64(len(line)) > limit {
		return "", pv.UsageError("input is longer than %d bytes", limit)
	}

	return strings.TrimRight(line, "\r\n"), nil
}

func (a *app) usage() {
	w := a.helpOutput()
	fmt.Fprintln(w, "PasteVault CLI: end-to-end encrypted sharing")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  pastevault <command> [flags] [arguments]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, cmd := range commands {
		fmt.Fprintf(w, "  %-8s %s\n", cmd.name, cmd.summary)
	}
	fmt.Fprintf(w, "  %-8s %s\n", "version", "Show version information")
	fmt.Fprint(w, `
Common flags:
  --server URL   PasteVault server (default $PASTEVAULT_SERVER or https://api.pastevault.dev)
  --json         One JSON object on stdout; errors as {"error":{...}} (or PASTEVAULT_JSON=1)
  -q, --quiet    Print only the essential result

Environment:
  PASTEVAULT_SERVER          Default server base URL
  PASTEVAULT_PUBLIC_URL      Base URL for share links (web origin)
  PASTEVAULT_TOKEN           API token (used only for the configured server)
  PASTEVAULT_PASSWORD        Share password (instead of a prompt)
  PASTEVAULT_CONFIG_DIR      Directory for stored credentials, agent keys and pins
  PASTEVAULT_AGENT           Default agent name
  PASTEVAULT_AGENT_KEY       Agent private key (base64url) instead of a key file
  PASTEVAULT_JSON            Set to 1 for JSON output
  PASTEVAULT_NO_UPDATE_CHECK Disable passive update checks

Examples:
  echo "hello" | pastevault put -
  pastevault put .env --expires 1h --burn
  pastevault put ./report.pdf ./data.csv --max-views 3
  pastevault get https://pastevault.dev/p/abc123#k=... --stdout
  pastevault get abc123 --key-file key.txt -o out.txt
  pastevault status abc123 --wait viewed --timeout 10m
  pastevault token create --name ci
  pastevault agent init --name laptop
  pastevault put .env --to build-bot

Run 'pastevault <command> --help' for a command's flags.
Exit codes and JSON shapes: docs/cli-reference.md
`)
}

func (a *app) printVersion() {
	if a.jsonMode {
		_ = writeJSON(a.stdout, map[string]string{"version": version, "commit": commit, "built": date})
		return
	}
	fmt.Fprintf(a.stdout, "pastevault %s\n", version)
	fmt.Fprintf(a.stdout, "commit %s\n", commit)
	fmt.Fprintf(a.stdout, "built %s\n", date)
}

// newClient creates an API client for server.
func newClient(server string) (*pv.Client, error) {
	client, err := pv.NewClient(server, version)
	if err != nil {
		return nil, pv.UsageError("invalid server URL %q: %v", server, err)
	}

	return client, nil
}

// authenticatedClient returns a client carrying the best available
// credential (see pv.AttachCredentials). A stored session is validated so an
// expired login is reported instead of silently acting anonymously. With
// required, having no credential at all is an auth error (exit 3).
func authenticatedClient(ctx context.Context, common *commonFlags, required bool) (*pv.Client, pv.CredentialSource, error) {
	client, err := newClient(common.server)
	if err != nil {
		return nil, pv.CredentialNone, err
	}

	source, err := pv.AttachCredentials(client, common.server)
	if err != nil {
		return nil, pv.CredentialNone, err
	}

	if source == pv.CredentialSession {
		if err := validateSession(ctx, client); err != nil {
			return nil, pv.CredentialNone, err
		}
	}

	if required && source == pv.CredentialNone {
		return nil, pv.CredentialNone, pv.NewError(pv.ExitAuth, pv.CodeNotLoggedIn, "not logged in to %s; run pastevault login, pastevault login --with-token, or set PASTEVAULT_TOKEN", client.BaseURL())
	}

	return client, source, nil
}

func validateSession(ctx context.Context, client *pv.Client) error {
	session, err := client.GetAuthSession(ctx)
	if err != nil {
		return err
	}
	if session == nil {
		_, _ = pv.DeleteStoredAuthToken(client.BaseURL())
		return pv.NewError(pv.ExitAuth, pv.CodeAuth, "stored login has expired; run pastevault login again or pastevault logout to continue anonymously")
	}

	return nil
}

// Server features account commands depend on (see requireFeature).
const (
	featureAccounts = "accounts"
	featureAudit    = "audit"
	featureTokens   = "api_tokens"
)

// requireFeature checks /capabilities before an account command does
// anything else, so a server without the feature (an old version, or
// DISABLE_AUTH=true) gives exit 14 instead of a confusing 401 or 404.
func requireFeature(ctx context.Context, client *pv.Client, feature string) (pv.CapabilitiesResponse, error) {
	capabilities, err := fetchCapabilities(ctx, client)
	if err != nil {
		return capabilities, err
	}

	if !capabilities.Auth.Enabled {
		return capabilities, pv.UnsupportedError("%s has accounts disabled (or is too old), so this command is not available", client.BaseURL())
	}
	switch {
	case feature == featureAudit && !capabilities.Features.Audit:
		return capabilities, pv.UnsupportedError("%s does not support the audit log; update the server", client.BaseURL())
	case feature == featureTokens && !capabilities.Features.APITokens:
		return capabilities, pv.UnsupportedError("%s does not support API tokens; update the server", client.BaseURL())
	}

	return capabilities, nil
}

// accountClient is authenticatedClient (credentials required) for commands
// that need an account feature on the server.
func accountClient(ctx context.Context, common *commonFlags, feature string) (*pv.Client, pv.CredentialSource, pv.CapabilitiesResponse, error) {
	probe, err := newClient(common.server)
	if err != nil {
		return nil, pv.CredentialNone, pv.CapabilitiesResponse{}, err
	}
	capabilities, err := requireFeature(ctx, probe, feature)
	if err != nil {
		return nil, pv.CredentialNone, capabilities, err
	}

	client, source, err := authenticatedClient(ctx, common, true)
	return client, source, capabilities, err
}

// sessionClient returns a client authenticated with the stored login
// session only. Token management is session-only on the server, so API
// tokens (PASTEVAULT_TOKEN or a stored token) are deliberately not used.
func sessionClient(ctx context.Context, common *commonFlags) (*pv.Client, error) {
	client, err := newClient(common.server)
	if err != nil {
		return nil, err
	}
	if _, err := requireFeature(ctx, client, featureTokens); err != nil {
		return nil, err
	}

	hasSession, err := pv.AttachStoredAuthToken(client)
	if err != nil {
		return nil, err
	}
	if !hasSession {
		return nil, pv.NewError(pv.ExitAuth, pv.CodeSessionRequired, "managing API tokens needs a browser-approved login session for %s; run pastevault login (API tokens cannot manage tokens)", client.BaseURL())
	}
	if err := validateSession(ctx, client); err != nil {
		return nil, err
	}

	return client, nil
}
