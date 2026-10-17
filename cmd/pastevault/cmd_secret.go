package main

import (
	"context"
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/secrets"
	"github.com/arc53/pastevault/internal/store"
)

// The local store (spec §4, §5.3): entries sealed to the default agent,
// used through pv://secret/NAME handles. Nothing here talks to the server.
func runSecret(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(a.helpOutput(), secretUsage)
		return pv.UsageError("secret needs a subcommand: list, import, rm or reveal")
	}

	switch args[0] {
	case "list", "ls":
		return runSecretList(a, args[1:])
	case "rm", "remove", "delete":
		return runSecretRemove(a, args[1:])
	case "import":
		return runSecretImport(a, args[1:])
	case "reveal":
		return runSecretReveal(a, args[1:])
	case "help", "-h", "--help":
		fmt.Fprint(a.helpOutput(), secretUsage)
		return errHelpShown
	}

	fmt.Fprint(a.helpOutput(), secretUsage)
	return pv.UsageError("unknown secret subcommand %q", args[0])
}

const secretUsage = `Usage:
  pastevault secret list [--agent NAME]
  pastevault secret import NAME (--from-file F | --from-stdin) [--kind text|file] [--overwrite]
  pastevault secret rm NAME...
  pastevault secret reveal NAME     (terminal only)

Secrets are sealed to your default agent key and used as pv://secret/NAME
with pastevault run and inject. pastevault request and get --save add them.
`

func openSecretStore(server, agent string) (*store.Store, error) {
	identity, err := pv.ResolveLocalAgent(server, agent)
	if err != nil {
		return nil, err
	}

	return store.Open(server, identity)
}

type secretJSON struct {
	Name      string       `json:"name"`
	Handle    string       `json:"handle"`
	Kind      string       `json:"kind"`
	CreatedAt string       `json:"created_at"`
	Source    store.Source `json:"source"`
}

func toSecretJSON(entry *store.Entry) secretJSON {
	return secretJSON{Name: entry.Name, Handle: entry.Handle(), Kind: entry.Kind, CreatedAt: entry.CreatedAt, Source: entry.Source}
}

func runSecretList(a *app, args []string) error {
	fs, common := a.newFlagSet("secret list", "pastevault secret list [--agent NAME] [flags]")
	agent := fs.String("agent", "", "List another agent's store (default: the default agent)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("secret list takes no arguments")
	}

	target, entries, warnings, err := secrets.ListSecrets(common.server, *agent)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		out.warnf("%s", warning)
	}

	result := make([]secretJSON, 0, len(entries))
	for _, entry := range entries {
		result = append(result, toSecretJSON(entry))
	}
	if out.json() {
		return out.emitJSON(map[string]any{"agent": target.Agent, "secrets": result})
	}
	if len(result) == 0 {
		out.infof("No secrets in the local store of agent %s.", target.Agent)
		return nil
	}

	table := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "NAME\tKIND\tCREATED\tSOURCE\tHANDLE")
	for _, entry := range result {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", entry.Name, entry.Kind, formatTime(entry.CreatedAt), entry.Source.Type, entry.Handle)
	}

	return table.Flush()
}

func runSecretRemove(a *app, args []string) error {
	fs, common := a.newFlagSet("secret rm", "pastevault secret rm NAME... [--agent NAME] [flags]")
	agent := fs.String("agent", "", "Use another agent's store (default: the default agent)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) == 0 {
		return pv.UsageError("at least one secret NAME is required")
	}

	target, err := openSecretStore(common.server, *agent)
	if err != nil {
		return err
	}
	for _, name := range positional {
		if err := target.Remove(name); err != nil {
			return err
		}
		if !out.json() {
			out.infof("Removed %s", name)
		}
	}

	if out.json() {
		return out.emitJSON(map[string]any{"removed": positional})
	}

	return nil
}

func runSecretImport(a *app, args []string) error {
	fs, common := a.newFlagSet("secret import", "pastevault secret import NAME (--from-file F | --from-stdin) [--kind text|file] [--overwrite] [flags]")
	fromFile := fs.String("from-file", "", "Read the secret from this file")
	fromStdin := fs.Bool("from-stdin", false, "Read the secret from stdin")
	kind := fs.String("kind", "", "text or file (default: text when the content is UTF-8 text)")
	overwrite := fs.Bool("overwrite", false, "Replace an existing secret")
	agent := fs.String("agent", "", "Use another agent's store (default: the default agent)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("exactly one secret NAME is required")
	}
	name := positional[0]
	if !pv.ValidSecretName(name) {
		return pv.UsageError("invalid secret name %q (letters, digits, _ . -, starting with a letter or _, at most 128)", name)
	}
	if (*fromFile == "") == !*fromStdin {
		return pv.UsageError("give the secret with exactly one of --from-file F and --from-stdin")
	}
	if *kind != "" && *kind != pv.SecretKindText && *kind != pv.SecretKindFile {
		return pv.UsageError("--kind must be text or file")
	}

	target, err := openSecretStore(common.server, *agent)
	if err != nil {
		return err
	}
	if err := target.CheckWritable(name, *overwrite); err != nil {
		return err
	}

	var value []byte
	if *fromFile != "" {
		value, err = readValueFile(*fromFile, store.MaxValueBytes)
	} else {
		value, err = readValue(a.stdin, store.MaxValueBytes, "stdin")
	}
	if err != nil {
		return err
	}

	importKind := *kind
	if importKind == "" {
		importKind = pv.SecretKindFile
		if utf8.Valid(value) && !strings.ContainsRune(string(value), 0) {
			importKind = pv.SecretKindText
		}
	}

	var payload pv.SecretPayload
	if importKind == pv.SecretKindText {
		// Like password files: one trailing newline (from echo or an editor)
		// is not part of the secret.
		value = pv.TrimTrailingNewline(value)
		if len(value) == 0 {
			return pv.UsageError("the secret is empty")
		}
		if payload, err = pv.NewTextPayload(name, value); err != nil {
			return err
		}
	} else {
		filename := name
		if *fromFile != "" {
			filename = filepath.Base(*fromFile)
		}
		contentType := mime.TypeByExtension(filepath.Ext(filename))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		payload = pv.NewFilePayload(name, filename, contentType, value)
	}

	entry, err := target.Put(name, payload, store.Source{Type: store.SourceImport}, *overwrite)
	if err != nil {
		return err
	}

	if out.json() {
		return out.emitJSON(toSecretJSON(entry))
	}
	out.infof("Stored %s (%s) in the local store of agent %s.", name, entry.Kind, target.Agent)
	fmt.Fprintln(a.stdout, entry.Handle())

	return nil
}

// runSecretReveal prints a secret, on a terminal only. That is deliberate
// friction against agents capturing it; it is not a security boundary (any
// program running as this user can read the store and the agent key).
func runSecretReveal(a *app, args []string) error {
	fs, common := a.newFlagSet("secret reveal", "pastevault secret reveal NAME [--agent NAME] (terminal only)")
	agent := fs.String("agent", "", "Use another agent's store (default: the default agent)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("exactly one secret NAME is required")
	}
	if out.json() {
		return pv.UsageError("secret reveal has no --json output; secrets are only shown on a terminal")
	}
	if !a.stdinIsTerminal() || !a.stdoutIsTerminal() {
		return pv.UsageError("secret reveal only prints to an interactive terminal (stdin and stdout); programs should use pastevault run or inject")
	}

	target, err := openSecretStore(common.server, *agent)
	if err != nil {
		return err
	}
	_, payload, err := target.Get(positional[0])
	if err != nil {
		return err
	}
	value, err := payload.Bytes()
	if err != nil {
		return err
	}

	if _, err := a.stdout.Write(value); err != nil {
		return err
	}
	if len(value) > 0 && value[len(value)-1] != '\n' {
		fmt.Fprintln(a.stdout)
	}

	return nil
}
