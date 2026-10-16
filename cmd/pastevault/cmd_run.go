package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/arc53/pastevault/internal/envmask"
	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/secrets"
)

// Exit codes of run (and inject) besides the child's own (spec §5.2).
const (
	exitRunUnresolved = 125
	exitRunCannotExec = 126
	exitRunNotFound   = 127
)

// strippedEnvironment are never inherited by the command: the CLI's own
// credentials have no business in a child process.
var strippedEnvironment = []string{pv.EnvToken, pv.EnvPassword, pv.EnvAgentKey}

// keptWithoutInherit survive --no-inherit, so the command can still be
// found and run.
var keptWithoutInherit = []string{"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "SystemRoot", "COMSPEC", "PATHEXT", "WINDIR"}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// runRun is "pastevault run [--env-file F]... [--no-mask] [--no-inherit] --
// COMMAND [ARGS...]". Values that are pv:// handles (in env files, or in
// the inherited environment) are resolved; the command's stdout and stderr
// are masked unless --no-mask.
func runRun(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("run", "pastevault run [--env-file .env.pv]... [--no-mask] [--no-inherit] -- COMMAND [ARGS...]")
	var envFiles stringList
	fs.Var(&envFiles, "env-file", "Read KEY=value lines from this file (repeatable; later files win); pv:// values are resolved")
	noMask := fs.Bool("no-mask", false, "Do not mask secret values in the command's output (output stays a terminal)")
	noInherit := fs.Bool("no-inherit", false, "Start from an empty environment (keeps PATH, HOME and a few system variables)")

	// Flags end at the first argument that isn't one: everything after it
	// belongs to the command ("pastevault run env -0" works without --).
	fs.SetOutput(a.helpOutput())
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelpShown
		}
		return pv.UsageError("%v", err)
	}
	command := fs.Args()
	out := a.output(common)
	if len(command) == 0 {
		return pv.UsageError("no command given: pastevault run [flags] -- COMMAND [ARGS...]")
	}

	environment, masked, err := buildRunEnvironment(ctx, out, common, envFiles, *noInherit)
	if err != nil {
		return &commandExit{code: exitRunUnresolved, err: err}
	}

	var maskSecrets []envmask.Secret
	for _, name := range sortedKeys(masked) {
		maskSecrets = append(maskSecrets, envmask.Secret{Name: name, Value: masked[name]})
	}
	masker, warnings := envmask.New(maskSecrets)
	if !*noMask {
		for _, warning := range warnings {
			out.warnf("%s", warning)
		}
	}

	return runChild(a, command, environment, masker, *noMask)
}

// buildRunEnvironment assembles the child's environment: the inherited
// environment (minus PASTEVAULT_TOKEN, _PASSWORD and _AGENT_KEY), then each
// env file in order. Every pv:// value is resolved; the resolved values are
// returned for masking, by variable name.
func buildRunEnvironment(ctx context.Context, out *output, common *commonFlags, envFiles []string, noInherit bool) ([]string, map[string][]byte, error) {
	values := map[string]string{}
	var order []string
	set := func(key, value string) {
		if _, exists := values[key]; !exists {
			order = append(order, key)
		}
		values[key] = value
	}

	stripped := map[string]bool{}
	for _, name := range strippedEnvironment {
		stripped[name] = true
	}
	kept := map[string]bool{}
	for _, name := range keptWithoutInherit {
		kept[name] = true
	}
	for _, entry := range os.Environ() {
		key, value, found := strings.Cut(entry, "=")
		if !found || key == "" || stripped[key] || (noInherit && !kept[key]) {
			continue
		}
		set(key, value)
	}

	type assignment struct {
		key, value, origin string
	}
	var assignments []assignment
	for _, key := range order {
		if pv.LooksLikeHandle(values[key]) {
			assignments = append(assignments, assignment{key, values[key], "the environment"})
		}
	}
	for _, path := range envFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "could not read --env-file %s", path)
		}
		entries, err := pv.ParseDotenv(data)
		if err != nil {
			return nil, nil, pv.UsageError("%s: %v", path, err)
		}
		for _, entry := range entries {
			set(entry.Key, entry.Value)
			assignments = append(assignments, assignment{entry.Key, entry.Value, path})
		}
	}

	resolver := runResolver(common)
	masked := map[string][]byte{}
	for _, item := range assignments {
		if values[item.key] != item.value || !pv.LooksLikeHandle(item.value) {
			// Overridden later, or a literal value.
			continue
		}
		value, err := resolver.Resolve(ctx, item.value, false)
		if err != nil {
			return nil, nil, fmt.Errorf("%s (from %s): %w", item.key, item.origin, err)
		}
		if strings.ContainsRune(string(value), 0) {
			return nil, nil, pv.UsageError("%s (from %s): the secret contains a NUL byte and can't be an environment variable", item.key, item.origin)
		}
		values[item.key] = string(value)
		masked[item.key] = value
	}

	environment := make([]string, 0, len(order))
	for _, key := range order {
		environment = append(environment, key+"="+values[key])
	}

	return environment, masked, nil
}

func runResolver(common *commonFlags) *secrets.Resolver {
	return &secrets.Resolver{
		Server:     common.server,
		PublicBase: pv.ResolvePublicBaseURL(common.server),
		NewClient: func(server string) (*pv.Client, error) {
			client, err := newClient(server)
			if err != nil {
				return nil, err
			}
			// PASTEVAULT_TOKEN only goes to the configured server.
			if _, err := pv.AttachCredentials(client, common.server); err != nil {
				return nil, err
			}
			return client, nil
		},
	}
}

func sortedKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

// runChild starts the command, forwards signals, waits, and returns its
// exit status as a commandExit.
func runChild(a *app, command []string, environment []string, masker *envmask.Masker, noMask bool) error {
	path, err := exec.LookPath(command[0])
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return &commandExit{code: exitRunNotFound, err: pv.UsageError("%s: command not found", command[0])}
		}
		return &commandExit{code: exitRunCannotExec, err: pv.UsageError("%s: %v", command[0], err)}
	}

	child := exec.Command(path, command[1:]...)
	child.Args[0] = command[0]
	child.Env = environment
	child.Stdin = a.stdin

	var writers []*envmask.Writer
	if noMask || !masker.Enabled() {
		child.Stdout = a.stdout
		child.Stderr = a.stderr
	} else {
		stdout, stderr := masker.Wrap(a.stdout), masker.Wrap(a.stderr)
		child.Stdout, child.Stderr = stdout, stderr
		writers = append(writers, stdout, stderr)
	}

	stopSignals := forwardSignals(child, a.stdinIsTerminal())
	if err := child.Start(); err != nil {
		stopSignals()
		return &commandExit{code: exitRunCannotExec, err: pv.UsageError("%s: %v", command[0], err)}
	}
	waitErr := child.Wait()
	stopSignals()

	for _, writer := range writers {
		_ = writer.Close()
	}

	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return &commandExit{code: exitRunCannotExec, err: fmt.Errorf("%s: %w", command[0], waitErr)}
		}
	}

	return &commandExit{code: childExitCode(child.ProcessState)}
}
