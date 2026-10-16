package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/arc53/pastevault/internal/mcpserver"
	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcp runs other commands in-process, which refer back to the command
// table, so it is added to the table here rather than in its initializer.
func init() {
	for index, cmd := range commands {
		if cmd.name == "inject" {
			commands = append(commands[:index+1], append([]command{{"mcp", "Serve the MCP server for AI agents on stdio (docs/agents.md)", runMCP}}, commands[index+1:]...)...)
			return
		}
	}
	commands = append(commands, command{"mcp", "Serve the MCP server for AI agents on stdio (docs/agents.md)", runMCP})
}

// runMCP serves the PasteVault MCP server on stdin/stdout (spec §9). Only
// protocol messages go to stdout; diagnostics go to stderr.
func runMCP(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("mcp", "pastevault mcp [--agent NAME] [--root DIR]... [--allow-plaintext] [--server URL]")
	agent := fs.String("agent", "", "Agent identity to act as (default: the default agent)")
	var roots stringList
	fs.Var(&roots, "root", "Directory send_file and receive may use (repeatable; default: the client's MCP roots, else the working directory)")
	allowPlaintext := fs.Bool("allow-plaintext", false, "Let receive return share content that does not look like a secret (allow_plaintext=true per call)")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		return pv.UsageError("mcp takes no arguments")
	}
	if _, err := newClient(common.server); err != nil {
		return err
	}
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return pv.UsageError("--root %s is not a directory", root)
		}
	}
	if *agent != "" {
		if !pv.ValidAgentName(*agent) {
			return pv.UsageError("invalid agent name %q", *agent)
		}
		if strings.TrimSpace(os.Getenv(pv.EnvAgentKey)) != "" {
			return pv.UsageError("--agent cannot be combined with %s", pv.EnvAgentKey)
		}
		// The in-process get --save resolves the default agent: make it
		// this one.
		if err := os.Setenv(pv.EnvAgent, *agent); err != nil {
			return err
		}
	}

	server := common.server
	options := mcpserver.Options{
		Server:         server,
		PublicBaseURL:  pv.ResolvePublicBaseURL(server),
		Agent:          *agent,
		Roots:          roots,
		AllowPlaintext: *allowPlaintext,
		Version:        version,
		RunCLI:         a.mcpCommandRunner(),
		NewClient: func(ctx context.Context) (*pv.Client, error) {
			client, _, err := authenticatedClient(ctx, &commonFlags{server: server}, true)
			return client, err
		},
		Log: a.stderr,
	}
	mcpServer, err := mcpserver.New(options)
	if err != nil {
		return err
	}

	// stdout carries only protocol messages: anything else that writes to
	// os.Stdout during the session ends up on stderr.
	protocolOut := a.stdout
	if file, ok := protocolOut.(*os.File); ok && file == os.Stdout {
		os.Stdout = os.Stderr
		defer func() { os.Stdout = file }()
	}

	fmt.Fprintf(a.stderr, "PasteVault MCP server %s for %s on stdio\n", version, server)
	transport := &mcp.IOTransport{Reader: io.NopCloser(a.stdin), Writer: nopWriteCloser{protocolOut}}
	if err := mcpServer.Run(ctx, transport); err != nil {
		return pv.WrapError(pv.ExitInternal, pv.CodeInternal, err, "MCP session failed")
	}

	return nil
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

// mcpCommandRunner runs CLI commands in-process for the MCP tools: no
// terminal, no prompts, stdin from the tool, stdout and stderr captured.
func (a *app) mcpCommandRunner() func(ctx context.Context, args []string, stdin []byte) mcpserver.CLIResult {
	return func(ctx context.Context, args []string, stdin []byte) mcpserver.CLIResult {
		var stdout, stderr bytes.Buffer
		sub := &app{
			stdin:            bytes.NewReader(stdin),
			stdout:           &stdout,
			stderr:           &stderr,
			stdinIsTerminal:  func() bool { return false },
			stdoutIsTerminal: func() bool { return false },
			promptPassword: func(string) (string, error) {
				return "", pv.NewError(pv.ExitUsage, pv.CodePasswordNeeded, "password-protected shares cannot be opened through MCP")
			},
		}
		exit := sub.run(ctx, args)

		return mcpserver.CLIResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Exit: exit}
	}
}
