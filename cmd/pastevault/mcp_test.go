package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arc53/pastevault/internal/mcpserver"
	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectMCP serves the MCP server with the real in-process CLI over the
// in-memory transport.
func connectMCP(t *testing.T, server string, roots []string, allowPlaintext bool) *mcp.ClientSession {
	t.Helper()
	a := newApp()
	a.stderr = io.Discard
	mcpServer, err := mcpserver.New(mcpserver.Options{
		Server:         server,
		PublicBaseURL:  server,
		Roots:          roots,
		AllowPlaintext: allowPlaintext,
		Version:        "test",
		RunCLI:         a.mcpCommandRunner(),
		NewClient: func(ctx context.Context) (*pv.Client, error) {
			client, _, err := authenticatedClient(ctx, &commonFlags{server: server}, true)
			return client, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := mcpServer.MCP().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })

	return session
}

func mcpCall(t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any) (map[string]any, bool) {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	var value map[string]any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		t.Fatalf("%s: result is not JSON: %v\n%s", name, err, text)
	}
	return value, result.IsError
}

func TestMCPSendTextThenReceiveToFile(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)
	root := t.TempDir()
	session := connectMCP(t, server.URL, []string{root}, false)

	sent, isError := mcpCall(t, session, "send_text", map[string]any{"text": "deploy notes\nline two\n", "title": "notes"})
	if isError {
		t.Fatalf("send_text: %v", sent)
	}
	url, _ := sent["url"].(string)
	if sent["kind"] != "paste" || !strings.Contains(url, "#k=") || sent["max_views"] != float64(1) {
		t.Fatalf("send_text = %v", sent)
	}
	server.mu.Lock()
	if server.lastCreate["burn_after_read"] != true || server.lastCreate["expires_in_minutes"] != float64(60) {
		t.Errorf("create request = %v", server.lastCreate)
	}
	server.mu.Unlock()

	received, isError := mcpCall(t, session, "receive", map[string]any{"ref": url, "output_path": "notes.txt"})
	if isError {
		t.Fatalf("receive: %v", received)
	}
	target := filepath.Join(root, "notes.txt")
	if real, err := filepath.EvalSymlinks(root); err == nil {
		target = filepath.Join(real, "notes.txt")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "deploy notes\nline two\n" {
		t.Fatalf("written file: %q, %v", data, err)
	}
	if received["written_to"] != target || received["burned"] != true {
		t.Fatalf("receive = %v", received)
	}
	if _, ok := received["content"]; ok {
		t.Fatal("receive to a file returned the content")
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(target); info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", info.Mode().Perm())
		}
	}

	// Burned: a second receive fails with the CLI's exit code.
	failure, isError := mcpCall(t, session, "receive", map[string]any{"ref": url, "output_path": "again.txt"})
	errObject, _ := failure["error"].(map[string]any)
	if !isError || errObject["exit_code"] != float64(pv.ExitGone) || errObject["code"] != pv.CodeGone {
		t.Fatalf("second receive = %v", failure)
	}

	// No overwrite without the flag; nothing is consumed by the refusal.
	sent, _ = mcpCall(t, session, "send_text", map[string]any{"text": "second", "max_views": 2})
	consumed := server.consumed
	failure, isError = mcpCall(t, session, "receive", map[string]any{"ref": sent["url"], "output_path": target})
	errObject, _ = failure["error"].(map[string]any)
	if !isError || errObject["exit_code"] != float64(pv.ExitLocalFile) || server.consumed != consumed {
		t.Fatalf("receive onto an existing file = %v (consumed %d -> %d)", failure, consumed, server.consumed)
	}
	if received, isError = mcpCall(t, session, "receive", map[string]any{"ref": sent["url"], "output_path": target, "overwrite": true}); isError {
		t.Fatalf("receive with overwrite: %v", received)
	}
	if data, _ := os.ReadFile(target); string(data) != "second" {
		t.Fatalf("overwritten file = %q", data)
	}

	// Outside the roots: refused before anything is opened.
	failure, isError = mcpCall(t, session, "receive", map[string]any{"ref": sent["url"], "output_path": filepath.Join(t.TempDir(), "x.txt")})
	errObject, _ = failure["error"].(map[string]any)
	if !isError || errObject["code"] != mcpserver.CodePathRefused || server.consumed != consumed+1 {
		t.Fatalf("outside the roots = %v", failure)
	}
}

func TestMCPReceivePlaintextRefusesSecretLike(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)
	t.Setenv(pv.EnvAgent, "")
	t.Setenv(pv.EnvAgentKey, "")
	keys, _ := pv.GenerateAgentKeyPair()
	path, _ := pv.AgentKeyPath(server.URL, "tester")
	if err := pv.SaveAgentIdentity(pv.NewAgentIdentity(server.URL, "tester", keys), path, false); err != nil {
		t.Fatal(err)
	}
	session := connectMCP(t, server.URL, []string{t.TempDir()}, true)

	sent, _ := mcpCall(t, session, "send_text", map[string]any{"text": "just a note"})
	received, isError := mcpCall(t, session, "receive", map[string]any{"ref": sent["url"], "allow_plaintext": true})
	if isError || received["content"] != "just a note" {
		t.Fatalf("plain receive = %v", received)
	}

	sent, _ = mcpCall(t, session, "send_text", map[string]any{"text": "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"})
	received, isError = mcpCall(t, session, "receive", map[string]any{"ref": sent["url"], "allow_plaintext": true})
	if isError || received["content"] != nil || received["withheld"] == nil {
		t.Fatalf("secret-like receive = %v", received)
	}
	handle, _ := received["saved_as"].(string)
	if !strings.HasPrefix(handle, "pv://secret/received_") {
		t.Fatalf("withheld content not kept: %v", received)
	}
}

func TestMCPCommandSpeaksOnlyProtocolOnStdout(t *testing.T) {
	server := newFakeServer(t)
	isolate(t, server.URL)
	t.Setenv(pv.EnvAgent, "")
	t.Setenv(pv.EnvAgentKey, "")

	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderr := &lockedWriter{}
	a := &app{
		stdin:            stdinReader,
		stdout:           stdoutWriter,
		stderr:           stderr,
		stdinIsTerminal:  func() bool { return false },
		stdoutIsTerminal: func() bool { return false },
		promptPassword:   func(string) (string, error) { return "", fmt.Errorf("no terminal") },
	}
	done := make(chan int, 1)
	go func() {
		done <- a.run(context.Background(), []string{"mcp", "--root", t.TempDir()})
		_ = stdoutWriter.Close()
	}()

	lines := bufio.NewScanner(stdoutReader)
	lines.Buffer(make([]byte, 1<<20), 1<<20)
	send := func(message string) {
		if _, err := io.WriteString(stdinWriter, message+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	receive := func() map[string]any {
		if !lines.Scan() {
			t.Fatalf("no response: %v", lines.Err())
		}
		var message map[string]any
		if err := json.Unmarshal(lines.Bytes(), &message); err != nil || message["jsonrpc"] != "2.0" {
			t.Fatalf("stdout carried a non-protocol line: %q", lines.Text())
		}
		return message
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	initialized := receive()
	result, _ := initialized["result"].(map[string]any)
	if result["protocolVersion"] != "2025-11-25" {
		t.Fatalf("initialize = %v", initialized)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_text","arguments":{"text":"over stdio"}}}`)
	called := receive()
	result, _ = called["result"].(map[string]any)
	if result == nil || result["isError"] == true {
		t.Fatalf("tools/call = %v", called)
	}

	_ = stdinWriter.Close()
	select {
	case exit := <-done:
		if exit != 0 {
			t.Fatalf("mcp exited %d: %s", exit, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mcp did not exit at EOF")
	}
	if !strings.Contains(stderr.String(), "PasteVault MCP server") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMCPFlagErrors(t *testing.T) {
	isolate(t, offlineServer)
	if result := runCLI(t, "", false, "mcp", "--root", filepath.Join(t.TempDir(), "missing")); result.exit != pv.ExitUsage {
		t.Fatalf("missing root: exit %d", result.exit)
	}
	if result := runCLI(t, "", false, "mcp", "extra"); result.exit != pv.ExitUsage {
		t.Fatalf("positional argument: exit %d", result.exit)
	}
}

// lockedWriter collects output written from several goroutines.
type lockedWriter struct {
	mu      sync.Mutex
	builder strings.Builder
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.builder.Write(p)
}

func (w *lockedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.builder.String()
}
