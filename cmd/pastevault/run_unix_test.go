//go:build !windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func TestRunForwardsSignals(t *testing.T) {
	requireShell(t)
	withAgent(t)

	var stdout, stderr syncBuffer
	a := &app{
		stdin:            strings.NewReader(""),
		stdout:           &stdout,
		stderr:           &stderr,
		stdinIsTerminal:  func() bool { return false },
		stdoutIsTerminal: func() bool { return false },
		promptPassword:   func(string) (string, error) { return "", fmt.Errorf("no terminal") },
	}

	done := make(chan int, 1)
	go func() {
		done <- a.run(context.Background(), []string{"run", "--", "sh", "-c", `trap 'echo got-term; exit 42' TERM; echo ready; while :; do sleep 0.05; done`})
	}()

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stdout.String(), "ready") {
		if time.Now().After(deadline) {
			t.Fatalf("the child never started: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// run has a handler installed, so this reaches run, which forwards it.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case exit := <-done:
		if exit != 42 || !strings.Contains(stdout.String(), "got-term") {
			t.Fatalf("exit %d, stdout %q", exit, stdout.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the signal was not forwarded")
	}
}

// A signal that arrives before the command has started is replayed to it
// once it has (it used to be dropped, and the forwarder raced with Start).
func TestSignalBeforeStartIsReplayed(t *testing.T) {
	attach, stop := forwardSignals()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	child := exec.Command("sleep", "10")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	attach(child.Process)
	started := time.Now()
	_ = child.Wait()
	if code := childExitCode(child.ProcessState); code != 128+int(syscall.SIGUSR1) || time.Since(started) > 5*time.Second {
		t.Fatalf("exit %d after %s, want %d at once", code, time.Since(started), 128+int(syscall.SIGUSR1))
	}
}

// Masked output must not keep run waiting for background processes the
// command left behind (they hold the output pipe open).
func TestRunDoesNotWaitForBackgroundProcesses(t *testing.T) {
	withAgent(t)
	importSecret(t, "TOKEN", "background-secret-value")
	envFile := writeFile(t, ".env.pv", "T=pv://secret/TOKEN\n", 0o600)

	started := time.Now()
	result := runCLI(t, "", false, "run", "--env-file", envFile, "--", "sh", "-c", `sleep 8 & echo "started $T"`)
	elapsed := time.Since(started)
	if result.exit != 0 || result.stdout != "started [masked:T]\n" {
		t.Fatalf("exit %d, stdout %q, stderr %s", result.exit, result.stdout, result.stderr)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("run waited %s for a background process", elapsed)
	}
}
