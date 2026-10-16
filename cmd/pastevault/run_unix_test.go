//go:build !windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
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
