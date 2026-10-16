//go:build !windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// forwardedSignals reach the child through run. SIGINT and SIGQUIT typed
// on the terminal already reach it directly (same process group), so they
// are only forwarded when run is not the terminal's foreground job.
var forwardedSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2}

func forwardSignals(child *exec.Cmd, _ bool) func() {
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, forwardedSignals...)
	done := make(chan struct{})
	foreground := inTerminalForeground()

	go func() {
		for {
			select {
			case <-done:
				return
			case received := <-signals:
				if child.Process == nil {
					continue
				}
				if foreground && (received == syscall.SIGINT || received == syscall.SIGQUIT) {
					continue
				}
				_ = child.Process.Signal(received)
			}
		}
	}()

	return func() {
		signal.Stop(signals)
		close(done)
	}
}

// inTerminalForeground reports whether this process's group is the
// foreground job of its controlling terminal.
func inTerminalForeground() bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	defer tty.Close()

	group, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	return err == nil && group == unix.Getpgrp()
}

func childExitCode(state *os.ProcessState) int {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}

	return state.ExitCode()
}
