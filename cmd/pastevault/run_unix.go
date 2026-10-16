//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// forwardedSignals reach the child through run. SIGINT and SIGQUIT typed
// on the terminal already reach it directly (same process group), so they
// are only forwarded when run is not the terminal's foreground job.
var forwardedSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2}

// forwardSignals starts catching the forwarded signals. Signals that
// arrive before attach hands over the started process are queued and
// replayed to it, so none is lost between launch and Start returning.
func forwardSignals() (attach func(*os.Process), stop func()) {
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, forwardedSignals...)
	processes := make(chan *os.Process, 1)
	done := make(chan struct{})
	finished := make(chan struct{})
	foreground := inTerminalForeground()

	go func() {
		defer close(finished)
		var process *os.Process
		var queued []os.Signal
		send := func(received os.Signal) {
			if foreground && (received == syscall.SIGINT || received == syscall.SIGQUIT) {
				return
			}
			_ = process.Signal(received)
		}
		for {
			select {
			case <-done:
				return
			case process = <-processes:
				for _, received := range queued {
					send(received)
				}
				queued = nil
			case received := <-signals:
				if process == nil {
					queued = append(queued, received)
					continue
				}
				send(received)
			}
		}
	}()

	stopped := false
	return func(process *os.Process) { processes <- process }, func() {
		if stopped {
			return
		}
		stopped = true
		signal.Stop(signals)
		close(done)
		<-finished
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
