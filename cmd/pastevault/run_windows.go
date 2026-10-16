//go:build windows

package main

import (
	"os"
	"os/exec"
)

// On Windows, Ctrl-C reaches every process attached to the console, so
// there is nothing to forward.
func forwardSignals(_ *exec.Cmd, _ bool) func() {
	return func() {}
}

func childExitCode(state *os.ProcessState) int {
	return state.ExitCode()
}
