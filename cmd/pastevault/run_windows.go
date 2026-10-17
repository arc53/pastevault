//go:build windows

package main

import (
	"os"
)

// On Windows, Ctrl-C reaches every process attached to the console, so
// there is nothing to forward.
func forwardSignals() (attach func(*os.Process), stop func()) {
	return func(*os.Process) {}, func() {}
}

func childExitCode(state *os.ProcessState) int {
	return state.ExitCode()
}
