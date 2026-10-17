package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	updater "github.com/arc53/pastevault/internal/update"
	"golang.org/x/term"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	command := ""
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	updateMode, executablePath := passiveUpdateGate(command)
	effectiveVersion := version
	if updateMode == updater.ModeOn {
		stagedVersion, err := updater.ApplyStaged(version, executablePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not apply staged PasteVault update: %v\n", err)
		} else if stagedVersion != "" {
			effectiveVersion = stagedVersion
			fmt.Fprintf(os.Stderr, "PasteVault updated to %s (takes effect on your next command)\n", stagedVersion)
		}
	}
	if updateMode != "" && updater.ShouldSpawnWorker(effectiveVersion, updateMode) {
		updater.SpawnWorker()
	}

	exitCode := newApp().run(ctx, os.Args[1:])

	if updateMode == updater.ModeNotify {
		if latest := updater.CachedNotice(effectiveVersion); latest != "" {
			fmt.Fprintf(os.Stderr, "\nA new PasteVault version is available: %s -> %s. Run 'pastevault update'.\n", version, latest)
		}
	}

	stop()
	os.Exit(exitCode)
}

// noUpdateGateCommands never apply or check for updates in the background:
// they manage updates themselves, or (mcp, run) are long-lived processes
// driven by other programs.
var noUpdateGateCommands = map[string]bool{
	"update": true,
	"config": true,
	"mcp":    true,
	"run":    true,
}

func passiveUpdateGate(command string) (mode string, executablePath string) {
	// Scripts and agents (no terminal on stderr) never get update side effects.
	if os.Getenv("PASTEVAULT_NO_UPDATE_CHECK") != "" ||
		!term.IsTerminal(int(os.Stderr.Fd())) ||
		command == "" || noUpdateGateCommands[command] ||
		!updater.IsReleaseVersion(version) {
		return "", ""
	}

	mode, err := updater.LoadMode()
	if err != nil || mode == updater.ModeOff {
		return "", ""
	}
	executablePath, err = updater.ExecutablePath()
	if err != nil {
		return "", ""
	}
	if mode == updater.ModeOn && (!updater.HasEmbeddedPublicKey() ||
		updater.IsHomebrewPath(executablePath) ||
		!updater.IsWritableDir(filepath.Dir(executablePath))) {
		mode = updater.ModeNotify
	}
	return mode, executablePath
}
