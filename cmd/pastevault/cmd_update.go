package main

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
	updater "github.com/arc53/pastevault/internal/update"
)

func runUpdate(ctx context.Context, a *app, args []string) error {
	if len(args) == 1 && args[0] == "--worker" {
		updater.RunWorker(version)
		return nil
	}

	fs := a.newBareFlagSet("update", "pastevault update [--check|--yes|--rollback]")
	checkOnly := fs.Bool("check", false, "Only check for a new version")
	assumeYes := fs.Bool("yes", false, "Skip the confirmation prompt")
	rollback := fs.Bool("rollback", false, "Restore the binary from before the last update")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		return pv.UsageError("update does not take positional arguments")
	}
	if *rollback && (*checkOnly || *assumeYes) {
		return pv.UsageError("--rollback cannot be combined with --check or --yes")
	}
	if !updater.IsReleaseVersion(version) {
		fmt.Fprintf(a.stdout, "This binary reports version %q, which is not a tagged release build.\n", version)
		fmt.Fprintln(a.stdout, "If you built from source, update with git pull and rebuild the CLI.")
		return nil
	}

	if *rollback {
		executablePath, err := updater.ExecutablePath()
		if err != nil {
			return err
		}
		if updater.IsHomebrewPath(executablePath) {
			fmt.Fprintln(a.stdout, "This binary is managed by Homebrew. Roll back with Homebrew instead.")
			return nil
		}
		if !updater.IsWritableDir(filepath.Dir(executablePath)) {
			return fmt.Errorf("no write permission for %s; reinstall into a user-writable directory or rerun with appropriate permissions", filepath.Dir(executablePath))
		}
		rolledTo, err := updater.Rollback(version, executablePath)
		if err != nil {
			return err
		}
		if rolledTo == "" {
			rolledTo = "the previous version"
		}
		fmt.Fprintf(a.stdout, "Rolled back to %s\n", rolledTo)
		fmt.Fprintf(a.stdout, "Auto-update will skip %s. Run 'pastevault update' to reinstall it.\n", version)
		return nil
	}

	fmt.Fprintln(a.stderr, "Checking for updates...")
	release, err := updater.FetchLatest(ctx, 10*time.Second)
	if err != nil {
		return pv.WrapError(pv.ExitNetwork, pv.CodeNetwork, err, "could not check for updates")
	}
	_ = updater.RecordCheck(release)
	if !updater.IsNewer(release.TagName, version) {
		fmt.Fprintf(a.stdout, "Already up to date: %s\n", version)
		return nil
	}
	if err := updater.ValidateRelease(ctx, release); err != nil {
		return fmt.Errorf("release %s is not installable: %w", release.TagName, err)
	}

	fmt.Fprintf(a.stdout, "Update available: %s -> %s\n", version, release.TagName)
	if release.HTMLURL != "" {
		fmt.Fprintln(a.stdout, release.HTMLURL)
	}
	if *checkOnly {
		if updater.StagedVersion() == release.TagName {
			fmt.Fprintln(a.stdout, "Already downloaded; it will be installed on your next command.")
		} else {
			fmt.Fprintln(a.stdout, "Run 'pastevault update' to install it.")
		}
		return nil
	}

	executablePath, err := updater.ExecutablePath()
	if err != nil {
		return err
	}
	if updater.IsHomebrewPath(executablePath) {
		fmt.Fprintln(a.stdout, "This binary is managed by Homebrew. Run 'brew upgrade --cask pastevault' instead.")
		return nil
	}
	if !updater.IsWritableDir(filepath.Dir(executablePath)) {
		return fmt.Errorf("no write permission for %s; reinstall into a user-writable directory or rerun with appropriate permissions", filepath.Dir(executablePath))
	}

	if !*assumeYes {
		fmt.Fprint(a.stdout, "Proceed? [Y/n] ")
		input, err := bufio.NewReader(a.stdin).ReadString('\n')
		if err != nil {
			return err
		}
		input = strings.ToLower(strings.TrimSpace(input))
		if input != "" && input != "y" && input != "yes" {
			fmt.Fprintln(a.stdout, "Update cancelled.")
			return nil
		}
	}

	fmt.Fprintf(a.stderr, "Downloading %s...\n", updater.AssetName())
	if err := updater.SetSkipVersion(""); err != nil {
		return fmt.Errorf("could not clear rollback protection: %w", err)
	}
	if err := updater.Apply(ctx, release, executablePath, version); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Updated to %s\n", release.TagName)
	fmt.Fprintln(a.stdout, "Roll back anytime with 'pastevault update --rollback'.")
	return nil
}

func runConfig(_ context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return pv.UsageError("usage: pastevault config <show|set-auto-update>")
	}
	switch args[0] {
	case "show":
		if len(args) != 1 {
			return pv.UsageError("config show does not take arguments")
		}
		mode, err := updater.LoadMode()
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "auto_update %s\n", mode)
		return nil
	case "set-auto-update":
		if len(args) != 2 {
			return pv.UsageError("usage: pastevault config set-auto-update <on|notify|off>")
		}
		mode := strings.ToLower(args[1])
		if err := updater.SetMode(mode); err != nil {
			return pv.WrapError(pv.ExitUsage, pv.CodeUsage, err, "invalid auto-update mode")
		}
		fmt.Fprintf(a.stdout, "Auto-update set to: %s\n", mode)
		return nil
	default:
		return pv.UsageError("unknown config command %q", args[0])
	}
}
