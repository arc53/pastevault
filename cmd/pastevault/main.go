package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
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
	defer stop()

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	updateMode, executablePath := passiveUpdateGate(os.Args[1])
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

	var err error

	switch os.Args[1] {
	case "put":
		err = runPut(ctx, os.Args[2:])
	case "get":
		err = runGet(ctx, os.Args[2:])
	case "login":
		err = runLogin(ctx, os.Args[2:])
	case "whoami":
		err = runWhoAmI(ctx, os.Args[2:])
	case "logout":
		err = runLogout(ctx, os.Args[2:])
	case "update":
		err = runUpdate(ctx, os.Args[2:])
	case "config":
		err = runConfig(os.Args[2:])
	case "version", "--version", "-v":
		printVersion()
	case "help", "--help", "-h":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if updateMode == updater.ModeNotify {
		if latest := updater.CachedNotice(effectiveVersion); latest != "" {
			fmt.Fprintf(os.Stderr, "\nA new PasteVault version is available: %s -> %s. Run 'pastevault update'.\n", version, latest)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `PasteVault CLI

Usage:
  pastevault put [flags] <file> [<file>...]
  pastevault get [flags] <share-url-or-slug>
  pastevault login [flags]
  pastevault whoami [flags]
  pastevault logout [flags]
  pastevault update [--check|--yes|--rollback]
  pastevault config <show|set-auto-update>
  pastevault version

Environment:
  PASTEVAULT_SERVER          Default PasteVault server base URL
  PASTEVAULT_PUBLIC_URL      Default public share URL base
  PASTEVAULT_NO_UPDATE_CHECK Disable passive update checks when set

Examples:
  pastevault put ./report.pdf
  pastevault put --password ./secret.txt
  pastevault get https://pastevault.example/f/abc123#k=base64urlkey
  pastevault get abc123#k=base64urlkey
  pastevault get --server https://pastevault.example abc123
  pastevault login
  pastevault whoami
  pastevault update --check
  pastevault config set-auto-update notify
`)
}

func printVersion() {
	fmt.Printf("pastevault %s\n", version)
	fmt.Printf("commit %s\n", commit)
	fmt.Printf("built %s\n", date)
}

func passiveUpdateGate(command string) (mode string, executablePath string) {
	if os.Getenv("PASTEVAULT_NO_UPDATE_CHECK") != "" ||
		!term.IsTerminal(int(os.Stderr.Fd())) ||
		command == "update" || command == "config" ||
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

func runUpdate(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "--worker" {
		updater.RunWorker(version)
		return nil
	}

	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	checkOnly := fs.Bool("check", false, "Only check for a new version")
	assumeYes := fs.Bool("yes", false, "Skip the confirmation prompt")
	rollback := fs.Bool("rollback", false, "Restore the binary from before the last update")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("update does not take positional arguments")
	}
	if *rollback && (*checkOnly || *assumeYes) {
		return errors.New("--rollback cannot be combined with --check or --yes")
	}
	if !updater.IsReleaseVersion(version) {
		fmt.Printf("This binary reports version %q, which is not a tagged release build.\n", version)
		fmt.Println("If you built from source, update with git pull and rebuild the CLI.")
		return nil
	}

	if *rollback {
		executablePath, err := updater.ExecutablePath()
		if err != nil {
			return err
		}
		if updater.IsHomebrewPath(executablePath) {
			fmt.Println("This binary is managed by Homebrew. Roll back with Homebrew instead.")
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
		fmt.Printf("Rolled back to %s\n", rolledTo)
		fmt.Printf("Auto-update will skip %s. Run 'pastevault update' to reinstall it.\n", version)
		return nil
	}

	fmt.Fprintln(os.Stderr, "Checking for updates...")
	release, err := updater.FetchLatest(ctx, 10*time.Second)
	if err != nil {
		return fmt.Errorf("could not check for updates: %w", err)
	}
	_ = updater.RecordCheck(release)
	if !updater.IsNewer(release.TagName, version) {
		fmt.Printf("Already up to date: %s\n", version)
		return nil
	}
	if err := updater.ValidateRelease(ctx, release); err != nil {
		return fmt.Errorf("release %s is not installable: %w", release.TagName, err)
	}

	fmt.Printf("Update available: %s -> %s\n", version, release.TagName)
	if release.HTMLURL != "" {
		fmt.Println(release.HTMLURL)
	}
	if *checkOnly {
		if updater.StagedVersion() == release.TagName {
			fmt.Println("Already downloaded; it will be installed on your next command.")
		} else {
			fmt.Println("Run 'pastevault update' to install it.")
		}
		return nil
	}

	executablePath, err := updater.ExecutablePath()
	if err != nil {
		return err
	}
	if updater.IsHomebrewPath(executablePath) {
		fmt.Println("This binary is managed by Homebrew. Run 'brew upgrade --cask pastevault' instead.")
		return nil
	}
	if !updater.IsWritableDir(filepath.Dir(executablePath)) {
		return fmt.Errorf("no write permission for %s; reinstall into a user-writable directory or rerun with appropriate permissions", filepath.Dir(executablePath))
	}

	if !*assumeYes {
		fmt.Print("Proceed? [Y/n] ")
		input, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		input = strings.ToLower(strings.TrimSpace(input))
		if input != "" && input != "y" && input != "yes" {
			fmt.Println("Update cancelled.")
			return nil
		}
	}

	fmt.Fprintf(os.Stderr, "Downloading %s...\n", updater.AssetName())
	if err := updater.SetSkipVersion(""); err != nil {
		return fmt.Errorf("could not clear rollback protection: %w", err)
	}
	if err := updater.Apply(ctx, release, executablePath, version); err != nil {
		return err
	}
	fmt.Printf("Updated to %s\n", release.TagName)
	fmt.Println("Roll back anytime with 'pastevault update --rollback'.")
	return nil
}

func runConfig(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pastevault config <show|set-auto-update>")
	}
	switch args[0] {
	case "show":
		if len(args) != 1 {
			return errors.New("config show does not take arguments")
		}
		mode, err := updater.LoadMode()
		if err != nil {
			return err
		}
		fmt.Printf("auto_update %s\n", mode)
		return nil
	case "set-auto-update":
		if len(args) != 2 {
			return errors.New("usage: pastevault config set-auto-update <on|notify|off>")
		}
		mode := strings.ToLower(args[1])
		if err := updater.SetMode(mode); err != nil {
			return err
		}
		fmt.Printf("Auto-update set to: %s\n", mode)
		return nil
	default:
		return fmt.Errorf("unknown config command %q", args[0])
	}
}

func runPut(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("put", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	server := fs.String("server", pv.DefaultServerURL(), "PasteVault server base URL")
	expiresHours := fs.Int("expires-hours", 24, "Share expiry in hours")
	passwordFlag := fs.Bool("password", false, "Prompt for a password instead of using a random URL key")
	jsonOutput := fs.Bool("json", false, "Emit machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return errors.New("at least one file path is required")
	}

	password := ""
	if *passwordFlag {
		value, err := pv.PromptForPassword("Password: ")
		if err != nil {
			return err
		}
		password = value
		if strings.TrimSpace(password) == "" {
			return errors.New("password cannot be empty")
		}
	}

	inputs, totalSize, err := pv.ResolveUploadInputs(fs.Args())
	if err != nil {
		return err
	}

	client, err := pv.NewClient(*server, version)
	if err != nil {
		return err
	}

	storedSession, hasStoredToken, err := pv.ValidateStoredAuthSession(ctx, client)
	if err != nil {
		return err
	}
	if hasStoredToken && storedSession == nil {
		_, _ = pv.DeleteStoredAuthToken(client.BaseURL())
		return errors.New("stored login has expired; run pastevault login again or pastevault logout to continue anonymously")
	}

	capabilities, err := client.GetCapabilities(ctx)
	if err != nil {
		return err
	}

	if !capabilities.FileShares.Enabled {
		return errors.New("file sharing is not enabled on this server")
	}

	if len(inputs) > capabilities.FileShares.MaxFiles {
		return fmt.Errorf("share includes %d files but server limit is %d", len(inputs), capabilities.FileShares.MaxFiles)
	}

	if totalSize > int64(capabilities.FileShares.MaxShareSizeBytes) {
		return fmt.Errorf("share is %d bytes but server limit is %d bytes", totalSize, capabilities.FileShares.MaxShareSizeBytes)
	}

	encryption, err := pv.PrepareFileShareEncryption(password)
	if err != nil {
		return err
	}

	slug, err := pv.GenerateSlug(9)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Creating share %s\n", slug)

	createResponse, err := client.CreateFileShare(ctx, pv.CreateFileShareRequest{
		Slug:           slug,
		Salt:           encryption.Salt,
		KDFParams:      encryption.KDFParams,
		ExpiresInHours: *expiresHours,
		FileCount:      len(inputs),
		TotalSizeBytes: totalSize,
	})
	if err != nil {
		return err
	}

	manifestFiles := make([]pv.FileShareManifestFile, 0, len(inputs))
	chunkSize := capabilities.FileShares.ChunkSizeBytes

	for index, input := range inputs {
		fileID, err := pv.GenerateSlug(12)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Uploading %s (%d/%d)\n", input.DisplayName, index+1, len(inputs))

		chunks, err := pv.UploadFile(ctx, client, input, encryption.Key, slug, fileID, chunkSize)
		if err != nil {
			return err
		}

		manifestFiles = append(manifestFiles, pv.FileShareManifestFile{
			ID:           fileID,
			Name:         input.DisplayName,
			Size:         input.Size,
			Type:         input.ContentType,
			LastModified: input.LastModified,
			Chunks:       chunks,
		})
	}

	manifest := pv.FileShareManifest{
		Version: "v1",
		Files:   manifestFiles,
	}

	manifestCiphertext, manifestNonce, err := pv.EncryptFileShareManifest(manifest, encryption.Key, slug)
	if err != nil {
		return err
	}

	if err := client.CompleteFileShare(ctx, slug, pv.CompleteFileShareRequest{
		ManifestCiphertext: manifestCiphertext,
		ManifestNonce:      manifestNonce,
	}); err != nil {
		return err
	}

	shareURL := pv.BuildFileShareURL(pv.ResolvePublicBaseURL(*server), createResponse.Slug, encryption.ShareKey())
	shareRef := pv.BuildShortShareRef(createResponse.Slug, encryption.ShareKey())
	if *jsonOutput {
		output, err := pv.NewShareOutputJSON(createResponse.Slug, shareURL, createResponse.ExpiresAt, len(inputs), totalSize, password != "")
		if err != nil {
			return err
		}
		fmt.Println(output)
		return nil
	}

	fmt.Println(shareURL)
	if password != "" {
		fmt.Printf("pastevault get --password %s\n", createResponse.Slug)
	} else {
		fmt.Printf("pastevault get %s\n", shareRef)
	}
	if password != "" {
		fmt.Fprintln(os.Stderr, "Password protection is enabled; recipients will also need the password.")
	}

	return nil
}

func runLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	server := fs.String("server", pv.DefaultServerURL(), "PasteVault server base URL")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 0 {
		return errors.New("login does not take positional arguments")
	}

	client, err := pv.NewClient(*server, version)
	if err != nil {
		return err
	}

	session, hasStoredToken, err := pv.ValidateStoredAuthSession(ctx, client)
	if err != nil {
		return err
	}
	if hasStoredToken && session != nil {
		fmt.Printf("Already linked as %s\n", pv.FormatAuthIdentity(session.User))
		return nil
	}
	if hasStoredToken {
		_, _ = pv.DeleteStoredAuthToken(client.BaseURL())
		client.SetAuthToken("")
	}

	deviceCode, err := client.RequestDeviceCode(ctx, pv.CLIClientID)
	if err != nil {
		return err
	}

	fmt.Printf("Open: %s\n", deviceCode.VerificationURI)
	fmt.Printf("Code: %s\n", deviceCode.UserCode)
	fmt.Printf("Or open: %s\n", deviceCode.VerificationURIComplete)
	fmt.Fprintln(os.Stderr, "Waiting for approval...")

	pollInterval := time.Duration(deviceCode.Interval) * time.Second
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}

	timer := time.NewTimer(pollInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}

		tokenResponse, err := client.ExchangeDeviceToken(ctx, deviceCode.DeviceCode, pv.CLIClientID)
		if err != nil {
			var apiErr *pv.APIRequestError
			if errors.As(err, &apiErr) {
				switch apiErr.ErrorCode {
				case "authorization_pending":
					timer.Reset(pollInterval)
					continue
				case "slow_down":
					pollInterval += time.Second
					timer.Reset(pollInterval)
					continue
				case "expired_token":
					return errors.New("login code expired; run pastevault login again")
				case "access_denied":
					return errors.New("device approval was denied")
				}
			}

			return err
		}

		client.SetAuthToken(tokenResponse.AccessToken)
		if err := pv.SaveStoredAuthToken(client.BaseURL(), tokenResponse.AccessToken); err != nil {
			return err
		}

		session, err := client.GetAuthSession(ctx)
		if err != nil {
			return err
		}
		if session == nil {
			return errors.New("login completed but the server did not return a session")
		}

		fmt.Printf("Linked as %s\n", pv.FormatAuthIdentity(session.User))
		return nil
	}
}

func runWhoAmI(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	server := fs.String("server", pv.DefaultServerURL(), "PasteVault server base URL")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 0 {
		return errors.New("whoami does not take positional arguments")
	}

	client, err := pv.NewClient(*server, version)
	if err != nil {
		return err
	}

	session, hasStoredToken, err := pv.ValidateStoredAuthSession(ctx, client)
	if err != nil {
		return err
	}
	if !hasStoredToken {
		return errors.New("not logged in; run pastevault login")
	}
	if session == nil {
		_, _ = pv.DeleteStoredAuthToken(client.BaseURL())
		return errors.New("stored login has expired; run pastevault login again")
	}

	fmt.Printf("%s\n", pv.FormatAuthIdentity(session.User))
	fmt.Printf("server %s\n", client.BaseURL())
	return nil
}

func runLogout(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	server := fs.String("server", pv.DefaultServerURL(), "PasteVault server base URL")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 0 {
		return errors.New("logout does not take positional arguments")
	}

	client, err := pv.NewClient(*server, version)
	if err != nil {
		return err
	}

	removed, err := pv.DeleteStoredAuthToken(client.BaseURL())
	if err != nil {
		return err
	}

	if !removed {
		fmt.Printf("No saved login for %s\n", client.BaseURL())
		return nil
	}

	fmt.Printf("Removed saved login for %s\n", client.BaseURL())
	return nil
}

func runGet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	server := fs.String("server", pv.DefaultServerURL(), "PasteVault server base URL")
	keyOverride := fs.String("key", "", "Base64url share key for passwordless shares")
	passwordFlag := fs.Bool("password", false, "Prompt for a password for password-protected shares")
	outDir := fs.String("out", "", "Directory to write downloaded files into (defaults to the current directory)")
	overwrite := fs.Bool("overwrite", false, "Overwrite existing files")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return errors.New("exactly one share URL or slug is required")
	}

	ref, err := pv.ParseShareReference(fs.Arg(0), *server, pv.ResolvePublicBaseURL(*server))
	if err != nil {
		return err
	}

	if *keyOverride != "" {
		key, err := pv.DecodeKeyString(*keyOverride)
		if err != nil {
			return fmt.Errorf("invalid --key value: %w", err)
		}
		ref.Key = key
	}

	password := ""
	if *passwordFlag {
		value, err := pv.PromptForPassword("Password: ")
		if err != nil {
			return err
		}
		password = value
	}

	client, err := pv.NewClient(ref.Server, version)
	if err != nil {
		return err
	}

	share, err := client.GetFileShare(ctx, ref.Slug)
	if err != nil {
		return err
	}

	key, err := pv.ResolveDownloadKey(ref, share, password)
	if err != nil {
		return err
	}

	manifest, err := pv.DecryptFileShareManifest(share.ManifestCiphertext, share.ManifestNonce, key, share.Metadata.Slug)
	if err != nil {
		return fmt.Errorf("failed to decrypt manifest: %w", err)
	}

	targetDir := *outDir
	targetDescription := targetDir
	if targetDir == "" {
		targetDir = "."
		targetDescription = "current directory"
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Downloading share %s into %s\n", share.Metadata.Slug, targetDescription)

	if err := pv.DownloadManifest(ctx, client, manifest, key, share.Metadata.Slug, targetDir, *overwrite); err != nil {
		return err
	}

	return nil
}
