package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

// putOutput is the --json result of put (docs/cli-reference.md).
type putOutput struct {
	Slug              string        `json:"slug"`
	Kind              string        `json:"kind"`
	URL               string        `json:"url"`
	KeyInURL          bool          `json:"key_in_url"`
	KeyFile           string        `json:"key_file,omitempty"`
	ExpiresAt         *string       `json:"expires_at"`
	MaxViews          *int          `json:"max_views"`
	BurnAfterRead     bool          `json:"burn_after_read"`
	Recipient         *putRecipient `json:"recipient"`
	PasswordProtected bool          `json:"password_protected"`
	FileCount         *int          `json:"file_count,omitempty"`
	TotalSizeBytes    *int64        `json:"total_size_bytes,omitempty"`
}

// putRecipient names the agent a sealed share was sent to (put --to).
type putRecipient struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

type putOptions struct {
	title         string
	format        string
	language      string
	as            string
	expiryMinutes int
	maxViews      int
	password      pv.PasswordSource
	noKeyInOutput bool
	keyOut        string
}

// pasteInput is text that becomes a /p/ paste.
type pasteInput struct {
	content  pv.PasteContent
	fromFile string
}

func runPut(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("put", "pastevault put [flags] [<file>... | -]")
	title := fs.String("title", "", "Paste title (pastes only; defaults to the file name)")
	format := fs.String("format", "", "Paste format: plain or markdown (default plain)")
	language := fs.String("language", "", "Syntax highlighting hint for plain pastes, e.g. bash or go")
	as := fs.String("as", "auto", "Share as auto, paste or files (auto: a single .env file becomes a paste)")
	text := fs.String("text", "", "Share this text (visible in the process list and shell history; prefer stdin)")
	expires := fs.String("expires", "", "Expiry such as 15m, 2h or 7d (default 24h)")
	expiresHours := fs.Int("expires-hours", 0, "Deprecated: use --expires Nh")
	maxViews := fs.Int("max-views", 0, "Destroy the share after N views (1-1000)")
	burn := fs.Bool("burn", false, "Destroy the share after the first view (same as --max-views 1)")
	burnAfterRead := fs.Bool("burn-after-read", false, "Alias for --burn")
	passwordPrompt := fs.Bool("password", false, "Protect with a password (prompted, or from --password-file / PASTEVAULT_PASSWORD)")
	passwordFile := fs.String("password-file", "", "Protect with the password in this file")
	noKeyInOutput := fs.Bool("no-key-in-output", false, "Print the link without its key (requires --key-out)")
	keyOut := fs.String("key-out", "", "Write the share key to this new file (mode 0600)")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)

	options := putOptions{
		title:         *title,
		format:        strings.ToLower(strings.TrimSpace(*format)),
		language:      strings.TrimSpace(*language),
		as:            strings.ToLower(strings.TrimSpace(*as)),
		maxViews:      *maxViews,
		password:      pv.PasswordSource{Prompt: *passwordPrompt, File: *passwordFile},
		noKeyInOutput: *noKeyInOutput,
		keyOut:        *keyOut,
	}
	if err := validatePutFlags(&options, out, *expires, *expiresHours, *burn || *burnAfterRead); err != nil {
		return err
	}

	textSet := flagWasSet(fs, "text")
	if textSet {
		out.warnf("--text puts the content in the process list and shell history; prefer piping it on stdin")
	}

	var paste *pasteInput
	var files []string
	switch {
	case textSet && len(positional) > 0:
		return pv.UsageError("--text cannot be combined with file arguments")
	case textSet:
		paste = &pasteInput{content: pv.PasteContent{Body: *text}}
	case len(positional) == 1 && positional[0] == "-":
		paste = &pasteInput{}
	case len(positional) == 0:
		if a.stdinIsTerminal() {
			return pv.UsageError("nothing to share: pass file paths, - to read stdin, or --text")
		}
		paste = &pasteInput{}
	default:
		for _, path := range positional {
			if path == "-" {
				return pv.UsageError("- (stdin) cannot be combined with file arguments")
			}
		}
		files = positional
	}

	if paste != nil && options.as == "files" {
		return pv.UsageError("--as files needs file paths; text from stdin or --text is shared as a paste")
	}

	client, _, err := authenticatedClient(ctx, common, false)
	if err != nil {
		return err
	}

	capabilities, err := fetchCapabilities(ctx, client)
	if err != nil {
		return err
	}
	maxPasteBytes := capabilities.Limits.MaxPasteSizeBytes
	if maxPasteBytes <= 0 {
		maxPasteBytes = pv.DefaultMaxPasteBytes
	}

	// Decide between a paste and a file share before anything is created.
	if paste != nil && !textSet {
		data, err := pv.ReadTextInput(a.stdin, int64(maxPasteBytes))
		if err != nil {
			return err
		}
		paste.content.Body = string(data)
	} else if paste != nil {
		if err := pv.ValidatePasteText([]byte(paste.content.Body)); err != nil {
			return err
		}
	}
	if files != nil {
		paste, err = filePasteCandidate(files, options.as, maxPasteBytes)
		if err != nil {
			return err
		}
	}

	if paste == nil && (options.title != "" || options.format != "" || options.language != "") {
		return pv.UsageError("--title, --format and --language apply to pastes; use --as paste to share one text file as a paste")
	}

	if err := checkShareLimits(capabilities, options.maxViews); err != nil {
		return err
	}
	expiry, err := pv.ResolveExpiry(options.expiryMinutes, capabilities)
	if err != nil {
		return err
	}

	password := ""
	if options.password.Requested() {
		password, err = pv.ResolvePassword(options.password, a.stdinIsTerminal(), a.promptPassword)
		if err != nil {
			return err
		}
		if password == "" {
			return pv.NewError(pv.ExitUsage, pv.CodePasswordNeeded, "--password needs a password: use --password-file, PASTEVAULT_PASSWORD or a terminal prompt")
		}
	}

	encryption, err := pv.PrepareFileShareEncryption(password)
	if err != nil {
		return err
	}

	// The key file is written before anything is uploaded, so a failure here
	// never leaves a share whose key was only printed.
	if options.keyOut != "" {
		if err := pv.WritePrivateFile(options.keyOut, []byte(pv.EncodeBase64URL(encryption.Key)+"\n"), false); err != nil {
			return err
		}
	}

	var result putOutput
	if paste != nil {
		result, err = createPaste(ctx, client, out, paste, options, encryption, expiry, maxPasteBytes, common.server)
	} else {
		result, err = createFileShare(ctx, client, out, files, options, encryption, expiry, capabilities, common.server)
	}
	if err != nil {
		if options.keyOut != "" {
			_ = os.Remove(options.keyOut)
		}
		return err
	}
	if options.keyOut != "" {
		result.KeyFile = options.keyOut
	}

	return printPutResult(out, result, encryption, options)
}

func validatePutFlags(options *putOptions, out *output, expires string, expiresHours int, burn bool) error {
	switch options.as {
	case "auto", "paste", "files":
	default:
		return pv.UsageError("--as must be auto, paste or files")
	}

	switch options.format {
	case "", pv.RenderModePlain, pv.RenderModeMarkdown:
	default:
		return pv.UsageError("--format must be plain or markdown")
	}
	if options.format == pv.RenderModeMarkdown && options.language != "" {
		return pv.UsageError("--language applies to plain pastes; it cannot be combined with --format markdown")
	}

	switch {
	case expires != "" && expiresHours != 0:
		return pv.UsageError("use either --expires or --expires-hours, not both")
	case expiresHours != 0:
		if err := pv.ValidateExpiresHours(expiresHours); err != nil {
			return pv.UsageError("%v", err)
		}
		out.warnf("--expires-hours is deprecated; use --expires %dh", expiresHours)
		options.expiryMinutes = expiresHours * 60
	case expires != "":
		minutes, err := pv.ParseExpiry(expires)
		if err != nil {
			return err
		}
		options.expiryMinutes = minutes
	default:
		options.expiryMinutes = pv.DefaultExpiresMinutes
	}

	if options.maxViews < 0 || options.maxViews > 1000 {
		return pv.UsageError("--max-views must be between 1 and 1000")
	}
	if burn {
		if options.maxViews > 1 {
			return pv.UsageError("--burn means --max-views 1; use one of them")
		}
		options.maxViews = 1
	}

	if options.noKeyInOutput && options.keyOut == "" {
		return pv.UsageError("--no-key-in-output requires --key-out FILE, or the key would be lost")
	}
	if options.password.Requested() && (options.keyOut != "" || options.noKeyInOutput) {
		return pv.UsageError("password-protected shares have no URL key; drop --key-out and --no-key-in-output")
	}

	return nil
}

// filePasteCandidate returns the paste for "--as paste", or for "--as auto"
// with a single dotenv file that fits the paste limit; nil means file share.
func filePasteCandidate(files []string, as string, maxPasteBytes int) (*pasteInput, error) {
	if as == "files" {
		return nil, nil
	}
	if as == "paste" && len(files) != 1 {
		return nil, pv.UsageError("--as paste takes exactly one file")
	}
	if as == "auto" && (len(files) != 1 || !pv.IsEnvFileName(files[0])) {
		return nil, nil
	}

	path := filepath.Clean(files[0])
	info, err := os.Stat(path)
	if err != nil {
		return nil, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot read %s", path)
	}
	if info.IsDir() {
		return nil, pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "%s is a directory", path)
	}
	if info.Size() > int64(maxPasteBytes) {
		if as == "auto" {
			return nil, nil
		}
		return nil, pv.NewError(pv.ExitUsage, pv.CodeTooLarge, "%s is larger than the %d-byte paste limit; share it with --as files", path, maxPasteBytes)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot read %s", path)
	}
	if err := pv.ValidatePasteText(data); err != nil {
		if as == "auto" {
			return nil, nil
		}
		return nil, err
	}

	content := pv.PasteContent{Title: filepath.Base(path), Body: string(data)}
	if pv.IsEnvFileName(path) {
		content.LanguageHint = "bash"
	}
	candidate := &pasteInput{content: content, fromFile: path}

	if as == "auto" {
		size, err := pv.PasteEncryptedSize(applyPasteOptions(content, putOptions{}))
		if err != nil || size > maxPasteBytes {
			return nil, nil
		}
	}

	return candidate, nil
}

// applyPasteOptions fills render mode, language and title from flags, the
// way the web app builds PasteContent: a language hint implies plain.
func applyPasteOptions(content pv.PasteContent, options putOptions) pv.PasteContent {
	if options.title != "" {
		content.Title = options.title
	}
	content.Title = strings.TrimSpace(content.Title)

	if options.language != "" {
		content.LanguageHint = options.language
	}
	switch {
	case options.format == pv.RenderModeMarkdown:
		content.RenderMode = pv.RenderModeMarkdown
		content.LanguageHint = ""
	default:
		content.RenderMode = pv.RenderModePlain
	}

	return content
}

func fetchCapabilities(ctx context.Context, client *pv.Client) (pv.CapabilitiesResponse, error) {
	capabilities, err := client.GetCapabilities(ctx)
	if pv.IsStatus(err, 404) {
		// Servers from before capabilities existed: no optional features.
		return pv.CapabilitiesResponse{}, nil
	}

	return capabilities, err
}

func checkShareLimits(capabilities pv.CapabilitiesResponse, maxViews int) error {
	if maxViews > 1 && !capabilities.Features.MaxViews {
		return pv.UnsupportedError("this server does not support --max-views above 1; update the server or use --burn")
	}
	if limit := capabilities.Limits.MaxViews; limit > 0 && maxViews > limit {
		return pv.UsageError("--max-views is above this server's limit of %d", limit)
	}

	return nil
}

func createPaste(
	ctx context.Context,
	client *pv.Client,
	out *output,
	paste *pasteInput,
	options putOptions,
	encryption pv.FileShareEncryption,
	expiry pv.ExpiryFields,
	maxPasteBytes int,
	server string,
) (putOutput, error) {
	content := applyPasteOptions(paste.content, options)

	size, err := pv.PasteEncryptedSize(content)
	if err != nil {
		return putOutput{}, err
	}
	if size > maxPasteBytes {
		hint := "split it, or share it as a file"
		if paste.fromFile != "" {
			hint = "share it with --as files"
		}
		return putOutput{}, pv.NewError(pv.ExitUsage, pv.CodeTooLarge, "the paste is %d bytes encrypted but the server limit is %d bytes; %s", size, maxPasteBytes, hint)
	}

	slug, err := pv.GeneratePasteSlug()
	if err != nil {
		return putOutput{}, err
	}
	ciphertext, nonce, err := pv.EncryptPaste(content, encryption.Key, slug)
	if err != nil {
		return putOutput{}, err
	}

	out.infof("Creating paste %s", slug)
	response, err := client.CreatePaste(ctx, pv.CreatePasteRequest{
		Ciphertext:       ciphertext,
		Nonce:            nonce,
		Slug:             slug,
		Salt:             encryption.Salt,
		KDFParams:        encryption.KDFParams,
		ExpiresInHours:   expiry.Hours,
		ExpiresInMinutes: expiry.Minutes,
		BurnAfterRead:    options.maxViews == 1,
		MaxViews:         maxViewsField(options.maxViews),
	})
	if err != nil {
		return putOutput{}, err
	}

	key := shareURLKey(encryption, options)
	return putOutput{
		Slug:              response.Slug,
		Kind:              string(pv.ShareKindPaste),
		URL:               pv.BuildPasteURL(pv.ResolvePublicBaseURL(server), response.Slug, key),
		KeyInURL:          len(key) > 0,
		ExpiresAt:         optionalString(response.ExpiresAt),
		MaxViews:          resultMaxViews(response.MaxViews, options.maxViews),
		BurnAfterRead:     options.maxViews == 1,
		PasswordProtected: encryption.Salt != "",
	}, nil
}

func createFileShare(
	ctx context.Context,
	client *pv.Client,
	out *output,
	paths []string,
	options putOptions,
	encryption pv.FileShareEncryption,
	expiry pv.ExpiryFields,
	capabilities pv.CapabilitiesResponse,
	server string,
) (putOutput, error) {
	inputs, totalSize, err := pv.ResolveUploadInputs(paths)
	if err != nil {
		return putOutput{}, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot share the files")
	}

	if !capabilities.FileShares.Enabled {
		return putOutput{}, pv.UnsupportedError("file sharing is not enabled on this server")
	}
	if options.maxViews == 1 && !capabilities.FileShares.BurnAfterRead {
		return putOutput{}, pv.UnsupportedError("this server does not support burn-after-read file shares; update the server or omit --burn")
	}
	if len(inputs) > capabilities.FileShares.MaxFiles {
		return putOutput{}, pv.UsageError("share includes %d files but the server limit is %d", len(inputs), capabilities.FileShares.MaxFiles)
	}
	if totalSize > int64(capabilities.FileShares.MaxShareSizeBytes) {
		return putOutput{}, pv.NewError(pv.ExitUsage, pv.CodeTooLarge, "share is %d bytes but the server limit is %d bytes", totalSize, capabilities.FileShares.MaxShareSizeBytes)
	}

	slug, err := pv.GenerateShareSlug(9)
	if err != nil {
		return putOutput{}, err
	}

	out.infof("Creating share %s", slug)
	createResponse, err := client.CreateFileShare(ctx, pv.CreateFileShareRequest{
		Slug:             slug,
		Salt:             encryption.Salt,
		KDFParams:        encryption.KDFParams,
		ExpiresInHours:   expiry.Hours,
		ExpiresInMinutes: expiry.Minutes,
		FileCount:        len(inputs),
		TotalSizeBytes:   totalSize,
		BurnAfterRead:    options.maxViews == 1,
		MaxViews:         maxViewsField(options.maxViews),
	})
	if err != nil {
		return putOutput{}, err
	}
	uploadToken := createResponse.UploadToken

	manifestFiles := make([]pv.FileShareManifestFile, 0, len(inputs))
	for index, input := range inputs {
		fileID, err := pv.GenerateSlug(12)
		if err != nil {
			return putOutput{}, err
		}

		out.infof("Uploading %s (%d/%d)", input.DisplayName, index+1, len(inputs))
		chunks, err := pv.UploadFile(ctx, client, input, encryption.Key, slug, uploadToken, fileID, capabilities.FileShares.ChunkSizeBytes)
		if err != nil {
			return putOutput{}, err
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

	manifestCiphertext, manifestNonce, err := pv.EncryptFileShareManifest(pv.FileShareManifest{
		Version: "v1",
		Files:   manifestFiles,
	}, encryption.Key, slug)
	if err != nil {
		return putOutput{}, err
	}

	if err := client.CompleteFileShare(ctx, slug, uploadToken, pv.CompleteFileShareRequest{
		ManifestCiphertext: manifestCiphertext,
		ManifestNonce:      manifestNonce,
	}); err != nil {
		return putOutput{}, err
	}

	key := shareURLKey(encryption, options)
	fileCount := len(inputs)
	return putOutput{
		Slug:              createResponse.Slug,
		Kind:              string(pv.ShareKindFileShare),
		URL:               pv.BuildFileShareURL(pv.ResolvePublicBaseURL(server), createResponse.Slug, key),
		KeyInURL:          len(key) > 0,
		ExpiresAt:         optionalString(createResponse.ExpiresAt),
		MaxViews:          resultMaxViews(createResponse.MaxViews, options.maxViews),
		BurnAfterRead:     options.maxViews == 1,
		PasswordProtected: encryption.Salt != "",
		FileCount:         &fileCount,
		TotalSizeBytes:    &totalSize,
	}, nil
}

// maxViewsField is the max_views request field: omitted for unlimited, and
// for a single view, which burn_after_read already says (old servers accept it).
func maxViewsField(maxViews int) int {
	if maxViews > 1 {
		return maxViews
	}

	return 0
}

// resultMaxViews prefers the server's answer; old servers don't send one.
func resultMaxViews(fromServer *int, requested int) *int {
	if fromServer != nil {
		return fromServer
	}
	if requested > 0 {
		return &requested
	}

	return nil
}

// shareURLKey is the key that goes into the printed link: none for password
// shares or with --no-key-in-output.
func shareURLKey(encryption pv.FileShareEncryption, options putOptions) []byte {
	if options.noKeyInOutput {
		return nil
	}

	return encryption.ShareKey()
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}

func printPutResult(out *output, result putOutput, encryption pv.FileShareEncryption, options putOptions) error {
	if out.json() {
		return out.emitJSON(result)
	}

	out.printf("%s\n", result.URL)
	if !out.common.quiet {
		switch {
		case result.PasswordProtected:
			out.printf("pastevault get %s --password\n", result.Slug)
		case options.noKeyInOutput:
			out.printf("pastevault get %s --key-file %s\n", result.Slug, options.keyOut)
		default:
			out.printf("pastevault get %s\n", pv.BuildShortShareRef(result.Slug, encryption.ShareKey()))
		}
	}

	if result.PasswordProtected {
		out.infof("Password protection is enabled; recipients also need the password.")
	}
	if options.keyOut != "" {
		out.infof("Share key written to %s", options.keyOut)
	}
	switch {
	case result.MaxViews != nil && *result.MaxViews == 1:
		out.infof("Burn after reading is enabled; the share is destroyed the first time it is opened.")
	case result.MaxViews != nil:
		out.infof("The share is destroyed after %d views.", *result.MaxViews)
	}
	if result.ExpiresAt != nil {
		out.infof("Expires %s", *result.ExpiresAt)
	}

	return nil
}
