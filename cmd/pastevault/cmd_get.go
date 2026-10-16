package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

// getOutput is the --json result of get. Content is only included with
// --stdout (pastes), so secrets don't end up in logs by accident.
type getOutput struct {
	Slug           string        `json:"slug"`
	Kind           string        `json:"kind"`
	Title          *string       `json:"title,omitempty"`
	RenderMode     string        `json:"render_mode,omitempty"`
	LanguageHint   string        `json:"language_hint,omitempty"`
	SizeBytes      int64         `json:"size_bytes"`
	WrittenTo      string        `json:"written_to,omitempty"`
	Files          []getFileInfo `json:"files,omitempty"`
	ViewCount      int           `json:"view_count"`
	MaxViews       *int          `json:"max_views"`
	ViewsRemaining *int          `json:"views_remaining"`
	Burned         bool          `json:"burned"`
	ExpiresAt      *string       `json:"expires_at"`
	// Recipient is the local agent key that opened a sealed share.
	Recipient *putRecipient `json:"recipient,omitempty"`
	Content   *string       `json:"content,omitempty"`
}

type getFileInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Path string `json:"path,omitempty"`
}

type getOptions struct {
	toStdout  bool
	outFile   string
	outDir    string
	overwrite bool
	password  pv.PasswordSource
	// sealedTo is the local agent key a sealed share is opened with.
	sealedTo *pv.AgentIdentity
}

// shareMeta is what get learns before it consumes a view.
type shareMeta struct {
	kind              pv.ShareKind
	known             bool // false when the server has no meta endpoint
	passwordProtected bool
	salt              string
	kdfParams         string
	viewsRemaining    *int
	recipient         *pv.RecipientMeta
	// requiresRecipientAuth: only the recipient agent's account may open it.
	requiresRecipientAuth bool
	fileCount             int
	// lookupErr is the 404 from the meta endpoints when known is false.
	lookupErr error
}

func runGet(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("get", "pastevault get [flags] <url | slug#k=KEY | slug | pv://share/SLUG>")
	keyFlag := fs.String("key", "", "Deprecated: base64url share key (visible in the process list; use --key-file, --key-env or --key-stdin)")
	keyFile := fs.String("key-file", "", "Read the share key from this file")
	keyEnv := fs.String("key-env", "", "Read the share key from this environment variable")
	keyStdin := fs.Bool("key-stdin", false, "Read the share key from stdin")
	passwordPrompt := fs.Bool("password", false, "Prompt for the share password")
	passwordFile := fs.String("password-file", "", "Read the share password from this file")
	toStdout := fs.Bool("stdout", false, "Write the content to stdout (pastes, or a share with one file)")
	outFile := fs.String("o", "", "Write the paste (or the only file of a share) to this file (mode 0600)")
	fs.StringVar(outFile, "output", "", "Same as -o")
	outDir := fs.String("out", "", "Write into this directory (file shares default to the current directory)")
	overwrite := fs.Bool("overwrite", false, "Replace existing files")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("exactly one share URL, slug or handle is required")
	}

	options := getOptions{
		toStdout:  *toStdout,
		outFile:   *outFile,
		outDir:    *outDir,
		overwrite: *overwrite,
		password:  pv.PasswordSource{Prompt: *passwordPrompt, File: *passwordFile},
	}
	destinations := 0
	for _, set := range []bool{options.toStdout, options.outFile != "", options.outDir != ""} {
		if set {
			destinations++
		}
	}
	if destinations > 1 {
		return pv.UsageError("use only one of --stdout, -o and --out")
	}

	ref, err := pv.ParseShareReference(positional[0], common.server, pv.ResolvePublicBaseURL(common.server))
	if err != nil {
		return err
	}
	if *keyFlag != "" {
		out.warnf("--key exposes the share key in the process list and shell history; prefer --key-file, --key-env or --key-stdin")
	}
	key, err := pv.ReadShareKey(pv.KeySource{Flag: *keyFlag, File: *keyFile, Env: *keyEnv, Stdin: *keyStdin}, a.stdin)
	if err != nil {
		return err
	}
	if key != nil {
		ref.Key = key
	}

	client, err := newClient(ref.Server)
	if err != nil {
		return err
	}
	// Credentials identify the reader (audit) and prove a sealed share's
	// recipient account (recipient auth).
	// PASTEVAULT_TOKEN is only sent to the configured server.
	if _, err := pv.AttachCredentials(client, common.server); err != nil {
		return err
	}

	// Look before opening: opening consumes a view (the last one burns the
	// share), so everything that can fail must fail first.
	meta, err := lookupShareMeta(ctx, client, ref)
	if err != nil {
		return err
	}

	if meta.recipient != nil {
		// Only the agent holding the matching private key can open it. That
		// is checked here, before a view is consumed.
		identity, err := pv.FindIdentityByFingerprint(ref.Server, meta.recipient.Fingerprint)
		if err != nil {
			return err
		}
		if identity == nil {
			return pv.NewError(pv.ExitDecrypt, pv.CodeSealedShare, "this share is sealed to the agent key %s, which matches no agent key on this machine (pastevault agent list); nothing was opened", meta.recipient.Fingerprint)
		}
		if meta.requiresRecipientAuth && !client.HasAuthToken() {
			return pv.NewError(pv.ExitAuth, pv.CodeAuth, "this share is sealed to agent %s of an account and can only be opened signed in to that account: run pastevault login, or set PASTEVAULT_TOKEN (scope shares:receive); nothing was opened", pv.ShortFingerprint(identity.Fingerprint))
		}
		if len(ref.Key) > 0 || options.password.Requested() {
			out.warnf("the share is sealed to an agent key; the given key or password is not used")
		}
		options.sealedTo = identity
		ref.Key = nil
	}

	if meta.kind == pv.ShareKindPaste && out.json() && destinations == 0 {
		return pv.UsageError("with --json, choose where the paste goes: --stdout (adds it to the JSON as content), -o FILE or --out DIR")
	}
	if meta.kind == pv.ShareKindFileShare && out.json() && options.toStdout {
		return pv.UsageError("--stdout with --json is only supported for pastes; use -o FILE or --out DIR")
	}
	if err := checkGetDestination(meta, options); err != nil {
		return err
	}

	password := ""
	if options.sealedTo == nil && (!meta.known || meta.passwordProtected) {
		promptAllowed := options.password.Prompt || (meta.passwordProtected && a.stdinIsTerminal() && !*keyStdin)
		password, err = pv.ResolvePassword(pv.PasswordSource{Prompt: promptAllowed, File: options.password.File}, a.stdinIsTerminal(), a.promptPassword)
		if err != nil {
			return err
		}
	}

	// A sealed share's key is unwrapped from the opened share instead.
	var derivedKey []byte
	switch {
	case options.sealedTo != nil:
	case meta.known:
		derivedKey, err = pv.DerivePasteKey(ref.Key, meta.salt, meta.kdfParams, password)
		if err != nil {
			return err
		}
	case len(ref.Key) == 0 && password == "":
		// Either the share does not exist, or the server predates /meta and
		// nothing could decrypt it anyway: report the 404 without opening.
		return meta.lookupErr
	}

	if meta.viewsRemaining != nil && *meta.viewsRemaining == 1 {
		out.infof("This share burns after reading; opening it now destroys it on the server.")
	}

	if meta.kind == pv.ShareKindPaste {
		return getPaste(ctx, a, out, client, ref, derivedKey, password, options)
	}

	return getFileShare(ctx, a, out, client, ref, meta, derivedKey, password, options)
}

// lookupShareMeta fetches the non-consuming metadata. A reference without a
// kind (bare slug, pv://share) tries pastes first, then file shares. Servers
// without /meta endpoints answer 404; file shares then fall back to the old
// flow (and a missing share still reports 404 when opened).
func lookupShareMeta(ctx context.Context, client *pv.Client, ref pv.ShareReference) (shareMeta, error) {
	if ref.Kind != pv.ShareKindFileShare {
		pasteMeta, err := client.GetPasteMeta(ctx, ref.Slug)
		switch {
		case err == nil:
			return shareMeta{
				kind:              pv.ShareKindPaste,
				known:             true,
				passwordProtected: pasteMeta.PasswordProtected || pasteMeta.Salt != "",
				salt:              pasteMeta.Salt,
				kdfParams:         pasteMeta.KDFParams,
				viewsRemaining:    pasteMeta.ViewsRemaining,
				recipient:         pasteMeta.Recipient,

				requiresRecipientAuth: pasteMeta.RequiresRecipientAuth,
			}, nil
		case !pv.IsStatus(err, 404):
			return shareMeta{}, err
		case ref.Kind == pv.ShareKindPaste:
			return shareMeta{kind: pv.ShareKindPaste, lookupErr: err}, nil
		}
	}

	fileMeta, err := client.GetFileShareMeta(ctx, ref.Slug)
	switch {
	case err == nil:
		return shareMeta{
			kind:              pv.ShareKindFileShare,
			known:             true,
			passwordProtected: fileMeta.PasswordProtected || fileMeta.Salt != "",
			salt:              fileMeta.Salt,
			kdfParams:         fileMeta.KDFParams,
			viewsRemaining:    fileMeta.ViewsRemaining,
			recipient:         fileMeta.Recipient,
			fileCount:         fileMeta.FileCount,

			requiresRecipientAuth: fileMeta.RequiresRecipientAuth,
		}, nil
	case pv.IsStatus(err, 404):
		return shareMeta{kind: pv.ShareKindFileShare, lookupErr: err}, nil
	default:
		return shareMeta{}, err
	}
}

func checkGetDestination(meta shareMeta, options getOptions) error {
	if meta.kind == pv.ShareKindFileShare && (options.toStdout || options.outFile != "") {
		flagName := "--stdout"
		if options.outFile != "" {
			flagName = "-o"
		}
		if meta.known && meta.fileCount != 1 {
			return pv.UsageError("%s needs a share with exactly one file; this one has %d (use --out DIR)", flagName, meta.fileCount)
		}
	}

	switch {
	case options.outFile != "":
		return pv.CheckWritableTarget(options.outFile, options.overwrite)
	case options.outDir != "":
		return ensureWritableDir(options.outDir)
	case meta.kind == pv.ShareKindFileShare && !options.toStdout:
		return ensureWritableDir(".")
	}

	return nil
}

func ensureWritableDir(dir string) error {
	if err := pv.EnsureWritableDir(dir); err != nil {
		return pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot write to %s", dir)
	}

	return nil
}

func getPaste(
	ctx context.Context,
	a *app,
	out *output,
	client *pv.Client,
	ref pv.ShareReference,
	key []byte,
	password string,
	options getOptions,
) error {
	paste, err := client.GetPaste(ctx, ref.Slug)
	if err != nil {
		return err
	}

	if options.sealedTo != nil {
		key, err = unwrapShareKey(options.sealedTo, paste.WrappedKey, paste.RecipientFingerprint, pv.PasteWrapContext(ref.Slug))
		if err != nil {
			return err
		}
	} else if key == nil {
		key, err = pv.DerivePasteKey(ref.Key, paste.Salt, paste.KDFParams, password)
		if err != nil {
			return err
		}
	}

	content, err := pv.DecryptPaste(paste.Ciphertext, paste.Nonce, key, paste.Metadata.Slug)
	burned := paste.Metadata.IsBurned
	// A burned paste only exists in memory now, so allow password retries on
	// a terminal instead of losing it to a typo.
	for attempt := 1; err != nil && paste.Salt != "" && burned && attempt < 3 && a.stdinIsTerminal(); attempt++ {
		fmt.Fprintln(a.stderr, "Incorrect password. The paste has already been opened and destroyed on the server; try again.")
		password, err = a.promptPassword("Password: ")
		if err != nil {
			return err
		}
		key, err = pv.DerivePasteKey(nil, paste.Salt, paste.KDFParams, password)
		if err != nil {
			continue
		}
		content, err = pv.DecryptPaste(paste.Ciphertext, paste.Nonce, key, paste.Metadata.Slug)
	}
	if err != nil {
		return err
	}

	result := getOutput{
		Slug:           paste.Metadata.Slug,
		Kind:           string(pv.ShareKindPaste),
		Title:          &content.Title,
		RenderMode:     content.RenderMode,
		LanguageHint:   content.LanguageHint,
		SizeBytes:      int64(len(content.Body)),
		ViewCount:      paste.Metadata.ViewCount,
		MaxViews:       paste.Metadata.MaxViews,
		ViewsRemaining: paste.Metadata.ViewsRemaining,
		Burned:         burned,
		ExpiresAt:      optionalString(paste.Metadata.ExpiresAt),
		Recipient:      sealedRecipientOutput(options.sealedTo),
	}

	switch {
	case options.outFile != "":
		if err := pv.WritePrivateFile(options.outFile, []byte(content.Body), options.overwrite); err != nil {
			return err
		}
		result.WrittenTo = options.outFile
	case options.outDir != "":
		target, err := choosePasteTarget(options.outDir, pv.PasteOutputFileName(content, paste.Metadata.Slug), options.overwrite)
		if err != nil {
			return err
		}
		if err := pv.WritePrivateFile(target, []byte(content.Body), options.overwrite); err != nil {
			return err
		}
		result.WrittenTo = target
	case out.json():
		result.Content = &content.Body
	default:
		if _, err := io.WriteString(a.stdout, content.Body); err != nil {
			return err
		}
		if a.stdoutIsTerminal() && !strings.HasSuffix(content.Body, "\n") {
			fmt.Fprintln(a.stdout)
		}
	}

	if out.json() {
		return out.emitJSON(result)
	}
	if result.WrittenTo != "" {
		out.infof("Saved paste %s to %s", result.Slug, result.WrittenTo)
	}

	return nil
}

// choosePasteTarget picks dir/name, or "name (1)" etc. when it exists and
// may not be replaced: the paste may already be burned, so it is never lost
// to a name clash.
func choosePasteTarget(dir, name string, overwrite bool) (string, error) {
	plan, err := pv.PlanDownload(pv.FileShareManifest{Files: []pv.FileShareManifestFile{{ID: "paste", Name: name}}}, dir, overwrite, true)
	if err != nil {
		return "", err
	}

	return plan.FilePaths[0], nil
}

func getFileShare(
	ctx context.Context,
	a *app,
	out *output,
	client *pv.Client,
	ref pv.ShareReference,
	meta shareMeta,
	key []byte,
	password string,
	options getOptions,
) error {
	share, err := client.GetFileShare(ctx, ref.Slug)
	if err != nil {
		return err
	}

	if options.sealedTo != nil {
		key, err = unwrapShareKey(options.sealedTo, share.WrappedKey, share.RecipientFingerprint, pv.FileShareWrapContext(ref.Slug))
		if err != nil {
			return err
		}
	} else if key == nil {
		key, err = pv.DerivePasteKey(ref.Key, share.Salt, share.KDFParams, password)
		if err != nil {
			return err
		}
	}

	burned := share.Metadata.IsBurned || share.DownloadGrant != ""
	manifest, err := pv.DecryptFileShareManifest(share.ManifestCiphertext, share.ManifestNonce, key, share.Metadata.Slug)
	for attempt := 1; err != nil && share.Salt != "" && burned && attempt < 3 && a.stdinIsTerminal(); attempt++ {
		fmt.Fprintln(a.stderr, "Incorrect password. The share has already been opened and destroyed on the server; try again.")
		password, err = a.promptPassword("Password: ")
		if err != nil {
			return err
		}
		key, err = pv.DerivePasteKey(nil, share.Salt, share.KDFParams, password)
		if err != nil {
			continue
		}
		manifest, err = pv.DecryptFileShareManifest(share.ManifestCiphertext, share.ManifestNonce, key, share.Metadata.Slug)
	}
	if err != nil {
		return pv.DecryptError("could not decrypt the share: wrong key or password, or the content was tampered with")
	}

	result := getOutput{
		Slug:           share.Metadata.Slug,
		Kind:           string(pv.ShareKindFileShare),
		ViewCount:      share.Metadata.ViewCount,
		MaxViews:       share.Metadata.MaxViews,
		ViewsRemaining: share.Metadata.ViewsRemaining,
		Burned:         burned,
		ExpiresAt:      optionalString(share.Metadata.ExpiresAt),
		Recipient:      sealedRecipientOutput(options.sealedTo),
	}

	if options.toStdout || options.outFile != "" {
		if len(manifest.Files) != 1 {
			return pv.UsageError("the share has %d files; use --out DIR", len(manifest.Files))
		}
		if manifest.Paste != nil {
			out.warnf("the share's note is not written with --stdout or -o; use --out DIR to save it")
		}
		fileEntry := manifest.Files[0]
		result.Files = []getFileInfo{{Name: fileEntry.Name, Size: fileEntry.Size}}
		result.SizeBytes = fileEntry.Size

		if options.outFile != "" {
			if err := downloadToFile(ctx, client, fileEntry, key, share, options); err != nil {
				return err
			}
			result.WrittenTo = options.outFile
			result.Files[0].Path = options.outFile
		} else {
			// runGet refused --stdout with --json for file shares, so file
			// bytes never mix with the JSON object.
			if err := pv.DownloadFileTo(ctx, client, fileEntry, key, share.Metadata.Slug, share.DownloadGrant, a.stdout); err != nil {
				return err
			}
		}

		if out.json() {
			return out.emitJSON(result)
		}
		return nil
	}

	targetDir := options.outDir
	targetDescription := targetDir
	if targetDir == "" {
		targetDir = "."
		targetDescription = "current directory"
	}

	// A burned share gets no second chance, so name clashes are resolved by
	// renaming instead of aborting.
	plan, err := pv.PlanDownload(manifest, targetDir, options.overwrite, burned)
	if err != nil {
		return pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot save the share")
	}
	for _, renamed := range plan.Renamed {
		out.infof("%s already exists; saving as %s", renamed.From, renamed.To)
	}

	out.infof("Downloading share %s into %s", share.Metadata.Slug, targetDescription)
	if err := pv.DownloadManifest(ctx, client, manifest, key, share.Metadata.Slug, share.DownloadGrant, plan); err != nil {
		return err
	}

	for index, fileEntry := range manifest.Files {
		result.Files = append(result.Files, getFileInfo{Name: fileEntry.Name, Size: fileEntry.Size, Path: plan.FilePaths[index]})
		result.SizeBytes += fileEntry.Size
	}
	result.WrittenTo = targetDir

	if out.json() {
		return out.emitJSON(result)
	}

	return nil
}

// downloadToFile streams the only file of a share into a new private file.
// A partial file is removed on failure.
func downloadToFile(ctx context.Context, client *pv.Client, fileEntry pv.FileShareManifestFile, key []byte, share pv.GetFileShareResponse, options getOptions) error {
	file, err := pv.CreatePrivateFile(options.outFile, options.overwrite)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "%s already exists; remove it first or pass --overwrite", options.outFile)
		}
		return pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "could not write %s", options.outFile)
	}

	writeErr := pv.DownloadFileTo(ctx, client, fileEntry, key, share.Metadata.Slug, share.DownloadGrant, file)
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(options.outFile)
	}

	return writeErr
}

// unwrapShareKey opens a sealed share's wrapped key with the local agent key.
// The context binds it to the slug that was asked for, so the server can't
// hand over another share's envelope.
func unwrapShareKey(identity *pv.AgentIdentity, wrappedKey, recipientFingerprint, context string) ([]byte, error) {
	if wrappedKey == "" {
		return nil, pv.DecryptError("the server returned the sealed share without its wrapped key")
	}
	if recipientFingerprint != "" && recipientFingerprint != identity.Fingerprint {
		return nil, pv.DecryptError("the share is sealed to %s, not to this agent (%s)", recipientFingerprint, identity.Fingerprint)
	}

	key, err := pv.UnwrapKey(wrappedKey, identity.Keys().PrivateKey, context)
	if err != nil {
		return nil, pv.DecryptError("could not unwrap the share key with agent key %s: it was sealed to another key or tampered with", pv.ShortFingerprint(identity.Fingerprint))
	}

	return key, nil
}

func sealedRecipientOutput(identity *pv.AgentIdentity) *putRecipient {
	if identity == nil {
		return nil
	}

	return &putRecipient{Name: identity.Name, Fingerprint: identity.Fingerprint}
}
