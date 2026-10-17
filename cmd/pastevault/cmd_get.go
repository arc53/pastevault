package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/store"
)

// getOutput is the --json result of get. Content is only included with
// --stdout (pastes), so secrets don't end up in logs by accident.
type getOutput struct {
	Slug         string  `json:"slug"`
	Kind         string  `json:"kind"`
	Title        *string `json:"title,omitempty"`
	RenderMode   string  `json:"render_mode,omitempty"`
	LanguageHint string  `json:"language_hint,omitempty"`
	SizeBytes    int64   `json:"size_bytes"`
	WrittenTo    string  `json:"written_to,omitempty"`
	// SavedAs is the pv://secret handle of a share saved with --save.
	SavedAs        string        `json:"saved_as,omitempty"`
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
	// saveAs stores the content in the local store (--save NAME).
	saveAs    string
	saveStore *store.Store
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
	totalSizeBytes        int64
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
	overwrite := fs.Bool("overwrite", false, "Replace existing files (or, with --save, an existing secret)")
	saveAs := fs.String("save", "", "Save the content in the local store as NAME (use it as pv://secret/NAME with run and inject)")

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
		saveAs:    *saveAs,
	}
	destinations := 0
	for _, set := range []bool{options.toStdout, options.outFile != "", options.outDir != "", options.saveAs != ""} {
		if set {
			destinations++
		}
	}
	if destinations > 1 {
		return pv.UsageError("use only one of --stdout, -o, --out and --save")
	}
	if options.saveAs != "" {
		// The store belongs to the default agent of the configured server.
		// Checked before anything is opened.
		if !pv.ValidSecretName(options.saveAs) {
			return pv.UsageError("invalid --save name %q (letters, digits, _ . -, starting with a letter or _, at most 128)", options.saveAs)
		}
		identity, err := resolveLocalAgent(common.server, "")
		if err != nil {
			return err
		}
		if options.saveStore, err = store.Open(common.server, identity); err != nil {
			return err
		}
		if err := options.saveStore.CheckWritable(options.saveAs, options.overwrite); err != nil {
			return err
		}
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
	credential, err := pv.AttachCredentials(client, common.server)
	if err != nil {
		return err
	}

	// Look before opening: opening consumes a view (the last one burns the
	// share), so everything that can fail must fail first.
	meta, err := lookupShareMeta(ctx, client, ref)
	if err != nil && credential.IsAPIToken() && isInvalidToken(err) {
		// A public share doesn't need the token; a bad one shouldn't block
		// it. Sealed shares that need an account fail below without it.
		out.warnf("the %s is invalid (revoked, expired or unknown); continuing without it", describeCredential(credential))
		client.SetAuthToken("")
		meta, err = lookupShareMeta(ctx, client, ref)
	}
	if err != nil {
		return err
	}

	if meta.recipient != nil {
		// A sealed link never carries a key and never has a password (put
		// prints neither, the server refuses salt with a recipient). A server
		// claiming that a link with a key is sealed could otherwise make this
		// agent accept content wrapped to it by anyone, instead of content
		// that only the link's key decrypts: refuse before consuming.
		if len(ref.Key) > 0 || options.password.Requested() || meta.passwordProtected {
			return pv.NewError(pv.ExitDecrypt, pv.CodeSealedConflict, "the server claims this share is sealed to agent key %s, but the link carries a key or the share a password; a sealed share has neither. Refusing to open it (possible tampering); nothing was opened", meta.recipient.Fingerprint)
		}

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
		options.sealedTo = identity
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

	switch meta.kind {
	case pv.ShareKindPaste:
		return getPaste(ctx, a, out, client, ref, derivedKey, password, options)
	case pv.ShareKindUnknown:
		// It may turn out to be a paste, so the same rule as above applies.
		if out.json() && destinations == 0 && len(ref.Key) > 0 {
			return pv.UsageError("with --json, choose where the paste goes: --stdout (adds it to the JSON as content), -o FILE or --out DIR")
		}
		return getLegacyShare(ctx, a, out, client, ref, meta, password, options)
	}

	return getFileShare(ctx, a, out, client, ref, meta, derivedKey, password, options)
}

// getLegacyShare opens a slug of unknown kind on a server without /meta
// endpoints. With a key, pastes are tried first: a missing paste answers 404
// without consuming anything, and an existing one is delivered (its view is
// used either way). Without a key (password only) only file shares are
// tried, as before /meta existed, so a paste is never opened that could not
// be decrypted.
func getLegacyShare(ctx context.Context, a *app, out *output, client *pv.Client, ref pv.ShareReference, meta shareMeta, password string, options getOptions) error {
	if len(ref.Key) > 0 {
		paste, err := client.GetPaste(ctx, ref.Slug)
		if err == nil {
			return deliverPaste(a, out, ref, paste, nil, password, options)
		}
		if !pv.IsStatus(err, 404) {
			return err
		}
	}

	// Now known to be a file share (or missing): file-share checks before
	// it is opened.
	meta.kind = pv.ShareKindFileShare
	if out.json() && options.toStdout {
		return pv.UsageError("--stdout with --json is only supported for pastes; use -o FILE or --out DIR")
	}
	if err := checkGetDestination(meta, options); err != nil {
		return err
	}

	return getFileShare(ctx, a, out, client, ref, meta, nil, password, options)
}

func isInvalidToken(err error) bool {
	var apiErr *pv.APIRequestError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 401 && apiErr.ErrorCode == "invalid_token"
}

func describeCredential(source pv.CredentialSource) string {
	if source == pv.CredentialEnvToken {
		return pv.EnvToken + " token"
	}

	return "stored API token"
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
			totalSizeBytes:    parseSize(fileMeta.TotalSizeBytes),

			requiresRecipientAuth: fileMeta.RequiresRecipientAuth,
		}, nil
	case pv.IsStatus(err, 404) && ref.Kind == pv.ShareKindUnknown:
		// No paste and no file share meta: missing, or a server without
		// /meta endpoints (getLegacyShare).
		return shareMeta{kind: pv.ShareKindUnknown, lookupErr: err}, nil
	case pv.IsStatus(err, 404):
		return shareMeta{kind: pv.ShareKindFileShare, lookupErr: err}, nil
	default:
		return shareMeta{}, err
	}
}

func checkGetDestination(meta shareMeta, options getOptions) error {
	if meta.kind == pv.ShareKindFileShare && (options.toStdout || options.outFile != "" || options.saveAs != "") {
		flagName := "--stdout"
		switch {
		case options.outFile != "":
			flagName = "-o"
		case options.saveAs != "":
			flagName = "--save"
		}
		if meta.known && meta.fileCount != 1 {
			return pv.UsageError("%s needs a share with exactly one file; this one has %d (use --out DIR)", flagName, meta.fileCount)
		}
	}
	if options.saveAs != "" {
		if meta.totalSizeBytes > store.MaxValueBytes {
			return pv.UsageError("--save takes at most %d bytes; this share has %d (use -o FILE)", store.MaxValueBytes, meta.totalSizeBytes)
		}
		return nil
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

	return deliverPaste(a, out, ref, paste, key, password, options)
}

// deliverPaste decrypts an opened paste and writes it out.
func deliverPaste(a *app, out *output, ref pv.ShareReference, paste pv.GetPasteResponse, key []byte, password string, options getOptions) error {
	var err error
	if options.sealedTo != nil {
		key, err = unwrapShareKey(options.sealedTo, paste.WrappedKey, paste.RecipientFingerprint, pv.PasteWrapContext(ref.Slug))
		if err != nil {
			return err
		}
	} else if key == nil {
		if paste.Salt != "" && password == "" && a.stdinIsTerminal() {
			// Only on servers without /meta: the paste turned out to be
			// password-protected after it was opened.
			if password, err = a.promptPassword("Password: "); err != nil {
				return err
			}
		}
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
	case options.saveAs != "":
		payload, err := pv.NewTextPayload(options.saveAs, []byte(content.Body))
		if err != nil {
			return err
		}
		if result.SavedAs, err = saveToStore(options, payload, ref.Slug); err != nil {
			return err
		}
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
	if result.SavedAs != "" {
		reportSaved(a, out, result.SavedAs)
	}

	return nil
}

// saveToStore seals payload into the local store (get --save). source never
// carries the share key.
func saveToStore(options getOptions, payload pv.SecretPayload, slug string) (string, error) {
	entry, err := options.saveStore.Put(options.saveAs, payload, store.Source{Type: store.SourceShare, Ref: slug}, options.overwrite)
	if err != nil {
		return "", err
	}

	return entry.Handle(), nil
}

func reportSaved(a *app, out *output, handle string) {
	out.infof("Saved in the local store; use it with pastevault run or inject:")
	fmt.Fprintln(a.stdout, handle)
}

func parseSize(value string) int64 {
	size, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}

	return size
}

// limitedBuffer collects at most limit bytes and fails beyond that.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, pv.NewError(pv.ExitUsage, pv.CodeTooLarge, "the file is larger than %d bytes, the --save limit", b.limit)
	}

	return b.Buffer.Write(p)
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

	if options.toStdout || options.outFile != "" || options.saveAs != "" {
		if len(manifest.Files) != 1 {
			return pv.UsageError("the share has %d files; use --out DIR", len(manifest.Files))
		}
		if manifest.Paste != nil {
			out.warnf("the share's note is not written with --stdout or -o; use --out DIR to save it")
		}
		fileEntry := manifest.Files[0]
		result.Files = []getFileInfo{{Name: fileEntry.Name, Size: fileEntry.Size}}
		result.SizeBytes = fileEntry.Size

		if options.saveAs != "" {
			buffer := &limitedBuffer{limit: store.MaxValueBytes}
			if err := pv.DownloadFileTo(ctx, client, fileEntry, key, share.Metadata.Slug, share.DownloadGrant, buffer); err != nil {
				return err
			}
			contentType := mime.TypeByExtension(filepath.Ext(fileEntry.Name))
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			payload := pv.NewFilePayload(options.saveAs, fileEntry.Name, contentType, buffer.Bytes())
			if result.SavedAs, err = saveToStore(options, payload, ref.Slug); err != nil {
				return err
			}
			if !out.json() {
				reportSaved(a, out, result.SavedAs)
			}
		} else if options.outFile != "" {
			target, err := downloadToFile(ctx, out, client, fileEntry, key, share, options)
			if err != nil {
				return err
			}
			result.WrittenTo = target
			result.Files[0].Path = target
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

	// The share has been opened, so its view is used: a name clash must not
	// throw that away. Without --overwrite, clashing files are saved as
	// "name (1).ext" instead.
	plan, err := pv.PlanDownload(manifest, targetDir, options.overwrite, true)
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
func downloadToFile(ctx context.Context, out *output, client *pv.Client, fileEntry pv.FileShareManifestFile, key []byte, share pv.GetFileShareResponse, options getOptions) (string, error) {
	target := options.outFile
	file, err := pv.CreatePrivateFile(target, options.overwrite)
	if errors.Is(err, os.ErrExist) {
		// The file appeared after the pre-open check; the share is already
		// opened, so save next to it instead of losing the view.
		if target, err = choosePasteTarget(filepath.Dir(options.outFile), filepath.Base(options.outFile), false); err == nil {
			out.warnf("%s appeared meanwhile; saving as %s", options.outFile, target)
			file, err = pv.CreatePrivateFile(target, false)
		}
	}
	if err != nil {
		return "", pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "could not write %s", target)
	}

	writeErr := pv.DownloadFileTo(ctx, client, fileEntry, key, share.Metadata.Slug, share.DownloadGrant, file)
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(target)
		return "", writeErr
	}

	return target, nil
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
