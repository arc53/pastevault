package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/secrets"
)

// Secret requests (spec §5.3, §6):
//
//	pastevault request NAME [--why TEXT] [--ttl 10m] [--accept text|file|any] [--save-as NAME] [--wait]
//	pastevault await <id|code>
//	pastevault request list | cancel <id|code> | fulfil <code|url> | decline <code|url>
func runRequest(ctx context.Context, a *app, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "list":
			return runRequestList(ctx, a, args[1:])
		case "cancel":
			return runRequestCancel(ctx, a, args[1:])
		case "fulfil", "fulfill":
			return runRequestFulfil(ctx, a, args[1:])
		case "decline":
			return runRequestDecline(ctx, a, args[1:])
		}
	}

	return runRequestCreate(ctx, a, args)
}

// requestOutput is the --json result of request and await.
type requestOutput struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	SaveAs      string `json:"save_as"`
	Agent       string `json:"agent,omitempty"`
	ExpiresAt   string `json:"expires_at"`
	// Status is the request status; "delivered" once the answer is stored.
	Status string `json:"status"`
	Handle string `json:"handle,omitempty"`
}

func newRequestOutput(pending *pv.PendingRequest, status string) requestOutput {
	return requestOutput{
		ID:          pending.ID,
		Code:        pending.Code,
		URL:         pending.URL,
		Fingerprint: pending.Fingerprint,
		Name:        pending.Name,
		SaveAs:      pending.SaveAs,
		Agent:       pending.Agent,
		ExpiresAt:   pending.ExpiresAt,
		Status:      status,
	}
}

// requireSecretRequests checks the server supports secret requests (exit 14).
func requireSecretRequests(ctx context.Context, server string) (pv.CapabilitiesResponse, error) {
	probe, err := newClient(server)
	if err != nil {
		return pv.CapabilitiesResponse{}, err
	}
	capabilities, err := fetchCapabilities(ctx, probe)
	if err != nil {
		return capabilities, err
	}
	if !capabilities.Auth.Enabled || !capabilities.Features.SecretRequests {
		return capabilities, pv.UnsupportedError("%s does not support secret requests (it is too old, or accounts are disabled)", probe.BaseURL())
	}

	return capabilities, nil
}

func runRequestCreate(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("request", "pastevault request NAME [--why TEXT] [--ttl 10m] [--accept text|file|any] [--save-as NAME] [--wait [--timeout D]] [flags]\n  pastevault request list | cancel <id|code> | fulfil <code|url> | decline <code|url>")
	why := fs.String("why", "", "Why the secret is needed (shown to the human, marked as untrusted)")
	ttl := fs.String("ttl", "10m", "How long the request stays open, e.g. 5m, 2h (server minimum applies; at most 24h)")
	accept := fs.String("accept", pv.SecretKindText, "What the human may send: text, file or any")
	saveAs := fs.String("save-as", "", "Store the answer as this name (default NAME)")
	agentName := fs.String("agent", "", "Agent to request as (default: the default agent)")
	wait := fs.Bool("wait", false, "Wait for the answer, store it and print its pv://secret handle")
	timeout := fs.String("timeout", "", "With --wait: give up after this long (exit 9; default: until the request expires)")
	overwrite := fs.Bool("overwrite", false, "Let the answer replace an existing secret of the same name")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("exactly one secret NAME is required, e.g. pastevault request OPENAI_API_KEY --why \"run the evals\"")
	}
	name := positional[0]
	if !pv.ValidSecretName(name) {
		return pv.UsageError("invalid secret name %q (letters, digits, _ . -, starting with a letter or _, at most 128)", name)
	}
	if *saveAs != "" && !pv.ValidSecretName(*saveAs) {
		return pv.UsageError("invalid --save-as name %q", *saveAs)
	}
	switch *accept {
	case pv.SecretKindText, pv.SecretKindFile, pv.AcceptAny:
	default:
		return pv.UsageError("--accept must be text, file or any")
	}
	if utf8.RuneCountInString(*why) > 500 {
		return pv.UsageError("--why is limited to 500 characters")
	}
	ttlDuration, err := pv.ParseWaitDuration("--ttl", *ttl)
	if err != nil {
		return err
	}
	var waitTimeout time.Duration
	if *timeout != "" {
		if !*wait {
			return pv.UsageError("--timeout needs --wait")
		}
		if waitTimeout, err = pv.ParseWaitDuration("--timeout", *timeout); err != nil {
			return err
		}
	}

	identity, err := resolveLocalAgent(common.server, *agentName)
	if err != nil {
		var cliErr *pv.CLIError
		if errors.As(err, &cliErr) && cliErr.Exit == pv.ExitUsage {
			return pv.UsageError("a secret request is made as an agent, and %v", err)
		}
		return err
	}

	capabilities, err := requireSecretRequests(ctx, common.server)
	if err != nil {
		return err
	}
	minimum := time.Duration(capabilities.Limits.MinSecretRequestTTLSeconds) * time.Second
	if minimum <= 0 {
		minimum = time.Minute
	}
	if ttlDuration < minimum || ttlDuration > 24*time.Hour || ttlDuration%time.Second != 0 {
		return pv.UsageError("--ttl must be between %s and 24h on this server", minimum)
	}

	client, _, err := authenticatedClient(ctx, common, true)
	if err != nil {
		return err
	}

	pending, err := secrets.NewRequest(ctx, client, pv.ResolvePublicBaseURL(common.server), identity, secrets.RequestOptions{
		Name:      name,
		SaveAs:    *saveAs,
		Reason:    *why,
		TTL:       ttlDuration,
		Accept:    *accept,
		Overwrite: *overwrite,
	})
	if err != nil {
		return err
	}

	printRequestInstructions(a, out, pending, *wait)
	if !*wait {
		if out.json() {
			return out.emitJSON(newRequestOutput(pending, pv.RequestPending))
		}
		if common.quiet {
			fmt.Fprintln(a.stdout, pending.URL)
		}
		return nil
	}

	return awaitRequest(ctx, a, out, client, pending, waitTimeout)
}

// printRequestInstructions tells the human what to do. Without --wait and
// --json the URL is the command's result (stdout); otherwise it is progress
// (stderr).
func printRequestInstructions(a *app, out *output, pending *pv.PendingRequest, wait bool) {
	urlOnStdout := !wait && !out.json() && !out.common.quiet
	if urlOnStdout {
		fmt.Fprintln(a.stdout, pending.URL)
	}

	notice := a.stderr
	if out.common.quiet && (wait || out.json()) {
		// Even with --quiet the human needs the link.
		fmt.Fprintf(notice, "Open %s\n", pending.URL)
		return
	}
	if out.common.quiet {
		return
	}

	fmt.Fprintf(notice, "Secret request %s for %s (expires %s).\n", pending.Code, pending.Name, formatTime(pending.ExpiresAt))
	if !urlOnStdout {
		fmt.Fprintf(notice, "Open this link signed in to your PasteVault account and enter the value:\n  %s\n", pending.URL)
	} else {
		fmt.Fprintln(notice, "Open the link above signed in to your PasteVault account and enter the value.")
	}
	fmt.Fprintf(notice, "The page must show the request key %s (short: %s).\n", pv.FormatFingerprint(pending.Fingerprint), pv.ShortFingerprint(pending.Fingerprint))
	if !wait {
		fmt.Fprintf(notice, "Then run: pastevault await %s\n", pending.Code)
	}
}

func awaitRequest(ctx context.Context, a *app, out *output, client *pv.Client, pending *pv.PendingRequest, timeout time.Duration) error {
	out.infof("Waiting for the answer (Ctrl-C to stop; resume with pastevault await %s)...", pending.Code)
	outcome, err := secrets.Await(ctx, client, pending, secrets.AwaitOptions{Timeout: timeout})
	if err != nil {
		return err
	}
	if err := secrets.OutcomeError(pending, outcome); err != nil {
		return err
	}

	if outcome.AckErr != nil {
		out.warnf("the secret is stored, but the server was not told (%v); it deletes the answer within two minutes anyway", outcome.AckErr)
	}
	if outcome.Renamed {
		out.warnf("%s already existed in the local store, so the answer was stored as %s instead", pending.SaveAs, outcome.SavedAs)
	}
	if out.json() {
		result := newRequestOutput(pending, pv.RequestDelivered)
		result.Handle = outcome.Handle
		if outcome.SavedAs != "" {
			result.SaveAs = outcome.SavedAs
		}
		return out.emitJSON(result)
	}
	out.infof("Stored %s in the local store. Use it with pastevault run or inject:", outcome.SavedAs)
	fmt.Fprintln(a.stdout, outcome.Handle)

	return nil
}

func runAwait(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("await", "pastevault await <id|code> [--timeout D] [--save-as NAME] [--overwrite] [flags]")
	timeout := fs.String("timeout", "", "Give up after this long (exit 9; default: until the request expires)")
	saveAs := fs.String("save-as", "", "Store the answer under this name instead of the one given to request")
	overwrite := fs.Bool("overwrite", false, "Let the answer replace an existing secret of that name")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("exactly one request id or code is required")
	}
	var waitTimeout time.Duration
	if *timeout != "" {
		if waitTimeout, err = pv.ParseWaitDuration("--timeout", *timeout); err != nil {
			return err
		}
	}

	pending, err := pv.FindPendingRequest(positional[0])
	if err != nil {
		return err
	}
	if pending == nil {
		return pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "this machine has no open request %s (it was answered, cancelled or made elsewhere; pastevault request list)", positional[0])
	}
	if *saveAs != "" || *overwrite {
		if *saveAs != "" {
			if !pv.ValidSecretName(*saveAs) {
				return pv.UsageError("invalid --save-as name %q", *saveAs)
			}
			pending.SaveAs = *saveAs
		}
		pending.Overwrite = pending.Overwrite || *overwrite
		// Remembered for a later await if this one is interrupted.
		if err := pv.SavePendingRequest(pending); err != nil {
			return err
		}
	}

	requestCommon := *common
	requestCommon.server = pending.Server
	client, _, err := authenticatedClient(ctx, &requestCommon, true)
	if err != nil {
		return err
	}

	return awaitRequest(ctx, a, out, client, pending, waitTimeout)
}

type requestListEntry struct {
	pv.SecretRequestSummary
	// Local: this machine holds the request file (can await it).
	Local bool `json:"local"`
}

func runRequestList(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("request list", "pastevault request list [--status S] [flags]")
	status := fs.String("status", "", "Only requests with this status: pending, fulfilled, delivered, declined, expired, cancelled")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 0 {
		return pv.UsageError("request list takes no arguments")
	}

	if _, err := requireSecretRequests(ctx, common.server); err != nil {
		return err
	}
	client, _, err := authenticatedClient(ctx, common, true)
	if err != nil {
		return err
	}
	response, err := client.ListSecretRequests(ctx, *status)
	if err != nil {
		return err
	}

	local := map[string]bool{}
	if pendings, _, err := pv.ListPendingRequests(); err == nil {
		for _, pending := range pendings {
			local[pending.ID] = true
		}
	}

	entries := make([]requestListEntry, 0, len(response.Requests))
	for _, summary := range response.Requests {
		entries = append(entries, requestListEntry{SecretRequestSummary: summary, Local: local[summary.ID]})
	}
	if out.json() {
		return out.emitJSON(map[string]any{"requests": entries})
	}
	if len(entries) == 0 {
		out.infof("No secret requests.")
		return nil
	}

	table := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "CODE\tNAME\tSTATUS\tAGENT\tEXPIRES\tLOCAL")
	for _, entry := range entries {
		agent := "-"
		if entry.Requester.Agent.Name != nil {
			agent = terminalSafe(*entry.Requester.Agent.Name)
		}
		marker := ""
		if entry.Local {
			marker = "*"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", terminalSafe(entry.Code), terminalSafe(entry.Name), terminalSafe(entry.Status), agent, terminalSafe(formatTime(entry.ExpiresAt)), marker)
	}

	return table.Flush()
}

func runRequestCancel(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("request cancel", "pastevault request cancel <id|code>... [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) == 0 {
		return pv.UsageError("at least one request id or code is required")
	}

	if _, err := requireSecretRequests(ctx, common.server); err != nil {
		return err
	}
	client, _, err := authenticatedClient(ctx, common, true)
	if err != nil {
		return err
	}

	type cancelled struct {
		ID     string `json:"id"`
		Code   string `json:"code,omitempty"`
		Status string `json:"status"`
	}
	var results []cancelled
	var listed []pv.SecretRequestSummary
	for _, target := range positional {
		id, code := target, ""
		pending, err := pv.FindPendingRequest(target)
		if err != nil {
			return err
		}
		switch normalized, isCode := pv.NormalizeRequestCode(target); {
		case pending != nil:
			id, code = pending.ID, pending.Code
		case isCode:
			if listed == nil {
				response, err := client.ListSecretRequests(ctx, "")
				if err != nil {
					return err
				}
				listed = response.Requests
			}
			id = ""
			for _, summary := range listed {
				if summary.Code == normalized {
					id, code = summary.ID, summary.Code
				}
			}
			if id == "" {
				return pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "no secret request %s in this account", normalized)
			}
		}

		response, err := client.CancelSecretRequest(ctx, id)
		if err != nil {
			return err
		}
		if pending != nil {
			_ = pv.DeletePendingRequest(pending)
		}
		results = append(results, cancelled{ID: id, Code: code, Status: response.Status})
		if !out.json() {
			out.infof("Cancelled request %s", firstNonEmpty(code, id))
		}
	}

	if out.json() {
		return out.emitJSON(map[string]any{"cancelled": results})
	}

	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

// requestSessionClient returns a client carrying the stored login session.
// Answering or declining a request is session-only on the server: an agent
// (API token) must never be able to answer its own request.
func requestSessionClient(ctx context.Context, common *commonFlags) (*pv.Client, error) {
	if _, err := requireSecretRequests(ctx, common.server); err != nil {
		return nil, err
	}
	client, err := newClient(common.server)
	if err != nil {
		return nil, err
	}
	hasSession, err := pv.AttachStoredAuthToken(client)
	if err != nil {
		return nil, err
	}
	if !hasSession {
		return nil, pv.NewError(pv.ExitAuth, pv.CodeSessionRequired, "answering a secret request needs a browser-approved login session for %s: run pastevault login (API tokens can't answer requests)", client.BaseURL())
	}
	if err := validateSession(ctx, client); err != nil {
		return nil, err
	}

	return client, nil
}

// openRequestForHuman fetches a request by code and checks its key: the
// fingerprint is recomputed from the public key and must match the one from
// the request URL (#fp=) or --fingerprint (exit 8 otherwise).
func openRequestForHuman(ctx context.Context, client *pv.Client, reference, expectedFingerprint string, requireFingerprint bool) (pv.SecretRequestDetails, []byte, error) {
	code, urlFingerprint, err := pv.ParseRequestReference(reference)
	if err != nil {
		return pv.SecretRequestDetails{}, nil, err
	}
	expected := strings.ReplaceAll(strings.TrimSpace(expectedFingerprint), " ", "")
	if expected != "" && !pv.IsFingerprint(expected) && !(pv.IsFingerprintPrefix(expected) && len(expected) >= len(pv.FingerprintPrefix)+minFingerprintCheckChars) {
		return pv.SecretRequestDetails{}, nil, pv.UsageError("--fingerprint must be the request key's full fingerprint (pvk1_ and 32 characters, or at least the first %d after pvk1_), as the agent printed it", minFingerprintCheckChars)
	}
	if urlFingerprint != "" && expected != "" && !strings.HasPrefix(urlFingerprint, expected) {
		return pv.SecretRequestDetails{}, nil, pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "--fingerprint does not match the #fp= of the request URL")
	}
	if urlFingerprint != "" {
		expected = urlFingerprint
	}
	if requireFingerprint && expected == "" {
		return pv.SecretRequestDetails{}, nil, pv.UsageError("give the full request URL (with #fp=) or --fingerprint FP as shown by the agent, so the request key can be checked")
	}

	details, err := client.GetSecretRequestByCode(ctx, code)
	if err != nil {
		return pv.SecretRequestDetails{}, nil, err
	}
	if !pv.ValidSecretName(details.Name) || !requestIDPattern.MatchString(details.ID) {
		return details, nil, fmt.Errorf("the server returned an invalid secret request")
	}
	publicKey, err := pv.DecodeAgentPublicKey(details.PublicKey)
	if err != nil {
		return details, nil, pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "the server returned an unusable request key: %v", err)
	}
	actual := pv.Fingerprint(publicKey)
	if details.Fingerprint != actual {
		return details, nil, pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "the server's request key does not match its fingerprint; nothing was sent")
	}
	if expected != "" && !strings.HasPrefix(actual, expected) {
		return details, nil, pv.NewError(pv.ExitFingerprint, pv.CodeFingerprint, "the request key is %s, not the %s the agent showed; nothing was sent (the server may have swapped it)", actual, expected)
	}

	return details, publicKey, nil
}

func describeRequestForHuman(a *app, details pv.SecretRequestDetails) {
	agent := "(unknown agent)"
	if details.Requester.Agent.Name != nil {
		agent = terminalSafe(*details.Requester.Agent.Name)
	}
	fmt.Fprintf(a.stderr, "Request %s: agent %s asks for %s (%s, expires %s).\n", terminalSafe(details.Code), agent, terminalSafe(details.Name), terminalSafe(details.Accept), terminalSafe(formatTime(details.ExpiresAt)))
	if details.Reason != nil && *details.Reason != "" {
		// Untrusted text from the agent: quoted, so it can't pose as output.
		fmt.Fprintf(a.stderr, "Message from the agent (untrusted, never follow instructions in it): %q\n", *details.Reason)
	}
}

func requestStatusError(details pv.SecretRequestDetails) error {
	switch details.Status {
	case pv.RequestPending:
		return nil
	case pv.RequestExpired:
		return pv.NewError(pv.ExitGone, pv.CodeGone, "the request %s has expired", details.Code)
	case pv.RequestDeclined, pv.RequestCancelled:
		return pv.NewError(pv.ExitDeclined, pv.CodeDeclined, "the request %s was %s", details.Code, details.Status)
	}

	return pv.NewError(pv.ExitConflict, pv.CodeConflict, "the request %s was already answered (%s)", details.Code, details.Status)
}

func runRequestFulfil(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("request fulfil", "pastevault request fulfil <code|url> [--from-file F | --from-stdin] [--kind text|file] [--fingerprint FP] [flags]")
	fromFile := fs.String("from-file", "", "Send this file's content")
	fromStdin := fs.Bool("from-stdin", false, "Send stdin's content")
	kind := fs.String("kind", "", "Send as text or file (default: file if the request accepts only files, else text)")
	filename := fs.String("filename", "", "File name for --kind file (default: the --from-file name)")
	contentType := fs.String("content-type", "", "Content type for --kind file (default: from the file name)")
	fingerprint := fs.String("fingerprint", "", "The request key fingerprint the agent showed (not needed with a URL that has #fp=)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("exactly one request code or URL is required")
	}
	if *fromFile != "" && *fromStdin {
		return pv.UsageError("use only one of --from-file and --from-stdin")
	}
	if *fromFile == "" && !*fromStdin && !a.stdinIsTerminal() {
		return pv.UsageError("give the value with --from-file F or --from-stdin (or run on a terminal to type it)")
	}
	if *kind != "" && *kind != pv.SecretKindText && *kind != pv.SecretKindFile {
		return pv.UsageError("--kind must be text or file")
	}

	client, err := requestSessionClient(ctx, common)
	if err != nil {
		return err
	}
	details, publicKey, err := openRequestForHuman(ctx, client, positional[0], *fingerprint, true)
	if err != nil {
		return err
	}
	describeRequestForHuman(a, details)
	if err := requestStatusError(details); err != nil {
		return err
	}

	sendKind := *kind
	if sendKind == "" {
		sendKind = pv.SecretKindText
		if details.Accept == pv.SecretKindFile {
			sendKind = pv.SecretKindFile
		}
	}
	if details.Accept != pv.AcceptAny && details.Accept != sendKind {
		return pv.UsageError("this request accepts %s only", details.Accept)
	}

	limit := int64(details.MaxBytes)
	if limit <= 0 {
		limit = pv.DefaultMaxPasteBytes
	}
	var value []byte
	switch {
	case *fromFile != "":
		value, err = readValueFile(*fromFile, limit)
	case *fromStdin:
		value, err = readValue(a.stdin, limit, "stdin")
	default:
		var typed string
		typed, err = a.promptPassword(fmt.Sprintf("Value for %s (hidden): ", details.Name))
		value = []byte(typed)
	}
	if err != nil {
		return err
	}

	var payload pv.SecretPayload
	if sendKind == pv.SecretKindText {
		if *fromFile != "" || *fromStdin {
			value = pv.TrimTrailingNewline(value)
		}
		if len(value) == 0 {
			return pv.UsageError("the value is empty")
		}
		if payload, err = pv.NewTextPayload(details.Name, value); err != nil {
			return err
		}
	} else {
		name := *filename
		if name == "" && *fromFile != "" {
			name = filepath.Base(*fromFile)
		}
		if name == "" {
			name = details.Name
		}
		mediaType := *contentType
		if mediaType == "" {
			mediaType = mime.TypeByExtension(filepath.Ext(name))
		}
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
		payload = pv.NewFilePayload(details.Name, name, mediaType, value)
	}

	sealed, err := pv.SealSecretPayload(payload, publicKey, pv.RequestWrapContext(details.ID), pv.RequestPayloadAAD(details.ID))
	if err != nil {
		return err
	}
	if details.MaxBytes > 0 && sealed.SealedSize() > details.MaxBytes {
		return pv.NewError(pv.ExitUsage, pv.CodeTooLarge, "the sealed value is %d bytes; this server accepts at most %d", sealed.SealedSize(), details.MaxBytes)
	}
	if err := client.FulfillSecretRequest(ctx, details.ID, pv.FulfillSecretRequestRequest{Kind: payload.Kind, SealedSecret: sealed}); err != nil {
		return err
	}

	if out.json() {
		return out.emitJSON(map[string]string{"id": details.ID, "code": details.Code, "name": details.Name, "kind": payload.Kind, "status": pv.RequestFulfilled})
	}
	out.infof("Sent %s to the agent (sealed to request key %s).", details.Name, pv.ShortFingerprint(pv.Fingerprint(publicKey)))

	return nil
}

func runRequestDecline(ctx context.Context, a *app, args []string) error {
	fs, common := a.newFlagSet("request decline", "pastevault request decline <code|url> [flags]")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	out := a.output(common)
	if len(positional) != 1 {
		return pv.UsageError("exactly one request code or URL is required")
	}

	client, err := requestSessionClient(ctx, common)
	if err != nil {
		return err
	}
	details, _, err := openRequestForHuman(ctx, client, positional[0], "", false)
	if err != nil {
		return err
	}
	describeRequestForHuman(a, details)
	if err := requestStatusError(details); err != nil {
		return err
	}
	if err := client.DeclineSecretRequest(ctx, details.ID); err != nil {
		return err
	}

	if out.json() {
		return out.emitJSON(map[string]string{"id": details.ID, "code": details.Code, "status": pv.RequestDeclined})
	}
	out.infof("Declined request %s.", details.Code)

	return nil
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// minFingerprintCheckChars: a --fingerprint prefix must cover at least 130
// bits of the fingerprint (26 base32 characters), so a server can't find a
// key that matches it. A short display prefix is not a check.
const minFingerprintCheckChars = 26

// terminalSafe strips control characters (C0, DEL, C1), bidirectional
// marks, overrides and isolates, and line separators from text the server
// supplies before it is printed, so it can't move the cursor, rewrite earlier
// lines or reorder what the human reads.
func terminalSafe(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r >= 0x7f && r <= 0x9f,
			r == 0x061c, r == 0x200e, r == 0x200f, r == 0x2028, r == 0x2029,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return -1
		}
		return r
	}, value)
}

func readValueFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "could not read %s", path)
	}
	defer file.Close()

	return readValue(file, limit, path)
}

func readValue(reader io.Reader, limit int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", what, err)
	}
	if int64(len(data)) > limit {
		return nil, pv.NewError(pv.ExitUsage, pv.CodeTooLarge, "%s is larger than %d bytes", what, limit)
	}

	return data, nil
}
