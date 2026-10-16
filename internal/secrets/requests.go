// Package secrets holds the agent-side flows shared by the CLI commands and
// the MCP server: making a secret request, collecting its response into the
// local store (spec §6), listing stored secrets, and resolving pv:// handles
// for run and inject (spec §5.4).
package secrets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/store"
)

// RequestOptions describe a new secret request.
type RequestOptions struct {
	// Name is what is asked for (e.g. OPENAI_API_KEY); SaveAs is the store
	// entry the answer becomes (default Name).
	Name   string
	SaveAs string
	// Reason is shown to the human as untrusted text.
	Reason string
	TTL    time.Duration
	// Accept is "text", "file" or "any" (default "text").
	Accept string
	// Overwrite lets the answer replace an existing store entry.
	Overwrite bool
}

// ResolveAgentID returns the server id and name of identity's agent: from
// its key file, or for PASTEVAULT_AGENT_KEY by matching the fingerprint
// (recomputed from each listed public key) against the account's agents.
func ResolveAgentID(ctx context.Context, client *pv.Client, identity *pv.AgentIdentity) (string, string, error) {
	if identity.AgentID != "" {
		return identity.AgentID, identity.Name, nil
	}

	response, err := client.ListAgents(ctx, false)
	if err != nil {
		return "", "", err
	}
	for _, agent := range response.Agents {
		publicKey, err := pv.DecodeAgentPublicKey(agent.PublicKey)
		if err == nil && pv.Fingerprint(publicKey) == identity.Fingerprint {
			return agent.ID, agent.Name, nil
		}
	}

	return "", "", pv.NewError(pv.ExitNotFound, pv.CodeNotFound, "agent key %s is not a registered agent of this account on %s (pastevault agent init)", pv.ShortFingerprint(identity.Fingerprint), client.BaseURL())
}

// NewRequest creates a secret request as identity's agent and saves the
// request file (ephemeral private key and poll token, 0600) needed to
// collect the answer. publicBase is the web origin for the request URL.
func NewRequest(ctx context.Context, client *pv.Client, publicBase string, identity *pv.AgentIdentity, options RequestOptions) (*pv.PendingRequest, error) {
	if !pv.ValidSecretName(options.Name) {
		return nil, pv.UsageError("invalid secret name %q (letters, digits, _ . -, starting with a letter or _, at most 128)", options.Name)
	}
	if options.SaveAs == "" {
		options.SaveAs = options.Name
	}
	if !pv.ValidSecretName(options.SaveAs) {
		return nil, pv.UsageError("invalid store name %q", options.SaveAs)
	}
	if options.Accept == "" {
		options.Accept = pv.SecretKindText
	}

	server := client.BaseURL()
	agentID, agentName, err := ResolveAgentID(ctx, client, identity)
	if err != nil {
		return nil, err
	}

	// The answer is stored for this agent; fail now rather than after the
	// human has answered.
	target, err := store.Open(server, identity)
	if err != nil {
		return nil, err
	}
	if err := target.CheckWritable(options.SaveAs, options.Overwrite); err != nil {
		return nil, err
	}

	keys, err := pv.GenerateAgentKeyPair()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateSecretRequest(ctx, pv.CreateSecretRequestRequest{
		Name:        options.Name,
		Reason:      options.Reason,
		TTLSeconds:  int(options.TTL / time.Second),
		Accept:      options.Accept,
		PublicKey:   pv.EncodeBase64URL(keys.PublicKey),
		Fingerprint: keys.Fingerprint,
		AgentID:     agentID,
	})
	if err != nil {
		return nil, err
	}

	code, ok := pv.NormalizeRequestCode(response.Code)
	if !ok {
		return nil, fmt.Errorf("the server returned an invalid request code")
	}
	interval := response.Interval
	if interval <= 0 {
		interval = 3
	}

	pending := &pv.PendingRequest{
		ID:               response.ID,
		Code:             code,
		Server:           server,
		URL:              pv.RequestURL(publicBase, code, keys.Fingerprint),
		Name:             options.Name,
		SaveAs:           options.SaveAs,
		Overwrite:        options.Overwrite,
		Accept:           options.Accept,
		PollToken:        response.PollToken,
		PrivateKey:       pv.EncodeBase64URL(keys.PrivateKey),
		PublicKey:        pv.EncodeBase64URL(keys.PublicKey),
		Fingerprint:      keys.Fingerprint,
		Interval:         interval,
		ExpiresAt:        response.ExpiresAt,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		Agent:            agentName,
		AgentID:          agentID,
		AgentFingerprint: identity.Fingerprint,
	}
	if err := pv.SavePendingRequest(pending); err != nil {
		// Without the file nobody can open the answer: withdraw the request.
		_, _ = client.CancelSecretRequest(context.WithoutCancel(ctx), response.ID)
		return nil, err
	}

	return pending, nil
}

// Outcome is the state of a request after a check.
type Outcome struct {
	// Status is a request status (pending, declined, expired, cancelled,
	// delivered) or "stored" once the answer is in the local store.
	Status string
	// Handle and Entry are set when Status is "stored".
	Handle string
	Entry  *store.Entry
	// AckErr is a failed acknowledgement after storing. The answer is safe
	// locally; the server wipes it when its delivery lease ends.
	AckErr error
}

// OutcomeStored is the Outcome status once the answer is stored locally.
const OutcomeStored = "stored"

// Final reports whether the request needs no more polling.
func (o Outcome) Final() bool {
	return o.Status != pv.RequestPending
}

// Check polls a request once. A fulfilled request is decrypted, sealed into
// the local store, acknowledged, and its request file deleted. Final states
// (declined, cancelled, expired, already delivered) delete the request file
// too. A 429 slow_down is returned as an error (pv.IsSlowDown).
func Check(ctx context.Context, client *pv.Client, pending *pv.PendingRequest) (Outcome, error) {
	response, err := client.PollSecretRequest(ctx, pending.ID, pending.PollToken)
	if err != nil {
		if pv.IsStatus(err, http.StatusNotFound) {
			_ = pv.DeletePendingRequest(pending)
		}
		return Outcome{}, err
	}

	switch response.Status {
	case pv.RequestFulfilled:
		return deliver(ctx, client, pending, response)
	case pv.RequestPending:
		return Outcome{Status: pv.RequestPending}, nil
	case pv.RequestDelivered:
		// Collected earlier (the answer is wiped): stored by an earlier run
		// whose ack or cleanup did not finish, or gone.
		if entry := storedFrom(pending); entry != nil {
			_ = pv.DeletePendingRequest(pending)
			return Outcome{Status: OutcomeStored, Handle: entry.Handle(), Entry: entry}, nil
		}
		_ = pv.DeletePendingRequest(pending)
		return Outcome{Status: pv.RequestDelivered}, nil
	case pv.RequestDeclined, pv.RequestCancelled, pv.RequestExpired:
		_ = pv.DeletePendingRequest(pending)
		return Outcome{Status: response.Status}, nil
	}

	return Outcome{}, fmt.Errorf("the server reported an unknown request status %q", response.Status)
}

// openStore opens the store of the agent the request was made as.
func openStore(pending *pv.PendingRequest) (*store.Store, error) {
	identity, err := pv.FindIdentityByFingerprint(pending.Server, pending.AgentFingerprint)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, pv.DecryptError("the request was made as agent key %s, which is no longer on this machine", pv.ShortFingerprint(pending.AgentFingerprint))
	}

	return store.Open(pending.Server, identity)
}

func storedFrom(pending *pv.PendingRequest) *store.Entry {
	target, err := openStore(pending)
	if err != nil {
		return nil
	}
	entry, err := target.Entry(pending.SaveAs)
	if err != nil || entry.Source.Type != store.SourceRequest || entry.Source.Ref != pending.ID {
		return nil
	}

	return entry
}

func deliver(ctx context.Context, client *pv.Client, pending *pv.PendingRequest, response pv.PollSecretRequestResponse) (Outcome, error) {
	keys, err := pending.Keys()
	if err != nil {
		return Outcome{}, err
	}
	payload, err := pv.OpenSecretPayload(response.SealedSecret, keys.PrivateKey, pv.RequestWrapContext(pending.ID), pv.RequestPayloadAAD(pending.ID))
	if err != nil {
		return Outcome{}, err
	}
	if payload.Name != pending.Name || payload.Kind != response.Kind {
		return Outcome{}, pv.DecryptError("the answer does not match the request (it names %q as %s)", payload.Name, payload.Kind)
	}
	if pending.Accept != pv.AcceptAny && pending.Accept != "" && payload.Kind != pending.Accept {
		return Outcome{}, pv.DecryptError("the request accepts %s, but the answer is a %s", pending.Accept, payload.Kind)
	}

	entry := storedFrom(pending)
	if entry == nil {
		target, err := openStore(pending)
		if err != nil {
			return Outcome{}, err
		}
		if entry, err = target.Put(pending.SaveAs, payload, store.Source{Type: store.SourceRequest, Ref: pending.ID}, pending.Overwrite); err != nil {
			return Outcome{}, err
		}
	}

	// Stored: only now tell the server it may wipe the answer.
	outcome := Outcome{Status: OutcomeStored, Handle: entry.Handle(), Entry: entry}
	outcome.AckErr = client.AckSecretRequest(context.WithoutCancel(ctx), pending.ID, pending.PollToken)
	if err := pv.DeletePendingRequest(pending); err != nil && outcome.AckErr == nil {
		outcome.AckErr = fmt.Errorf("could not delete the request file %s: %w", pending.Path, err)
	}

	return outcome, nil
}

// AwaitOptions control Await.
type AwaitOptions struct {
	// Timeout bounds the wait (0: until the request expires, plus a minute).
	Timeout time.Duration
	// OnPoll is called after each check that left the request pending.
	OnPoll func()
}

// Await polls until the request is final or the timeout passes (exit 9).
// It honours the server's interval and backs off on slow_down and transient
// errors.
func Await(ctx context.Context, client *pv.Client, pending *pv.PendingRequest, options AwaitOptions) (Outcome, error) {
	deadline := time.Now().Add(options.Timeout)
	if options.Timeout <= 0 {
		deadline = time.Now().Add(time.Minute)
		if expires, err := time.Parse(time.RFC3339Nano, pending.ExpiresAt); err == nil {
			deadline = expires.Add(time.Minute)
		}
	}

	interval := time.Duration(pending.Interval) * time.Second
	if interval <= 0 {
		interval = 3 * time.Second
	}
	failures := 0

	for {
		outcome, err := Check(ctx, client, pending)
		switch {
		case err == nil:
			failures = 0
			if outcome.Final() {
				return outcome, nil
			}
			if options.OnPoll != nil {
				options.OnPoll()
			}
		case pv.IsSlowDown(err):
			interval += 2 * time.Second
		case transient(err) && failures < 5:
			failures++
		default:
			return Outcome{}, err
		}

		wait := interval
		if failures > 0 {
			wait = interval * time.Duration(1<<failures)
		}
		if time.Now().Add(wait).After(deadline) {
			return Outcome{Status: pv.RequestPending}, pv.NewError(pv.ExitTimeout, pv.CodeTimeout, "the request %s for %s is still pending; run pastevault await %s to keep waiting", pending.Code, pending.Name, pending.Code)
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Outcome{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func transient(err error) bool {
	var apiErr *pv.APIRequestError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500
	}
	return pv.Classify(err).Exit == pv.ExitNetwork
}

// OutcomeError maps a final outcome that delivered nothing to its CLI error:
// declined or cancelled exit 6, expired or already collected exit 5.
func OutcomeError(pending *pv.PendingRequest, outcome Outcome) error {
	switch outcome.Status {
	case pv.RequestDeclined:
		return pv.NewError(pv.ExitDeclined, pv.CodeDeclined, "the request %s for %s was declined", pending.Code, pending.Name)
	case pv.RequestCancelled:
		return pv.NewError(pv.ExitDeclined, "cancelled", "the request %s for %s was cancelled", pending.Code, pending.Name)
	case pv.RequestExpired:
		return pv.NewError(pv.ExitGone, pv.CodeGone, "the request %s for %s expired before it was answered", pending.Code, pending.Name)
	case pv.RequestDelivered:
		return pv.NewError(pv.ExitGone, pv.CodeGone, "the answer to request %s was already collected and is gone from the server", pending.Code)
	}

	return nil
}

// ListSecrets lists the local store of agent (default agent when "") on
// server. Values are not decrypted.
func ListSecrets(server, agent string) (*store.Store, []*store.Entry, []string, error) {
	identity, err := pv.ResolveLocalAgent(server, agent)
	if err != nil {
		return nil, nil, nil, err
	}
	target, err := store.Open(server, identity)
	if err != nil {
		return nil, nil, nil, err
	}
	entries, warnings, err := target.List()

	return target, entries, warnings, err
}
