package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pv "github.com/arc53/pastevault/internal/pastevault"
	"github.com/arc53/pastevault/internal/store"
)

// fakeServer implements the agent side of the secret-request API.
type fakeServer struct {
	t      *testing.T
	mu     sync.Mutex
	agents []pv.AgentSummary
	// created request
	request   pv.CreateSecretRequestRequest
	id        string
	pollToken string
	// what poll answers next, in order (the last one repeats)
	answers   []func() (int, any)
	polls     int
	acks      int
	cancelled int
	// shares for the resolver
	pasteMeta map[string]pv.PasteMetaResponse
	pastes    map[string]pv.GetPasteResponse
}

func newFakeServer(t *testing.T) (*fakeServer, *pv.Client) {
	fake := &fakeServer{t: t, id: "11111111-2222-4333-8444-555555555555", pollToken: "poll-secret", pasteMeta: map[string]pv.PasteMetaResponse{}, pastes: map[string]pv.GetPasteResponse{}}
	server := httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(server.Close)
	client, err := pv.NewClient(server.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("pv_pat_test")
	return fake, client
}

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}

	switch path := r.URL.Path; {
	case r.Method == http.MethodGet && path == "/api/agents":
		reply(200, pv.ListAgentsResponse{Agents: f.agents})
	case r.Method == http.MethodPost && path == "/api/secret-requests":
		_ = json.NewDecoder(r.Body).Decode(&f.request)
		reply(201, pv.CreateSecretRequestResponse{ID: f.id, Code: "ABCD-EFGH", URLPath: "/r/ABCD-EFGH", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), PollToken: f.pollToken, Interval: 1})
	case r.Method == http.MethodPost && path == "/api/secret-requests/"+f.id+"/poll":
		var body struct {
			PollToken string `json:"poll_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.PollToken != f.pollToken {
			reply(403, map[string]string{"error": "invalid_poll_token"})
			return
		}
		answer := f.answers[min(f.polls, len(f.answers)-1)]
		f.polls++
		reply(answer())
	case r.Method == http.MethodPost && path == "/api/secret-requests/"+f.id+"/ack":
		f.acks++
		reply(204, nil)
	case r.Method == http.MethodDelete && path == "/api/secret-requests/"+f.id:
		f.cancelled++
		reply(200, map[string]string{"status": "cancelled"})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/pastes/") && strings.HasSuffix(path, "/meta"):
		slug := strings.TrimSuffix(strings.TrimPrefix(path, "/api/pastes/"), "/meta")
		if meta, ok := f.pasteMeta[slug]; ok {
			reply(200, meta)
			return
		}
		reply(404, map[string]string{"error": "Paste not found"})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/pastes/"):
		slug := strings.TrimPrefix(path, "/api/pastes/")
		if paste, ok := f.pastes[slug]; ok {
			reply(200, paste)
			return
		}
		reply(404, map[string]string{"error": "Paste not found"})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/file-shares/"):
		reply(404, map[string]string{"error": "File share not found"})
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, path)
		reply(404, map[string]string{"error": "unexpected"})
	}
}

func isolate(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "config")
	t.Setenv(pv.EnvConfigDir, dir)
	t.Setenv(pv.EnvAgent, "")
	t.Setenv(pv.EnvAgentKey, "")
	return dir
}

func newAgent(t *testing.T, server, name, id string) *pv.AgentIdentity {
	t.Helper()
	keys, err := pv.GenerateAgentKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	identity := pv.NewAgentIdentity(server, name, keys)
	identity.AgentID = id
	path, _ := pv.AgentKeyPath(server, name)
	if err := pv.SaveAgentIdentity(identity, path, false); err != nil {
		t.Fatal(err)
	}
	return identity
}

// fulfilled answers a poll like the server does once the human answered:
// the payload sealed (by the "browser") to the request key.
func fulfilled(t *testing.T, pending func() *pv.PendingRequest, value string) func() (int, any) {
	return func() (int, any) {
		request := pending()
		publicKey, _ := pv.DecodeAgentPublicKey(request.PublicKey)
		payload, _ := pv.NewTextPayload(request.Name, []byte(value))
		sealed, err := pv.SealSecretPayload(payload, publicKey, pv.RequestWrapContext(request.ID), pv.RequestPayloadAAD(request.ID))
		if err != nil {
			t.Error(err)
		}
		return 200, pv.PollSecretRequestResponse{Status: pv.RequestFulfilled, Interval: 1, Kind: pv.SecretKindText, SealedSecret: sealed}
	}
}

func status(value string) func() (int, any) {
	return func() (int, any) { return 200, map[string]any{"status": value, "interval": 1} }
}

func TestRequestFlowStoresAndAcks(t *testing.T) {
	isolate(t)
	fake, client := newFakeServer(t)
	agent := newAgent(t, client.BaseURL(), "builder", "agent-1")

	pending, err := NewRequest(context.Background(), client, "https://pastevault.example", agent, RequestOptions{Name: "OPENAI_API_KEY", Reason: "evals", TTL: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if fake.request.AgentID != "agent-1" || fake.request.Accept != "text" || fake.request.TTLSeconds != 600 || fake.request.Reason != "evals" {
		t.Fatalf("create request = %+v", fake.request)
	}
	if fake.request.Fingerprint != pending.Fingerprint || fake.request.Fingerprint == agent.Fingerprint {
		t.Fatal("the request uses its own ephemeral key")
	}
	if pending.URL != "https://pastevault.example/r/ABCD-EFGH#fp="+pending.Fingerprint || pending.SaveAs != "OPENAI_API_KEY" {
		t.Fatalf("pending = %+v", pending)
	}
	if _, err := os.Stat(pending.Path); err != nil {
		t.Fatal(err)
	}

	fake.answers = []func() (int, any){
		status(pv.RequestPending),
		func() (int, any) { return 429, map[string]any{"error": "slow_down", "interval": 1} },
		fulfilled(t, func() *pv.PendingRequest { return pending }, "sk-value-123"),
		status(pv.RequestDelivered),
	}
	polls := 0
	outcome, err := Await(context.Background(), client, pending, AwaitOptions{Timeout: 30 * time.Second, OnPoll: func() { polls++ }})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != OutcomeStored || outcome.Handle != "pv://secret/OPENAI_API_KEY" || outcome.AckErr != nil {
		t.Fatalf("outcome = %+v", outcome)
	}
	if fake.acks != 1 || polls != 1 {
		t.Fatalf("acks = %d, pending polls = %d", fake.acks, polls)
	}
	if _, err := os.Stat(pending.Path); !os.IsNotExist(err) {
		t.Fatal("the request file must be deleted after the ack")
	}

	_, entries, _, err := ListSecrets(client.BaseURL(), "")
	if err != nil || len(entries) != 1 || entries[0].Source.Type != store.SourceRequest || entries[0].Source.Ref != pending.ID {
		t.Fatalf("ListSecrets = %+v %v", entries, err)
	}

	// Crash recovery: the request file survived, the server says delivered
	// (wiped) but the store has the entry from this request.
	if err := pv.SavePendingRequest(pending); err != nil {
		t.Fatal(err)
	}
	fake.answers = []func() (int, any){status(pv.RequestDelivered)}
	outcome, err = Check(context.Background(), client, pending)
	if err != nil || outcome.Status != OutcomeStored {
		t.Fatalf("recovered outcome = %+v %v", outcome, err)
	}

	// A re-poll within the lease after a crash before the ack: same payload,
	// already stored, so it is acked without a second write.
	if err := pv.SavePendingRequest(pending); err != nil {
		t.Fatal(err)
	}
	fake.answers = []func() (int, any){fulfilled(t, func() *pv.PendingRequest { return pending }, "sk-value-123")}
	outcome, err = Check(context.Background(), client, pending)
	if err != nil || outcome.Status != OutcomeStored || fake.acks != 2 {
		t.Fatalf("re-poll outcome = %+v %v (acks %d)", outcome, err, fake.acks)
	}
}

func TestRequestOutcomes(t *testing.T) {
	isolate(t)
	fake, client := newFakeServer(t)
	agent := newAgent(t, client.BaseURL(), "builder", "agent-1")

	for _, test := range []struct {
		status string
		exit   int
	}{
		{pv.RequestDeclined, pv.ExitDeclined},
		{pv.RequestCancelled, pv.ExitDeclined},
		{pv.RequestExpired, pv.ExitGone},
		{pv.RequestDelivered, pv.ExitGone},
	} {
		pending, err := NewRequest(context.Background(), client, "https://x", agent, RequestOptions{Name: "TOKEN", TTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		fake.answers = []func() (int, any){status(test.status)}
		outcome, err := Await(context.Background(), client, pending, AwaitOptions{Timeout: 10 * time.Second})
		if err != nil || outcome.Status != test.status {
			t.Fatalf("%s: outcome %+v %v", test.status, outcome, err)
		}
		if exit := pv.Classify(OutcomeError(pending, outcome)).Exit; exit != test.exit {
			t.Fatalf("%s: exit %d, want %d", test.status, exit, test.exit)
		}
		if _, err := os.Stat(pending.Path); !os.IsNotExist(err) {
			t.Fatalf("%s: the request file must be deleted", test.status)
		}
	}

	// Timeout: exit 9, the request file stays for a later await.
	pending, _ := NewRequest(context.Background(), client, "https://x", agent, RequestOptions{Name: "TOKEN", TTL: time.Minute})
	fake.answers = []func() (int, any){status(pv.RequestPending)}
	_, err := Await(context.Background(), client, pending, AwaitOptions{Timeout: 1500 * time.Millisecond})
	if pv.Classify(err).Exit != pv.ExitTimeout {
		t.Fatalf("timeout: %v", err)
	}
	if _, err := os.Stat(pending.Path); err != nil {
		t.Fatal("the request file must stay after a timeout")
	}

	// An answer sealed for another request id is refused (exit 7) and not
	// acknowledged.
	other := *pending
	other.ID = "99999999-2222-4333-8444-555555555555"
	acks := fake.acks
	fake.answers = []func() (int, any){fulfilled(t, func() *pv.PendingRequest { return &other }, "x")}
	if _, err := Check(context.Background(), client, pending); pv.Classify(err).Exit != pv.ExitDecrypt {
		t.Fatalf("wrong request id: %v, want exit 7", err)
	}
	if fake.acks != acks {
		t.Fatal("a failed delivery must not be acknowledged")
	}

	// The store name is checked before the request is made.
	target, _ := store.Open(client.BaseURL(), agent)
	payload, _ := pv.NewTextPayload("x", []byte("existing"))
	_, _ = target.Put("TAKEN", payload, store.Source{Type: store.SourceImport}, false)
	if _, err := NewRequest(context.Background(), client, "https://x", agent, RequestOptions{Name: "TAKEN", TTL: time.Minute}); pv.Classify(err).Exit != pv.ExitLocalFile {
		t.Fatalf("existing store entry: %v, want exit 13", err)
	}
}

func TestResolveAgentIDForEnvKey(t *testing.T) {
	isolate(t)
	fake, client := newFakeServer(t)
	keys, _ := pv.GenerateAgentKeyPair()
	other, _ := pv.GenerateAgentKeyPair()
	t.Setenv(pv.EnvAgentKey, pv.EncodeBase64URL(keys.PrivateKey))
	fake.agents = []pv.AgentSummary{
		// The server's fingerprint field is never trusted: recomputed.
		{ID: "wrong", Name: "liar", PublicKey: pv.EncodeBase64URL(other.PublicKey), Fingerprint: keys.Fingerprint},
		{ID: "agent-ci", Name: "ci", PublicKey: pv.EncodeBase64URL(keys.PublicKey), Fingerprint: "pvk1_whatever"},
	}
	identity, err := pv.ResolveLocalAgent(client.BaseURL(), "")
	if err != nil {
		t.Fatal(err)
	}
	id, name, err := ResolveAgentID(context.Background(), client, identity)
	if err != nil || id != "agent-ci" || name != "ci" {
		t.Fatalf("ResolveAgentID = %q %q %v", id, name, err)
	}
	fake.agents = fake.agents[:1]
	if _, _, err := ResolveAgentID(context.Background(), client, identity); pv.Classify(err).Exit != pv.ExitNotFound {
		t.Fatalf("unregistered key: %v", err)
	}
}

func TestResolver(t *testing.T) {
	isolate(t)
	fake, client := newFakeServer(t)
	server := client.BaseURL()
	agent := newAgent(t, server, "builder", "agent-1")
	target, _ := store.Open(server, agent)
	payload, _ := pv.NewTextPayload("x", []byte("A=1\nTOKEN=from-dotenv\n"))
	_, _ = target.Put("ENV", payload, store.Source{Type: store.SourceImport}, false)

	resolver := &Resolver{Server: server, PublicBase: server, NewClient: func(string) (*pv.Client, error) { return client, nil }}
	ctx := context.Background()

	if value, err := resolver.Resolve(ctx, "pv://secret/ENV", false); err != nil || string(value) != "A=1\nTOKEN=from-dotenv\n" {
		t.Fatalf("secret = %q %v", value, err)
	}
	if value, err := resolver.Resolve(ctx, "pv://secret/ENV?var=TOKEN", false); err != nil || string(value) != "from-dotenv" {
		t.Fatalf("secret var = %q %v", value, err)
	}
	if _, err := resolver.Resolve(ctx, "pv://secret/ENV?var=NOPE", false); pv.Classify(err).Exit != pv.ExitNotFound {
		t.Fatalf("missing var: %v", err)
	}
	if _, err := resolver.Resolve(ctx, "pv://secret/MISSING", false); pv.Classify(err).Exit != pv.ExitNotFound {
		t.Fatalf("missing secret: %v", err)
	}

	// Share handles: an unlimited paste resolves; a view-limited one is
	// refused before it is opened.
	key := make([]byte, 32)
	content := pv.PasteContent{Body: "SHARED=yes\n", RenderMode: pv.RenderModePlain}
	ciphertext, nonce, err := pv.EncryptPaste(content, key, "unlimited01")
	if err != nil {
		t.Fatal(err)
	}
	fake.pasteMeta["unlimited01"] = pv.PasteMetaResponse{Slug: "unlimited01"}
	fake.pastes["unlimited01"] = pv.GetPasteResponse{Metadata: pv.PasteMetadata{Slug: "unlimited01"}, Ciphertext: ciphertext, Nonce: nonce}
	one := 1
	fake.pasteMeta["limited0001"] = pv.PasteMetaResponse{Slug: "limited0001", MaxViews: &one}
	fake.pastes["limited0001"] = pv.GetPasteResponse{Metadata: pv.PasteMetadata{Slug: "limited0001"}}

	handle := "pv://share/unlimited01?var=SHARED#k=" + pv.EncodeBase64URL(key)
	if value, err := resolver.Resolve(ctx, handle, false); err != nil || string(value) != "yes" {
		t.Fatalf("share = %q %v", value, err)
	}
	_, err = resolver.Resolve(ctx, "pv://share/limited0001#k="+pv.EncodeBase64URL(key), false)
	if err == nil || !strings.Contains(err.Error(), "--save NAME") {
		t.Fatalf("view-limited share: %v", err)
	}
	if _, err := resolver.Resolve(ctx, "pv://share/unlimited01", false); pv.Classify(err).Code != pv.CodeKeyRequired {
		t.Fatalf("share without key: %v", err)
	}
	if _, err := resolver.Resolve(ctx, server+"/p/unlimited01#k="+pv.EncodeBase64URL(key), false); err == nil {
		t.Fatal("URLs are only handles with allowURLs")
	}
	if value, err := resolver.Resolve(ctx, server+"/p/unlimited01#k="+pv.EncodeBase64URL(key), true); err != nil || string(value) != "SHARED=yes\n" {
		t.Fatalf("legacy URL = %q %v", value, err)
	}
}

// Errors never delete the request file: it holds the only key for the answer.
func TestCheckKeepsRequestFileOnErrors(t *testing.T) {
	isolate(t)
	fake, client := newFakeServer(t)
	agent := newAgent(t, client.BaseURL(), "builder", "agent-1")
	pending, err := NewRequest(context.Background(), client, "https://x", agent, RequestOptions{Name: "TOKEN", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	for _, answer := range []func() (int, any){
		func() (int, any) { return 404, map[string]string{"error": "Secret request not found"} },
		func() (int, any) { return 401, map[string]string{"error": "invalid_token"} },
		func() (int, any) { return 403, map[string]string{"error": "other_agent"} },
		func() (int, any) { return 500, map[string]string{"error": "boom"} },
	} {
		fake.answers = []func() (int, any){answer}
		if _, err := Check(context.Background(), client, pending); err == nil {
			t.Fatal("expected an error")
		}
		if _, err := os.Stat(pending.Path); err != nil {
			t.Fatalf("the request file was deleted after an error: %v", err)
		}
	}
}

// Two requests saved under one name: the later answer is stored under a
// fallback name instead of being lost after delivery.
func TestAnswerStoredUnderFallbackName(t *testing.T) {
	isolate(t)
	fake, client := newFakeServer(t)
	agent := newAgent(t, client.BaseURL(), "builder", "agent-1")
	pending, err := NewRequest(context.Background(), client, "https://x", agent, RequestOptions{Name: "TOKEN", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	// Meanwhile something else stored TOKEN.
	target, _ := store.Open(client.BaseURL(), agent)
	payload, _ := pv.NewTextPayload("x", []byte("first-answer"))
	if _, err := target.Put("TOKEN", payload, store.Source{Type: store.SourceImport}, false); err != nil {
		t.Fatal(err)
	}

	fake.answers = []func() (int, any){fulfilled(t, func() *pv.PendingRequest { return pending }, "second-answer")}
	outcome, err := Check(context.Background(), client, pending)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Renamed || outcome.SavedAs != "TOKEN.ABCDEFGH" || outcome.Handle != "pv://secret/TOKEN.ABCDEFGH" || fake.acks != 1 {
		t.Fatalf("outcome = %+v (acks %d)", outcome, fake.acks)
	}
	_, first, _ := target.Get("TOKEN")
	_, second, _ := target.Get("TOKEN.ABCDEFGH")
	if first.Value != "first-answer" || second.Value != "second-answer" {
		t.Fatalf("values %q %q", first.Value, second.Value)
	}

	// Crash recovery finds the fallback entry again.
	if err := pv.SavePendingRequest(pending); err != nil {
		t.Fatal(err)
	}
	fake.answers = []func() (int, any){status(pv.RequestDelivered)}
	outcome, err = Check(context.Background(), client, pending)
	if err != nil || outcome.Status != OutcomeStored || outcome.SavedAs != "TOKEN.ABCDEFGH" {
		t.Fatalf("recovered = %+v %v", outcome, err)
	}

	// With Overwrite (await --overwrite) the name is replaced instead.
	pending2, _ := NewRequest(context.Background(), client, "https://x", agent, RequestOptions{Name: "OTHER", TTL: time.Minute})
	_, _ = target.Put("OTHER", payload, store.Source{Type: store.SourceImport}, false)
	pending2.Overwrite = true
	fake.answers = []func() (int, any){fulfilled(t, func() *pv.PendingRequest { return pending2 }, "replacement")}
	outcome, err = Check(context.Background(), client, pending2)
	if err != nil || outcome.Renamed || outcome.SavedAs != "OTHER" {
		t.Fatalf("overwrite = %+v %v", outcome, err)
	}
}
