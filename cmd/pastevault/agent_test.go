package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

// sealedServer is an in-memory server with agents and sealed pastes.
type sealedServer struct {
	*httptest.Server
	mu       sync.Mutex
	features map[string]any
	agents   []map[string]any
	pastes   map[string]map[string]any
	views    map[string]int
	consumed int
	creates  int
	// failCreate, when set, is the status and body POST /api/pastes answers.
	failCreate *struct {
		status int
		body   map[string]any
	}
}

func newSealedServer(t *testing.T) *sealedServer {
	t.Helper()

	server := &sealedServer{
		features: map[string]any{"expires_in_minutes": true, "max_views": true, "agents": true, "sealed_shares": true},
		pastes:   map[string]map[string]any{},
		views:    map[string]int{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/capabilities", func(w http.ResponseWriter, _ *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		writeTestJSON(w, 200, map[string]any{"api_version": 2, "features": server.features, "limits": map[string]any{"max_views": 1000}})
	})
	mux.HandleFunc("GET /api/agents", func(w http.ResponseWriter, _ *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		writeTestJSON(w, 200, map[string]any{"agents": server.agents})
	})
	mux.HandleFunc("POST /api/pastes", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		server.mu.Lock()
		defer server.mu.Unlock()
		if server.failCreate != nil {
			writeTestJSON(w, server.failCreate.status, server.failCreate.body)
			return
		}
		slug, _ := body["slug"].(string)
		server.pastes[slug] = body
		server.creates++
		writeTestJSON(w, 201, map[string]any{"slug": slug, "expires_at": "2026-10-17T12:00:00.000Z", "max_views": 1})
	})
	recipientOf := func(body map[string]any) (map[string]any, bool) {
		recipient, ok := body["recipient"].(map[string]any)
		_, hasAgent := recipient["agent_id"]
		return recipient, ok && hasAgent
	}
	mux.HandleFunc("GET /api/pastes/{slug}/meta", func(w http.ResponseWriter, r *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		body := server.pastes[r.PathValue("slug")]
		if body == nil || server.views[r.PathValue("slug")] > 0 {
			writeTestJSON(w, 404, map[string]any{"error": "Paste not found"})
			return
		}
		recipient, requiresAuth := recipientOf(body)
		var recipientMeta any
		if recipient != nil {
			recipientMeta = map[string]any{"fingerprint": recipient["fingerprint"]}
		}
		salt, _ := body["salt"].(string)
		writeTestJSON(w, 200, map[string]any{
			"slug": r.PathValue("slug"), "max_views": 1, "views_remaining": 1,
			"recipient": recipientMeta, "requires_recipient_auth": requiresAuth,
			"password_protected": salt != "", "salt": salt, "kdf_params": body["kdf_params"],
		})
	})
	mux.HandleFunc("GET /api/pastes/{slug}", func(w http.ResponseWriter, r *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		slug := r.PathValue("slug")
		body := server.pastes[slug]
		if body == nil || server.views[slug] > 0 {
			writeTestJSON(w, 410, map[string]any{"error": "Paste has been burned"})
			return
		}
		recipient, requiresAuth := recipientOf(body)
		if recipient == nil {
			recipient = map[string]any{}
		}
		if requiresAuth && r.Header.Get("Authorization") == "" {
			writeTestJSON(w, 403, map[string]any{"error": "recipient_auth_required"})
			return
		}
		server.views[slug]++
		server.consumed++
		writeTestJSON(w, 200, map[string]any{
			"metadata":   map[string]any{"slug": slug, "view_count": 1, "max_views": 1, "views_remaining": 0, "is_burned": true},
			"ciphertext": body["ciphertext"], "nonce": body["nonce"],
			"wrapped_key": recipient["wrapped_key"], "recipient_fingerprint": recipient["fingerprint"],
		})
	})

	server.Server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func (s *sealedServer) addAgent(name string, keys pv.AgentKeyPair) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents = append(s.agents, map[string]any{
		"id": "agent-" + name, "name": name, "kind": "agent",
		"public_key": pv.EncodeBase64URL(keys.PublicKey), "fingerprint": keys.Fingerprint,
		"created_at": "2026-10-16T12:00:00.000Z", "last_used_at": nil, "revoked_at": nil,
	})
}

// swapKey replaces an agent's public key but keeps the fingerprint the
// server claims, like a malicious server would.
func (s *sealedServer) swapKey(name string, publicKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, agent := range s.agents {
		if agent["name"] == name {
			agent["public_key"] = pv.EncodeBase64URL(publicKey)
		}
	}
}

func isolateAgents(t *testing.T, server string) {
	t.Helper()
	isolate(t, server)
	t.Setenv(pv.EnvAgent, "")
	t.Setenv(pv.EnvAgentKey, "")
	t.Setenv(pv.EnvToken, "pv_pat_"+strings.Repeat("a", 52))
}

func mustKeyPair(t *testing.T) pv.AgentKeyPair {
	t.Helper()
	keys, err := pv.GenerateAgentKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestPutToAgentSealsPinsAndGetOpens(t *testing.T) {
	server := newSealedServer(t)
	isolateAgents(t, server.URL)
	bot := mustKeyPair(t)
	server.addAgent("bot", bot)

	result := runCLI(t, "for the bot\n", false, "put", "-", "--to", "bot", "--json")
	if result.exit != 0 {
		t.Fatalf("put --to: exit %d\n%s", result.exit, result.stderr)
	}
	if !strings.Contains(result.stderr, "Pinned bot pvk1_") {
		t.Fatalf("expected a TOFU notice, got %q", result.stderr)
	}
	output := decodeJSON(t, result.stdout)
	url, _ := output["url"].(string)
	if strings.Contains(url, "#k=") || output["key_in_url"] != false {
		t.Fatalf("a sealed link must not carry a key: %v", output)
	}
	recipient, _ := output["recipient"].(map[string]any)
	if recipient["name"] != "bot" || recipient["fingerprint"] != bot.Fingerprint {
		t.Fatalf("recipient = %v", recipient)
	}

	slug, _ := output["slug"].(string)
	sent, _ := server.pastes[slug]["recipient"].(map[string]any)
	if sent["agent_id"] != "agent-bot" || sent["fingerprint"] != bot.Fingerprint {
		t.Fatalf("request recipient = %v", sent)
	}
	if _, err := pv.UnwrapKey(sent["wrapped_key"].(string), bot.PrivateKey, pv.PasteWrapContext(slug)); err != nil {
		t.Fatalf("the wrapped key does not open with the bot's key: %v", err)
	}
	if server.pastes[slug]["max_views"] != nil || server.pastes[slug]["burn_after_read"] != true {
		t.Fatalf("--to defaults to a single view: %v", server.pastes[slug])
	}

	// No local key for the recipient: exit 7 before consuming.
	refused := runCLI(t, "", false, "get", url, "--stdout", "--json")
	if refused.exit != pv.ExitDecrypt || server.consumed != 0 {
		t.Fatalf("get without the key: exit %d, consumed %d\n%s", refused.exit, server.consumed, refused.stderr)
	}

	// With the agent key but no credentials: exit 3 before consuming.
	t.Setenv(pv.EnvAgentKey, pv.EncodeBase64URL(bot.PrivateKey))
	t.Setenv(pv.EnvToken, "")
	anonymous := runCLI(t, "", false, "get", url, "--stdout")
	if anonymous.exit != pv.ExitAuth || server.consumed != 0 {
		t.Fatalf("get without credentials: exit %d, consumed %d\n%s", anonymous.exit, server.consumed, anonymous.stderr)
	}

	t.Setenv(pv.EnvToken, "pv_pat_"+strings.Repeat("b", 52))
	opened := runCLI(t, "", false, "get", url, "--stdout")
	if opened.exit != 0 || opened.stdout != "for the bot\n" {
		t.Fatalf("get with the agent key: exit %d stdout %q\n%s", opened.exit, opened.stdout, opened.stderr)
	}
	if strings.Contains(opened.stderr+opened.stdout, pv.EncodeBase64URL(bot.PrivateKey)) {
		t.Fatal("the private key was printed")
	}
}

func TestPutToSwappedKeyExitsWithPinMismatch(t *testing.T) {
	server := newSealedServer(t)
	isolateAgents(t, server.URL)
	bot := mustKeyPair(t)
	server.addAgent("bot", bot)

	if result := runCLI(t, "first", false, "put", "-", "--to", "bot", "-q"); result.exit != 0 {
		t.Fatalf("first put: exit %d\n%s", result.exit, result.stderr)
	}

	substitute := mustKeyPair(t)
	server.swapKey("bot", substitute.PublicKey)
	creates := server.creates

	swapped := runCLI(t, "second", false, "put", "-", "--to", "bot", "--json")
	if swapped.exit != pv.ExitFingerprint {
		t.Fatalf("swapped key: exit %d, want %d\n%s", swapped.exit, pv.ExitFingerprint, swapped.stderr)
	}
	errorObject, _ := decodeJSON(t, swapped.stdout)["error"].(map[string]any)
	if errorObject["code"] != pv.CodeFingerprint || !strings.Contains(swapped.stderr, "agent trust bot "+substitute.Fingerprint) {
		t.Fatalf("error = %v\n%s", errorObject, swapped.stderr)
	}
	if server.creates != creates {
		t.Fatal("a share was created despite the pin mismatch")
	}

	// A fingerprint prefix only resolves to an already trusted key: the
	// substitute isn't, so the full fingerprint is required (exit 2).
	if result := runCLI(t, "third", false, "put", "-", "--to", pv.ShortFingerprint(substitute.Fingerprint)); result.exit != pv.ExitUsage || !strings.Contains(result.stderr, "full fingerprint") {
		t.Fatalf("prefix of an untrusted key: exit %d\n%s", result.exit, result.stderr)
	}
	if result := runCLI(t, "x", false, "agent", "trust", "bot", bot.Fingerprint); result.exit != pv.ExitFingerprint {
		t.Fatalf("trusting a fingerprint the server's key lacks: exit %d\n%s", result.exit, result.stderr)
	}
	if result := runCLI(t, "", false, "agent", "trust", "bot", substitute.Fingerprint); result.exit != 0 {
		t.Fatalf("agent trust: exit %d\n%s", result.exit, result.stderr)
	}
	if result := runCLI(t, "fourth", false, "put", "-", "--to", "bot", "-q"); result.exit != 0 {
		t.Fatalf("put after trust: exit %d\n%s", result.exit, result.stderr)
	}
}

func TestPutToNeedsServerSupport(t *testing.T) {
	server := newSealedServer(t)
	isolateAgents(t, server.URL)
	server.features = map[string]any{"expires_in_minutes": true, "max_views": true}
	keys := mustKeyPair(t)

	if result := runCLI(t, "x", false, "put", "-", "--to", "bot"); result.exit != pv.ExitUnsupported {
		t.Fatalf("--to on an old server: exit %d\n%s", result.exit, result.stderr)
	}
	if result := runCLI(t, "x", false, "put", "-", "--to-key", pv.EncodeBase64URL(keys.PublicKey)); result.exit != pv.ExitUnsupported {
		t.Fatalf("--to-key on an old server: exit %d\n%s", result.exit, result.stderr)
	}
	if result := runCLI(t, "x", false, "put", "-", "--to-key", strings.Repeat("A", 43)); result.exit != pv.ExitUsage {
		t.Fatalf("--to-key with a low-order key: exit %d\n%s", result.exit, result.stderr)
	}
	if result := runCLI(t, "x", false, "put", "-", "--to-key", pv.EncodeBase64URL(keys.PublicKey), "--password"); result.exit != pv.ExitUsage {
		t.Fatalf("--to-key with --password: exit %d\n%s", result.exit, result.stderr)
	}
}

func TestPutToPrefixNeedsTrustedKey(t *testing.T) {
	server := newSealedServer(t)
	isolateAgents(t, server.URL)
	bot := mustKeyPair(t)
	server.addAgent("bot", bot)
	prefix := pv.ShortFingerprint(bot.Fingerprint)

	// Never seen: a 40-bit prefix is not enough to trust a key.
	if result := runCLI(t, "x", false, "put", "-", "--to", prefix); result.exit != pv.ExitUsage {
		t.Fatalf("untrusted prefix: exit %d\n%s", result.exit, result.stderr)
	}
	if server.creates != 0 {
		t.Fatal("a share was created for an untrusted prefix")
	}
	// After the full fingerprint (which pins it), the prefix resolves.
	if result := runCLI(t, "x", false, "put", "-", "--to", bot.Fingerprint, "-q"); result.exit != 0 {
		t.Fatalf("full fingerprint: exit %d\n%s", result.exit, result.stderr)
	}
	if result := runCLI(t, "x", false, "put", "-", "--to", prefix, "-q"); result.exit != 0 {
		t.Fatalf("trusted prefix: exit %d\n%s", result.exit, result.stderr)
	}
}

func TestPutToPinsOnlyAfterCreate(t *testing.T) {
	server := newSealedServer(t)
	isolateAgents(t, server.URL)
	bot := mustKeyPair(t)
	server.addAgent("bot", bot)

	server.failCreate = &struct {
		status int
		body   map[string]any
	}{500, map[string]any{"error": "Internal server error"}}
	if result := runCLI(t, "x", false, "put", "-", "--to", "bot"); result.exit != pv.ExitNetwork {
		t.Fatalf("failed create: exit %d\n%s", result.exit, result.stderr)
	}
	if pins, err := pv.LoadPins(server.URL); err != nil || len(pins) != 0 {
		t.Fatalf("a failed put pinned the key: %v %v", pins, err)
	}

	// The server's own fingerprint check maps to exit 8.
	server.failCreate.status = 400
	server.failCreate.body = map[string]any{"error": "recipient.fingerprint does not match the agent", "code": "recipient_fingerprint_mismatch"}
	if result := runCLI(t, "x", false, "put", "-", "--to", "bot"); result.exit != pv.ExitFingerprint {
		t.Fatalf("server fingerprint mismatch: exit %d\n%s", result.exit, result.stderr)
	}

	server.failCreate = nil
	if result := runCLI(t, "x", false, "put", "-", "--to", "bot"); result.exit != 0 || !strings.Contains(result.stderr, "Pinned bot") {
		t.Fatalf("successful put: exit %d\n%s", result.exit, result.stderr)
	}
	if pins, _ := pv.LoadPins(server.URL); pins["bot"].Fingerprint != bot.Fingerprint || pins["bot"].Source != pv.PinSourceTOFU {
		t.Fatalf("pin after success: %+v", pins)
	}
}

// A malicious server turns a normal #k= link into a "sealed" one with
// content it wrapped to the reader's agent key. get must refuse.
func TestGetRefusesSealedClaimOnLinkWithKey(t *testing.T) {
	server := newSealedServer(t)
	isolateAgents(t, server.URL)
	bot := mustKeyPair(t)
	t.Setenv(pv.EnvAgentKey, pv.EncodeBase64URL(bot.PrivateKey))

	created := runCLI(t, "the real content", false, "put", "-", "--json")
	if created.exit != 0 {
		t.Fatalf("put: exit %d\n%s", created.exit, created.stderr)
	}
	output := decodeJSON(t, created.stdout)
	url, _ := output["url"].(string)
	slug, _ := output["slug"].(string)
	if !strings.Contains(url, "#k=") {
		t.Fatalf("a normal link carries its key: %s", url)
	}

	// The server swaps in forged content sealed to the bot's key.
	forgedKey := make([]byte, 32)
	forgedKey[0] = 1
	ciphertext, nonce, err := pv.EncryptPaste(pv.PasteContent{Body: "forged", RenderMode: "plain"}, forgedKey, slug)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := pv.WrapKey(forgedKey, bot.PublicKey, pv.PasteWrapContext(slug))
	if err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	server.pastes[slug]["ciphertext"] = ciphertext
	server.pastes[slug]["nonce"] = nonce
	server.pastes[slug]["recipient"] = map[string]any{"agent_id": "agent-bot", "fingerprint": bot.Fingerprint, "wrapped_key": wrapped}
	server.mu.Unlock()

	result := runCLI(t, "", false, "get", url, "--stdout", "--json")
	if result.exit != pv.ExitDecrypt || strings.Contains(result.stdout, "forged") {
		t.Fatalf("get of a tampered link: exit %d\n%s\n%s", result.exit, result.stdout, result.stderr)
	}
	errorObject, _ := decodeJSON(t, result.stdout)["error"].(map[string]any)
	if errorObject["code"] != pv.CodeSealedConflict || server.consumed != 0 {
		t.Fatalf("error %v, consumed %d", errorObject, server.consumed)
	}
}
