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
		writeTestJSON(w, 200, map[string]any{
			"slug": r.PathValue("slug"), "max_views": 1, "views_remaining": 1,
			"recipient": recipientMeta, "requires_recipient_auth": requiresAuth,
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

	// A fingerprint prefix still checks the pin; the full fingerprint is
	// itself the verification.
	if result := runCLI(t, "third", false, "put", "-", "--to", pv.ShortFingerprint(substitute.Fingerprint)); result.exit != pv.ExitFingerprint {
		t.Fatalf("prefix with swapped key: exit %d\n%s", result.exit, result.stderr)
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
