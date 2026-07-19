package pastevault

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDoJSONAllowsNilTarget(t *testing.T) {
	t.Parallel()

	client, err := NewClient("https://api.pastevault.dev", "test")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected method: %s", r.Method)
			}

			if r.URL.String() != "https://api.pastevault.dev/api/file-shares/test/complete" {
				t.Fatalf("unexpected URL: %s", r.URL.String())
			}

			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(http.NoBody),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		}),
	}

	err = client.CompleteFileShare(context.Background(), "test", CompleteFileShareRequest{
		ManifestCiphertext: "ciphertext",
		ManifestNonce:      "nonce",
	})
	if err != nil {
		t.Fatalf("CompleteFileShare returned error: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestResolvePublicBaseURLStripsAPIHost(t *testing.T) {
	t.Parallel()

	publicURL := ResolvePublicBaseURL("https://api.pastevault.dev")
	if publicURL != "https://pastevault.dev" {
		t.Fatalf("unexpected public URL: %s", publicURL)
	}
}

func TestParseShareReferenceMapsPublicShareURLBackToAPI(t *testing.T) {
	t.Parallel()

	ref, err := ParseShareReference(
		"https://pastevault.dev/f/w5SfkQSGJAZS#k=bFL-OMRbUfar5MkwE0WrkhunoT2k_jwB5HKL_OxGpGY",
		"https://api.pastevault.dev",
		"https://pastevault.dev",
	)
	if err != nil {
		t.Fatalf("ParseShareReference returned error: %v", err)
	}

	if ref.Server != "https://api.pastevault.dev" {
		t.Fatalf("unexpected server: %s", ref.Server)
	}

	if ref.Slug != "w5SfkQSGJAZS" {
		t.Fatalf("unexpected slug: %s", ref.Slug)
	}

	if len(ref.Key) == 0 {
		t.Fatal("expected parsed share key")
	}
}

func TestParseShortShareReferenceUsesDefaultServer(t *testing.T) {
	t.Parallel()

	ref, err := ParseShareReference(
		"w5SfkQSGJAZS#k=bFL-OMRbUfar5MkwE0WrkhunoT2k_jwB5HKL_OxGpGY",
		"https://api.pastevault.dev",
		"https://pastevault.dev",
	)
	if err != nil {
		t.Fatalf("ParseShareReference returned error: %v", err)
	}

	if ref.Server != "https://api.pastevault.dev" {
		t.Fatalf("unexpected server: %s", ref.Server)
	}

	if ref.Slug != "w5SfkQSGJAZS" {
		t.Fatalf("unexpected slug: %s", ref.Slug)
	}

	if len(ref.Key) == 0 {
		t.Fatal("expected parsed share key")
	}
}

func TestGetAuthSessionUsesAuthBaseAndBearerToken(t *testing.T) {
	t.Parallel()

	client, err := NewClient("https://api.pastevault.dev", "test")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	client.SetAuthToken("test-token")
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method: %s", r.Method)
			}

			if r.URL.String() != "https://api.pastevault.dev/api/auth/get-session" {
				t.Fatalf("unexpected URL: %s", r.URL.String())
			}

			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Fatalf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"session":{"id":"session_123","expiresAt":"2026-03-16T12:00:00Z","token":"token_123","userId":"user_123"},"user":{"id":"user_123","email":"alex@example.com","username":"alextu"}}`,
				)),
				Header:  make(http.Header),
				Request: r,
			}, nil
		}),
	}

	session, err := client.GetAuthSession(context.Background())
	if err != nil {
		t.Fatalf("GetAuthSession returned error: %v", err)
	}
	if session == nil {
		t.Fatal("expected session")
	}
	if session.User.Email != "alex@example.com" {
		t.Fatalf("unexpected email: %s", session.User.Email)
	}
}

func TestGetAuthSessionAllowsNullResponse(t *testing.T) {
	t.Parallel()

	client, err := NewClient("https://api.pastevault.dev", "test")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("null")),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		}),
	}

	session, err := client.GetAuthSession(context.Background())
	if err != nil {
		t.Fatalf("GetAuthSession returned error: %v", err)
	}
	if session != nil {
		t.Fatal("expected nil session")
	}
}
