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

			if r.Header.Get("X-Upload-Token") != "upload-token" {
				t.Fatalf("unexpected X-Upload-Token header: %q", r.Header.Get("X-Upload-Token"))
			}

			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(http.NoBody),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		}),
	}

	err = client.CompleteFileShare(context.Background(), "test", "upload-token", CompleteFileShareRequest{
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

func newTestClient(t *testing.T, handler func(*http.Request) (*http.Response, error)) *Client {
	t.Helper()

	client, err := NewClient("https://api.pastevault.dev", "test")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	client.httpClient = &http.Client{Transport: roundTripFunc(handler)}
	return client
}

func emptyResponse(r *http.Request, status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(http.NoBody),
		Header:     make(http.Header),
		Request:    r,
	}
}

func TestUploadFileShareChunkSendsUploadToken(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/file-shares/slug123/chunks/file_1/3" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get(UploadTokenHeader); got != "secret-token" {
			t.Fatalf("unexpected upload token header: %q", got)
		}
		return emptyResponse(r, http.StatusNoContent), nil
	})

	if err := client.UploadFileShareChunk(context.Background(), "slug123", "secret-token", "file_1", 3, []byte("chunk")); err != nil {
		t.Fatalf("UploadFileShareChunk returned error: %v", err)
	}
}

func TestUploadFileShareChunkOmitsEmptyUploadToken(t *testing.T) {
	t.Parallel()

	// Older servers issue no token; the CLI must not send an empty header.
	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		if _, ok := r.Header[UploadTokenHeader]; ok {
			t.Fatalf("expected no %s header", UploadTokenHeader)
		}
		return emptyResponse(r, http.StatusNoContent), nil
	})

	if err := client.UploadFileShareChunk(context.Background(), "slug123", "", "file_1", 0, []byte("chunk")); err != nil {
		t.Fatalf("UploadFileShareChunk returned error: %v", err)
	}
}

func TestUploadFileShareChunkSurfacesUpdateHint(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Body:       io.NopCloser(strings.NewReader(`{"error":"Missing upload token (X-Upload-Token). Your PasteVault client is out of date; please update it and try again."}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})

	err := client.UploadFileShareChunk(context.Background(), "slug123", "", "file_1", 0, []byte("chunk"))
	if err == nil || !strings.Contains(err.Error(), "please update it") {
		t.Fatalf("expected update hint in error, got %v", err)
	}
}

func TestCreateFileShareSendsBurnAfterRead(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		if !strings.Contains(string(body), `"burn_after_read":true`) {
			t.Fatalf("expected burn_after_read in body: %s", body)
		}
		if !strings.Contains(string(body), `"expires_in_hours":1`) {
			t.Fatalf("expected expires_in_hours in body: %s", body)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(`{"slug":"slug123","expires_at":null,"burn_after_read":true,"upload_token":"tok"}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})

	response, err := client.CreateFileShare(context.Background(), CreateFileShareRequest{
		Slug:           "slug123",
		ExpiresInHours: 1,
		FileCount:      1,
		TotalSizeBytes: 5,
		BurnAfterRead:  true,
	})
	if err != nil {
		t.Fatalf("CreateFileShare returned error: %v", err)
	}
	if response.UploadToken != "tok" || !response.BurnAfterRead {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestDownloadFileShareChunkSendsGrant(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get(DownloadGrantHeader); got != "grant-123" {
			t.Fatalf("unexpected download grant header: %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ciphertext")),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})

	data, err := client.DownloadFileShareChunk(context.Background(), "slug123", "grant-123", "file_1", 0)
	if err != nil {
		t.Fatalf("DownloadFileShareChunk returned error: %v", err)
	}
	if string(data) != "ciphertext" {
		t.Fatalf("unexpected chunk: %q", data)
	}
}

func TestGetFileShareMetaUsesMetaEndpoint(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/file-shares/slug123/meta" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"slug":"slug123","burn_after_read":true,"password_protected":true,"file_count":2}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})

	meta, err := client.GetFileShareMeta(context.Background(), "slug123")
	if err != nil {
		t.Fatalf("GetFileShareMeta returned error: %v", err)
	}
	if !meta.BurnAfterRead || !meta.PasswordProtected || meta.FileCount != 2 {
		t.Fatalf("unexpected meta: %+v", meta)
	}
}

func TestSignOutRevokesBearerSession(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.String() != "https://api.pastevault.dev/api/auth/sign-out" {
			t.Fatalf("unexpected URL: %s", r.URL.String())
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"success":true}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	client.SetAuthToken("test-token")

	if err := client.SignOut(context.Background()); err != nil {
		t.Fatalf("SignOut returned error: %v", err)
	}
}
