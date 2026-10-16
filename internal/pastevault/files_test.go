package pastevault

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateExpiresHours(t *testing.T) {
	t.Parallel()

	for _, hours := range []int{0, -1, -24} {
		err := ValidateExpiresHours(hours)
		if err == nil || !strings.Contains(err.Error(), "must be at least 1") {
			t.Fatalf("expected error for %d hours, got %v", hours, err)
		}
	}

	if err := ValidateExpiresHours(MaxExpiresHours + 1); err == nil {
		t.Fatal("expected error above the server maximum")
	}

	for _, hours := range []int{1, 24, MaxExpiresHours} {
		if err := ValidateExpiresHours(hours); err != nil {
			t.Fatalf("unexpected error for %d hours: %v", hours, err)
		}
	}
}

func TestCheckShareAccess(t *testing.T) {
	t.Parallel()

	keyed := ShareReference{Slug: "slug123", Key: []byte("key")}
	keyless := ShareReference{Slug: "slug123"}
	passwordMeta := FileShareMetaResponse{PasswordProtected: true, BurnAfterRead: true}
	keyMeta := FileShareMetaResponse{BurnAfterRead: true}

	if err := CheckShareAccess(passwordMeta, keyless, ""); err == nil || !strings.Contains(err.Error(), "--password") {
		t.Fatalf("expected password error, got %v", err)
	}
	if err := CheckShareAccess(passwordMeta, keyless, "hunter2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := CheckShareAccess(keyMeta, keyless, ""); err == nil || !strings.Contains(err.Error(), "missing share key") {
		t.Fatalf("expected missing key error, got %v", err)
	}
	if err := CheckShareAccess(keyMeta, keyed, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownloadManifestWritesPrivateFilesWithGrant(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	plaintext := []byte("top secret contents")
	ciphertext, nonce, err := EncryptFileChunk(plaintext, key, "slug123", "file_1", 0)
	if err != nil {
		t.Fatalf("EncryptFileChunk returned error: %v", err)
	}

	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get(DownloadGrantHeader); got != "grant-123" {
			t.Fatalf("unexpected download grant header: %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(ciphertext))),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})

	targetDir := t.TempDir()
	// --overwrite must also tighten the mode of a pre-existing file.
	existingPath := filepath.Join(targetDir, "secret.txt")
	if err := os.WriteFile(existingPath, []byte("old"), 0o644); err != nil {
		t.Fatalf("failed to seed file: %v", err)
	}

	manifest := FileShareManifest{
		Version: "v1",
		Paste:   &FileShareManifestPaste{Title: "Note", Body: "note body", RenderMode: "markdown"},
		Files: []FileShareManifestFile{{
			ID:     "file_1",
			Name:   "secret.txt",
			Size:   int64(len(plaintext)),
			Chunks: []FileShareChunkInfo{{Index: 0, Nonce: nonce, PlaintextSize: len(plaintext)}},
		}},
	}

	plan, err := PlanDownload(manifest, targetDir, true, false)
	if err != nil {
		t.Fatalf("PlanDownload returned error: %v", err)
	}
	if len(plan.Renamed) != 0 {
		t.Fatalf("--overwrite should not rename: %+v", plan.Renamed)
	}

	if err := DownloadManifest(context.Background(), client, manifest, key, "slug123", "grant-123", plan); err != nil {
		t.Fatalf("DownloadManifest returned error: %v", err)
	}

	written, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(written) != string(plaintext) {
		t.Fatalf("unexpected file contents: %q", written)
	}

	if runtime.GOOS == "windows" {
		return
	}

	for _, name := range []string{"secret.txt", "NOTE.md"} {
		info, err := os.Stat(filepath.Join(targetDir, name))
		if err != nil {
			t.Fatalf("failed to stat %s: %v", name, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("%s has mode %o, want 600", name, mode)
		}
	}
}

func conflictManifest() FileShareManifest {
	return FileShareManifest{
		Version: "v1",
		Paste:   &FileShareManifestPaste{Body: "note", RenderMode: "markdown"},
		Files: []FileShareManifestFile{
			{ID: "file_1", Name: "secret.txt"},
			{ID: "file_2", Name: "secret.txt"},
			{ID: "file_3", Name: "other.bin"},
			{ID: "file_4", Name: ".env"},
		},
	}
}

func TestPlanDownloadRenamesConflictsForBurnedShares(t *testing.T) {
	t.Parallel()

	targetDir := t.TempDir()
	for _, name := range []string{"NOTE.md", "secret.txt", "secret (1).txt", ".env"} {
		if err := os.WriteFile(filepath.Join(targetDir, name), []byte("keep me"), 0o600); err != nil {
			t.Fatalf("failed to seed %s: %v", name, err)
		}
	}

	plan, err := PlanDownload(conflictManifest(), targetDir, false, true)
	if err != nil {
		t.Fatalf("PlanDownload returned error: %v", err)
	}

	if want := filepath.Join(targetDir, "NOTE (1).md"); plan.NotePath != want {
		t.Fatalf("note path = %s, want %s", plan.NotePath, want)
	}
	wantFiles := []string{"secret (2).txt", "secret (3).txt", "other.bin", ".env (1)"}
	for index, name := range wantFiles {
		if want := filepath.Join(targetDir, name); plan.FilePaths[index] != want {
			t.Fatalf("file %d path = %s, want %s", index, plan.FilePaths[index], want)
		}
	}
	if len(plan.Renamed) != 4 {
		t.Fatalf("expected 4 renames, got %+v", plan.Renamed)
	}
}

func TestPlanDownloadRefusesConflictsBeforeDownloading(t *testing.T) {
	t.Parallel()

	targetDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetDir, "other.bin"), []byte("keep me"), 0o600); err != nil {
		t.Fatalf("failed to seed file: %v", err)
	}

	_, err := PlanDownload(conflictManifest(), targetDir, false, false)
	if err == nil || !strings.Contains(err.Error(), "--overwrite") {
		t.Fatalf("expected --overwrite error, got %v", err)
	}

	// Repeated names inside one share never clobber each other, even with --overwrite.
	plan, err := PlanDownload(conflictManifest(), targetDir, true, false)
	if err != nil {
		t.Fatalf("PlanDownload returned error: %v", err)
	}
	if plan.FilePaths[0] == plan.FilePaths[1] {
		t.Fatalf("duplicate names mapped to one path: %s", plan.FilePaths[0])
	}
}

func TestDownloadManifestKeepsExistingFilesWhenRenaming(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	plaintext := []byte("fresh download")
	ciphertext, nonce, err := EncryptFileChunk(plaintext, key, "slug123", "file_1", 0)
	if err != nil {
		t.Fatalf("EncryptFileChunk returned error: %v", err)
	}
	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(ciphertext))),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})

	targetDir := t.TempDir()
	for _, name := range []string{"NOTE.md", "secret.txt"} {
		if err := os.WriteFile(filepath.Join(targetDir, name), []byte("keep me"), 0o644); err != nil {
			t.Fatalf("failed to seed %s: %v", name, err)
		}
	}

	manifest := FileShareManifest{
		Version: "v1",
		Paste:   &FileShareManifestPaste{Body: "note body", RenderMode: "markdown"},
		Files: []FileShareManifestFile{{
			ID:     "file_1",
			Name:   "secret.txt",
			Chunks: []FileShareChunkInfo{{Index: 0, Nonce: nonce, PlaintextSize: len(plaintext)}},
		}},
	}
	plan, err := PlanDownload(manifest, targetDir, false, true)
	if err != nil {
		t.Fatalf("PlanDownload returned error: %v", err)
	}
	if err := DownloadManifest(context.Background(), client, manifest, key, "slug123", "grant", plan); err != nil {
		t.Fatalf("DownloadManifest returned error: %v", err)
	}

	for name, want := range map[string]string{
		"NOTE.md":        "keep me",
		"secret.txt":     "keep me",
		"NOTE (1).md":    "note body",
		"secret (1).txt": "fresh download",
	} {
		got, err := os.ReadFile(filepath.Join(targetDir, name))
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestEnsureWritableDir(t *testing.T) {
	t.Parallel()

	nested := filepath.Join(t.TempDir(), "a", "b")
	if err := EnsureWritableDir(nested); err != nil {
		t.Fatalf("EnsureWritableDir returned error: %v", err)
	}
	entries, err := os.ReadDir(nested)
	if err != nil || len(entries) != 0 {
		t.Fatalf("expected empty directory, got %v (%v)", entries, err)
	}

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return
	}
	if info, err := os.Stat(nested); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 directory, got %v (%v)", info.Mode().Perm(), err)
	}

	readOnly := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatalf("failed to create read-only dir: %v", err)
	}
	if err := EnsureWritableDir(readOnly); err == nil {
		t.Fatal("expected an error for a read-only directory")
	}
}

func TestDownloadChunkRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) < 3 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Status:     "503 Service Unavailable",
				Body:       io.NopCloser(http.NoBody),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("chunk")),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	client.chunkRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}

	data, err := client.downloadChunkWithRetry(context.Background(), "slug123", "grant", "file_1", 0)
	if err != nil || string(data) != "chunk" {
		t.Fatalf("expected chunk after retries, got %q (%v)", data, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls.Load())
	}
}

func TestDownloadChunkDoesNotRetryFinalErrors(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	client := newTestClient(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusGone,
			Status:     "410 Gone",
			Body:       io.NopCloser(strings.NewReader(`{"error":"File share has been burned"}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	client.chunkRetryDelays = []time.Duration{time.Millisecond, time.Millisecond}

	if _, err := client.downloadChunkWithRetry(context.Background(), "slug123", "grant", "file_1", 0); err == nil {
		t.Fatal("expected an error")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected a single attempt, got %d", calls.Load())
	}
}
