package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"aead.dev/minisign"
)

func TestVersionComparison(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"v1.2.3", true},
		{"1.2.3", true},
		{"v10.0.0", true},
		{"dev", false},
		{"v1.2.3-dirty", false},
		{"v1.2.3-beta.1", false},
		{"v1.2.3+local", false},
	}
	for _, test := range tests {
		if got := IsReleaseVersion(test.version); got != test.valid {
			t.Errorf("IsReleaseVersion(%q) = %v, want %v", test.version, got, test.valid)
		}
	}
	if !IsNewer("v1.10.0", "v1.9.9") {
		t.Fatal("expected v1.10.0 to be newer than v1.9.9")
	}
	if IsNewer("v1.0.0", "v1.0.0") {
		t.Fatal("equal versions must not compare as newer")
	}
}

func TestPlatformAssetNames(t *testing.T) {
	tests := []struct {
		goos   string
		goarch string
		want   string
	}{
		{"darwin", "amd64", "pastevault_darwin_x86_64.tar.gz"},
		{"darwin", "arm64", "pastevault_darwin_arm64.tar.gz"},
		{"linux", "amd64", "pastevault_linux_x86_64.tar.gz"},
		{"linux", "arm64", "pastevault_linux_arm64.tar.gz"},
		{"windows", "amd64", "pastevault_windows_x86_64.zip"},
		{"windows", "arm64", "pastevault_windows_arm64.zip"},
	}
	for _, test := range tests {
		if got := platformAssetName(test.goos, test.goarch); got != test.want {
			t.Errorf("platformAssetName(%q, %q) = %q, want %q", test.goos, test.goarch, got, test.want)
		}
	}
}

func TestHomebrewPaths(t *testing.T) {
	for _, path := range []string{
		"/usr/local/Cellar/pastevault/1.0.0/bin/pastevault",
		"/opt/homebrew/Caskroom/pastevault/1.0.0/pastevault",
		"/home/linuxbrew/.linuxbrew/Cellar/pastevault/1.0.0/bin/pastevault",
	} {
		if !IsHomebrewPath(path) {
			t.Errorf("IsHomebrewPath(%q) = false", path)
		}
	}
	if IsHomebrewPath("/home/alex/.local/bin/pastevault") {
		t.Fatal("direct install was classified as Homebrew")
	}
}

func TestSettingsModes(t *testing.T) {
	setupTestConfig(t)
	mode, err := LoadMode()
	if err != nil || mode != ModeOn {
		t.Fatalf("LoadMode() = %q, %v, want %q, nil", mode, err, ModeOn)
	}
	for _, want := range []string{ModeNotify, ModeOff, ModeOn} {
		if err := SetMode(want); err != nil {
			t.Fatal(err)
		}
		got, err := LoadMode()
		if err != nil || got != want {
			t.Fatalf("LoadMode() = %q, %v, want %q, nil", got, err, want)
		}
	}
	if err := SetMode("sometimes"); err == nil {
		t.Fatal("expected invalid mode to fail")
	}
}

func TestFetchLatest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("User-Agent") != "pastevault-updater" {
			t.Errorf("unexpected User-Agent %q", request.Header.Get("User-Agent"))
		}
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprint(response, `{"tag_name":"v2.0.0","html_url":"https://example.test/release","assets":[]}`)
	}))
	defer server.Close()

	previousURL := latestReleaseURL
	latestReleaseURL = server.URL
	t.Cleanup(func() { latestReleaseURL = previousURL })
	release, err := FetchLatest(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if release.TagName != "v2.0.0" {
		t.Fatalf("TagName = %q, want v2.0.0", release.TagName)
	}
}

func TestValidateReleaseRejectsBadSignature(t *testing.T) {
	setupTestConfig(t)
	release, closeServer := serveRelease(t, "v2.0.0", []byte("new binary"))
	defer closeServer()

	signature := release.asset(checksumSignatureName)
	signature.DownloadURL += "?tamper=1"
	if err := ValidateRelease(context.Background(), release); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("ValidateRelease() error = %v, want signature verification failure", err)
	}
}

func TestStageApplyRollbackEndToEnd(t *testing.T) {
	setupTestConfig(t)
	oldBinary := []byte("pastevault version 1")
	newBinary := []byte("pastevault version 2")
	release, closeServer := serveRelease(t, "v2.0.0", newBinary)
	defer closeServer()

	if err := ValidateRelease(context.Background(), release); err != nil {
		t.Fatalf("ValidateRelease() error: %v", err)
	}
	if err := Stage(context.Background(), release); err != nil {
		t.Fatalf("Stage() error: %v", err)
	}
	if got := StagedVersion(); got != "v2.0.0" {
		t.Fatalf("StagedVersion() = %q, want v2.0.0", got)
	}

	target := filepath.Join(t.TempDir(), binaryBaseName())
	if err := os.WriteFile(target, oldBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	installed, err := ApplyStaged("v1.0.0", target)
	if err != nil || installed != "v2.0.0" {
		t.Fatalf("ApplyStaged() = %q, %v, want v2.0.0, nil", installed, err)
	}
	if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, newBinary) {
		t.Fatalf("installed binary = %q, %v, want %q", got, err, newBinary)
	}
	if StagedVersion() != "" {
		t.Fatal("staging area was not cleared")
	}

	rolledTo, err := Rollback("v2.0.0", target)
	if err != nil || rolledTo != "v1.0.0" {
		t.Fatalf("Rollback() = %q, %v, want v1.0.0, nil", rolledTo, err)
	}
	if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, oldBinary) {
		t.Fatalf("rolled back binary = %q, %v, want %q", got, err, oldBinary)
	}
	if got := SkipVersion(); got != "v2.0.0" {
		t.Fatalf("SkipVersion() = %q, want v2.0.0", got)
	}
}

func TestApplyStagedRejectsCorruptBinary(t *testing.T) {
	setupTestConfig(t)
	release, closeServer := serveRelease(t, "v2.0.0", []byte("valid binary"))
	defer closeServer()
	if err := Stage(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	binaryPath, err := stagedBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), binaryBaseName())
	if err := os.WriteFile(target, []byte("current"), 0o755); err != nil {
		t.Fatal(err)
	}
	version, err := ApplyStaged("v1.0.0", target)
	if err != nil || version != "" {
		t.Fatalf("ApplyStaged() = %q, %v, want empty, nil", version, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "current" {
		t.Fatalf("target was modified: %q", got)
	}
	if StagedVersion() != "" {
		t.Fatal("corrupt staging area was not cleared")
	}
}

func TestRollbackRejectsMissingManifest(t *testing.T) {
	setupTestConfig(t)
	backupPath, err := backupBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte("untrusted backup"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), binaryBaseName())
	if err := os.WriteFile(target, []byte("current"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback("v2.0.0", target); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("Rollback() error = %v, want missing manifest failure", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "current" {
		t.Fatalf("target was modified: %q", got)
	}
}

func TestStageRetryBackoff(t *testing.T) {
	setupTestConfig(t)
	if err := RecordCheck(&Release{TagName: "v2.0.0"}); err != nil {
		t.Fatal(err)
	}
	if !ShouldSpawnWorker("v1.0.0", ModeOn) {
		t.Fatal("expected worker before first staging attempt")
	}
	if err := recordStageAttempt("v2.0.0"); err != nil {
		t.Fatal(err)
	}
	if ShouldSpawnWorker("v1.0.0", ModeOn) {
		t.Fatal("worker ignored staging retry backoff")
	}
	state := loadState()
	state.LastStageAttempt = time.Now().Add(-stageRetryInterval - time.Minute)
	if err := saveState(state); err != nil {
		t.Fatal(err)
	}
	if !ShouldSpawnWorker("v1.0.0", ModeOn) {
		t.Fatal("expected worker after staging retry backoff")
	}
}

func TestConcurrentStateUpdatesPreserveRollbackSkip(t *testing.T) {
	setupTestConfig(t)
	var wait sync.WaitGroup
	errors := make(chan error, 21)
	wait.Add(1)
	go func() {
		defer wait.Done()
		errors <- SetSkipVersion("v2.0.0")
	}()
	for index := 0; index < 20; index++ {
		wait.Add(1)
		go func(version int) {
			defer wait.Done()
			errors <- RecordCheck(&Release{TagName: fmt.Sprintf("v3.0.%d", version)})
		}(index)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := SkipVersion(); got != "v2.0.0" {
		t.Fatalf("SkipVersion() = %q, want v2.0.0", got)
	}
}

func TestDownloadLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte("12345"))
	}))
	defer server.Close()
	if _, err := download(context.Background(), server.URL, 4); err == nil {
		t.Fatal("expected oversized download to fail")
	}
}

func setupTestConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("APPDATA", filepath.Join(dir, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(dir, "AppData", "Local"))
	previousKey := embeddedPublicKey
	t.Cleanup(func() { embeddedPublicKey = previousKey })
}

func serveRelease(t *testing.T, version string, binary []byte) (*Release, func()) {
	t.Helper()
	publicKey, privateKey, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	embeddedPublicKey = publicKey.String()

	archive := buildArchive(t, binary)
	archiveName := AssetName()
	sum := sha256.Sum256(archive)
	checksums := []byte(fmt.Sprintf("%x  %s\n", sum, archiveName))
	signature := minisign.Sign(privateKey, checksums)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/archive":
			_, _ = response.Write(archive)
		case "/checksums":
			_, _ = response.Write(checksums)
		case "/signature":
			if request.URL.Query().Get("tamper") != "" {
				_, _ = response.Write([]byte("not a signature"))
				return
			}
			_, _ = response.Write(signature)
		default:
			http.NotFound(response, request)
		}
	}))

	release := &Release{
		TagName: version,
		HTMLURL: server.URL + "/release",
		Assets: []Asset{
			{Name: archiveName, DownloadURL: server.URL + "/archive"},
			{Name: checksumsAssetName, DownloadURL: server.URL + "/checksums"},
			{Name: checksumSignatureName, DownloadURL: server.URL + "/signature"},
		},
	}
	return release, server.Close
}

func buildArchive(t *testing.T, binary []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if runtime.GOOS == "windows" {
		writer := zip.NewWriter(&buffer)
		file, err := writer.Create("pastevault.exe")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(binary); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}

	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name:     "pastevault",
		Mode:     0o755,
		Size:     int64(len(binary)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
