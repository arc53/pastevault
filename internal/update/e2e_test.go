package update

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"aead.dev/minisign"
)

// TestCLIUpdateEndToEnd builds two real PasteVault executables, serves the
// newer one as a signed GitHub-style release, updates the running path through
// the CLI command, then rolls it back and executes it again.
func TestCLIUpdateEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compiled CLI update lifecycle in short mode")
	}
	moduleCache := goEnv(t, "GOMODCACHE")
	buildCache := goEnv(t, "GOCACHE")
	setupTestConfig(t)
	t.Setenv("GOMODCACHE", moduleCache)
	t.Setenv("GOCACHE", buildCache)

	publicKey, privateKey, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var (
		archive   []byte
		checksums []byte
		signature []byte
	)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/releases/latest":
			payload := Release{
				TagName: "v2.0.0",
				HTMLURL: serverURL(request) + "/release/v2.0.0",
				Assets: []Asset{
					{Name: AssetName(), DownloadURL: serverURL(request) + "/archive"},
					{Name: checksumsAssetName, DownloadURL: serverURL(request) + "/checksums"},
					{Name: checksumSignatureName, DownloadURL: serverURL(request) + "/signature"},
				},
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(payload)
		case "/archive":
			_, _ = response.Write(archive)
		case "/checksums":
			_, _ = response.Write(checksums)
		case "/signature":
			_, _ = response.Write(signature)
		default:
			http.NotFound(response, request)
		}
	}))
	releaseServerURL := "http://" + server.Listener.Addr().String()

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	executableName := "pastevault"
	if runtime.GOOS == "windows" {
		executableName += ".exe"
	}
	target := filepath.Join(binDir, executableName)
	newExecutable := filepath.Join(binDir, "pastevault-new"+filepath.Ext(executableName))
	buildCLI(t, repoRoot, newExecutable, "v2.0.0", releaseServerURL+"/releases/latest", publicKey.String())
	newBinary, err := os.ReadFile(newExecutable)
	if err != nil {
		t.Fatal(err)
	}
	archive = buildArchive(t, newBinary)
	sum := sha256.Sum256(archive)
	checksums = []byte(fmt.Sprintf("%x  %s\n", sum, AssetName()))
	signature = minisign.Sign(privateKey, checksums)
	buildCLI(t, repoRoot, target, "v1.0.0", releaseServerURL+"/releases/latest", publicKey.String())
	server.Start()
	defer server.Close()

	environment := append(os.Environ(), "PASTEVAULT_NO_UPDATE_CHECK=1")
	runCLI(t, target, environment, "update", "--yes")
	if output := runCLI(t, target, environment, "version"); !strings.Contains(output, "pastevault v2.0.0") {
		t.Fatalf("updated version output = %q", output)
	}
	runCLI(t, target, environment, "update", "--rollback")
	if output := runCLI(t, target, environment, "version"); !strings.Contains(output, "pastevault v1.0.0") {
		t.Fatalf("rolled-back version output = %q", output)
	}
}

func buildCLI(t *testing.T, repoRoot, output, version, releaseURL, publicKey string) {
	t.Helper()
	ldflags := strings.Join([]string{
		"-X", "main.version=" + version,
		"-X", "main.commit=e2e",
		"-X", "main.date=e2e",
		"-X", "github.com/arc53/pastevault/internal/update.latestReleaseURL=" + releaseURL,
		"-X", "github.com/arc53/pastevault/internal/update.embeddedPublicKey=" + publicKey,
	}, " ")
	command := exec.Command("go", "build", "-ldflags", ldflags, "-o", output, "./cmd/pastevault")
	command.Dir = repoRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, output)
	}
}

func runCLI(t *testing.T, executable string, environment []string, args ...string) string {
	t.Helper()
	command := exec.Command(executable, args...)
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", executable, strings.Join(args, " "), err, output)
	}
	return string(output)
}

func serverURL(request *http.Request) string {
	return "http://" + request.Host
}

func goEnv(t *testing.T, name string) string {
	t.Helper()
	command := exec.Command("go", "env", name)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go env %s failed: %v", name, err)
	}
	return strings.TrimSpace(string(output))
}
