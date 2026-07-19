package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	ModeOn     = "on"
	ModeNotify = "notify"
	ModeOff    = "off"

	defaultLatestReleaseURL = "https://api.github.com/repos/arc53/pastevault/releases/latest"
	maxReleaseResponseBytes = 2 << 20
)

// embeddedPublicKey is populated by GoReleaser through -ldflags. It is the
// minisign public key used to authenticate checksums.txt before any update is
// installed.
var embeddedPublicKey string

var latestReleaseURL = defaultLatestReleaseURL

type Release struct {
	TagName    string  `json:"tag_name"`
	HTMLURL    string  `json:"html_url"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

type Asset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

// IsReleaseVersion reports whether version is an exact stable semantic
// version. Development, dirty, and prerelease builds never update themselves.
func IsReleaseVersion(version string) bool {
	version = normalizeVersion(version)
	return semver.IsValid(version) && semver.Prerelease(version) == "" && semver.Build(version) == ""
}

func IsNewer(latest, current string) bool {
	return semver.Compare(normalizeVersion(latest), normalizeVersion(current)) > 0
}

func HasEmbeddedPublicKey() bool {
	return strings.TrimSpace(embeddedPublicKey) != ""
}

func IsHomebrewPath(executablePath string) bool {
	clean := filepath.ToSlash(executablePath)
	return strings.Contains(clean, "/Cellar/") || strings.Contains(clean, "/Caskroom/") || strings.Contains(clean, "/homebrew/")
}

func FetchLatest(ctx context.Context, timeout time.Duration) (*Release, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pastevault-updater")

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("GitHub API returned %s", response.Status)
	}

	var release Release
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxReleaseResponseBytes))
	if err := decoder.Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode release response: %w", err)
	}
	if release.TagName == "" {
		return nil, fmt.Errorf("release response is missing a tag name")
	}
	if release.Draft || release.Prerelease || !IsReleaseVersion(release.TagName) {
		return nil, fmt.Errorf("latest release %q is not a stable release", release.TagName)
	}
	return &release, nil
}

func (r *Release) asset(name string) *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}
