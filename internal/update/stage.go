package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func stagingDir() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "staging"), nil
}

func stagedBinaryPath() (string, error) {
	dir, err := stagingDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, binaryBaseName()), nil
}

func stagedManifestPath() (string, error) {
	dir, err := stagingDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "manifest.json"), nil
}

func loadStagedManifest() (binaryManifest, bool) {
	var manifest binaryManifest
	path, err := stagedManifestPath()
	if err != nil {
		return manifest, false
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.Version == "" {
		return binaryManifest{}, false
	}
	return manifest, true
}

func StagedVersion() string {
	manifest, ok := loadStagedManifest()
	if !ok {
		return ""
	}
	return manifest.Version
}

func ClearStaging() {
	dir, err := stagingDir()
	if err == nil {
		_ = os.RemoveAll(dir)
	}
}

func Stage(ctx context.Context, release *Release) error {
	binary, err := fetchVerifiedBinary(ctx, release)
	if err != nil {
		return err
	}
	dir, err := stagingDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	binaryPath, err := stagedBinaryPath()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(binaryPath, binary, 0o755); err != nil {
		return err
	}
	sum := sha256.Sum256(binary)
	manifest := binaryManifest{
		Version: release.TagName,
		SHA256:  hex.EncodeToString(sum[:]),
		GOOS:    runtime.GOOS,
		GOARCH:  runtime.GOARCH,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	manifestPath, err := stagedManifestPath()
	if err != nil {
		return err
	}
	return writeFileAtomic(manifestPath, append(data, '\n'), 0o600)
}

func ApplyStaged(currentVersion, targetPath string) (string, error) {
	manifest, ok := loadStagedManifest()
	if !ok {
		return "", nil
	}
	if manifest.GOOS != runtime.GOOS || manifest.GOARCH != runtime.GOARCH ||
		!IsNewer(manifest.Version, currentVersion) || manifest.Version == SkipVersion() {
		ClearStaging()
		return "", nil
	}
	binaryPath, err := stagedBinaryPath()
	if err != nil {
		ClearStaging()
		return "", nil
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		ClearStaging()
		return "", nil
	}
	sum := sha256.Sum256(binary)
	if hex.EncodeToString(sum[:]) != manifest.SHA256 {
		ClearStaging()
		return "", nil
	}
	if err := swapBinary(binary, targetPath, currentVersion); err != nil {
		ClearStaging()
		return "", err
	}
	return manifest.Version, nil
}

func acquireStageLock() (release func(), ok bool) {
	dir, err := configDir()
	if err != nil || os.MkdirAll(dir, 0o700) != nil {
		return nil, false
	}
	lockPath := filepath.Join(dir, "staging.lock")
	for attempt := 0; attempt < 2; attempt++ {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = file.Close()
			return func() { _ = os.Remove(lockPath) }, true
		}
		info, statErr := os.Stat(lockPath)
		if statErr != nil || time.Since(info.ModTime()) < 15*time.Minute {
			return nil, false
		}
		_ = os.Remove(lockPath)
	}
	return nil, false
}
