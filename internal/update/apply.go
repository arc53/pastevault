package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"aead.dev/minisign"
	"github.com/minio/selfupdate"
)

const (
	checksumsAssetName          = "checksums.txt"
	checksumSignatureName       = "checksums.txt.minisig"
	maxChecksumsBytes     int64 = 2 << 20
	maxSignatureBytes     int64 = 64 << 10
	maxArchiveBytes       int64 = 256 << 20
	maxBinaryBytes        int64 = 192 << 20
	downloadTimeout             = 5 * time.Minute
)

type binaryManifest struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
}

func AssetName() string {
	return platformAssetName(runtime.GOOS, runtime.GOARCH)
}

func platformAssetName(goos, goarch string) string {
	archiveArch := goarch
	if goarch == "amd64" {
		archiveArch = "x86_64"
	}
	extension := "tar.gz"
	if goos == "windows" {
		extension = "zip"
	}
	return fmt.Sprintf("pastevault_%s_%s.%s", goos, archiveArch, extension)
}

func binaryBaseName() string {
	if runtime.GOOS == "windows" {
		return "pastevault.exe"
	}
	return "pastevault"
}

func ValidateRelease(ctx context.Context, release *Release) error {
	name := AssetName()
	if release.asset(name) == nil {
		return fmt.Errorf("release %s has no asset for %s/%s (%s)", release.TagName, runtime.GOOS, runtime.GOARCH, name)
	}
	checksums, err := fetchSignedChecksums(ctx, release)
	if err != nil {
		return err
	}
	_, err = findChecksum(string(checksums), name)
	return err
}

func Apply(ctx context.Context, release *Release, targetPath, currentVersion string) error {
	binary, err := fetchVerifiedBinary(ctx, release)
	if err != nil {
		return err
	}
	return swapBinary(binary, targetPath, currentVersion)
}

func Rollback(currentVersion, targetPath string) (string, error) {
	binaryPath, err := backupBinaryPath()
	if err != nil {
		return "", err
	}
	manifestPath, err := backupManifestPath()
	if err != nil {
		return "", err
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return "", fmt.Errorf("no rollback backup found at %s", binaryPath)
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("rollback manifest is unavailable at %s: %w", manifestPath, err)
	}
	var manifest binaryManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", fmt.Errorf("rollback manifest is invalid: %w", err)
	}
	if manifest.Version == "" || manifest.SHA256 == "" || manifest.GOOS == "" || manifest.GOARCH == "" {
		return "", fmt.Errorf("rollback manifest is incomplete; refusing to roll back")
	}
	sum := sha256.Sum256(binary)
	if hex.EncodeToString(sum[:]) != manifest.SHA256 {
		return "", fmt.Errorf("backup binary does not match its manifest; refusing to roll back")
	}
	if manifest.GOOS != runtime.GOOS || manifest.GOARCH != runtime.GOARCH {
		return "", fmt.Errorf("backup binary is for %s/%s, not this machine", manifest.GOOS, manifest.GOARCH)
	}
	previousSkip := SkipVersion()
	if err := SetSkipVersion(currentVersion); err != nil {
		return "", fmt.Errorf("could not persist rollback protection: %w", err)
	}
	if err := swapBinary(binary, targetPath, currentVersion); err != nil {
		_ = SetSkipVersion(previousSkip)
		return "", err
	}
	return manifest.Version, nil
}

func fetchVerifiedBinary(ctx context.Context, release *Release) ([]byte, error) {
	name := AssetName()
	asset := release.asset(name)
	if asset == nil {
		return nil, fmt.Errorf("release %s has no asset for %s/%s (%s)", release.TagName, runtime.GOOS, runtime.GOARCH, name)
	}

	checksums, err := fetchSignedChecksums(ctx, release)
	if err != nil {
		return nil, err
	}
	want, err := findChecksum(string(checksums), name)
	if err != nil {
		return nil, err
	}

	archive, err := download(ctx, asset.DownloadURL, maxArchiveBytes)
	if err != nil {
		return nil, fmt.Errorf("could not download %s: %w", name, err)
	}
	sum := sha256.Sum256(archive)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("checksum mismatch for %s: expected %s, got %s", name, want, got)
	}
	return extractBinary(archive, name)
}

func fetchSignedChecksums(ctx context.Context, release *Release) ([]byte, error) {
	checksumsAsset := release.asset(checksumsAssetName)
	if checksumsAsset == nil {
		return nil, fmt.Errorf("release %s has no %s; refusing to update", release.TagName, checksumsAssetName)
	}
	signatureAsset := release.asset(checksumSignatureName)
	if signatureAsset == nil {
		return nil, fmt.Errorf("release %s has no %s; refusing to update", release.TagName, checksumSignatureName)
	}

	checksums, err := download(ctx, checksumsAsset.DownloadURL, maxChecksumsBytes)
	if err != nil {
		return nil, fmt.Errorf("could not download checksums: %w", err)
	}
	signature, err := download(ctx, signatureAsset.DownloadURL, maxSignatureBytes)
	if err != nil {
		return nil, fmt.Errorf("could not download checksum signature: %w", err)
	}
	if err := verifyChecksumSignature(checksums, signature); err != nil {
		return nil, err
	}
	return checksums, nil
}

func verifyChecksumSignature(checksums, signature []byte) error {
	if !HasEmbeddedPublicKey() {
		return fmt.Errorf("this PasteVault binary has no embedded update signing key")
	}
	var publicKey minisign.PublicKey
	if err := publicKey.UnmarshalText([]byte(strings.TrimSpace(embeddedPublicKey))); err != nil {
		return fmt.Errorf("invalid embedded update signing key: %w", err)
	}
	if !minisign.Verify(publicKey, checksums, signature) {
		return fmt.Errorf("checksum signature verification failed")
	}
	return nil
}

func findChecksum(checksums, name string) (string, error) {
	for _, line := range strings.Split(checksums, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != name {
			continue
		}
		value := strings.ToLower(fields[0])
		if len(value) != sha256.Size*2 {
			return "", fmt.Errorf("invalid SHA-256 checksum for %s", name)
		}
		if _, err := hex.DecodeString(value); err != nil {
			return "", fmt.Errorf("invalid SHA-256 checksum for %s", name)
		}
		return value, nil
	}
	return "", fmt.Errorf("no checksum entry for %s", name)
}

func download(ctx context.Context, url string, limit int64) ([]byte, error) {
	client := &http.Client{Timeout: downloadTimeout}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "pastevault-updater")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("GET %s returned %s", url, response.Status)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("download is larger than the %d-byte limit", limit)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("download is larger than the %d-byte limit", limit)
	}
	return data, nil
}

func extractBinary(archive []byte, archiveName string) ([]byte, error) {
	binaryName := "pastevault"
	if strings.HasSuffix(archiveName, ".zip") {
		binaryName += ".exe"
		reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, file := range reader.File {
			if path.Base(file.Name) != binaryName || file.FileInfo().IsDir() {
				continue
			}
			if file.UncompressedSize64 > uint64(maxBinaryBytes) {
				return nil, fmt.Errorf("%s is larger than the extraction limit", binaryName)
			}
			contents, err := file.Open()
			if err != nil {
				return nil, err
			}
			binary, readErr := readLimited(contents, maxBinaryBytes)
			closeErr := contents.Close()
			if readErr != nil {
				return nil, readErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
			return binary, nil
		}
		return nil, fmt.Errorf("%s not found in %s", binaryName, archiveName)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg || path.Base(header.Name) != binaryName {
			continue
		}
		if header.Size < 0 || header.Size > maxBinaryBytes {
			return nil, fmt.Errorf("%s is larger than the extraction limit", binaryName)
		}
		return readLimited(tarReader, maxBinaryBytes)
	}
	return nil, fmt.Errorf("%s not found in %s", binaryName, archiveName)
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("extracted binary is larger than the %d-byte limit", limit)
	}
	return data, nil
}

func backupDir() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "backup"), nil
}

func backupBinaryPath() (string, error) {
	dir, err := backupDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, binaryBaseName()), nil
}

func backupManifestPath() (string, error) {
	dir, err := backupDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "manifest.json"), nil
}

func swapBinary(binary []byte, targetPath, oldVersion string) error {
	dir, err := backupDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	oldPath, err := backupBinaryPath()
	if err != nil {
		return err
	}
	if err := selfupdate.Apply(bytes.NewReader(binary), selfupdate.Options{
		TargetPath:  targetPath,
		OldSavePath: oldPath,
	}); err != nil {
		if rollbackErr := selfupdate.RollbackError(err); rollbackErr != nil {
			return fmt.Errorf("update failed and the old binary could not be restored (%v), reinstall manually: %w", rollbackErr, err)
		}
		return err
	}
	writeBackupManifest(oldVersion)
	ClearStaging()
	return nil
}

func writeBackupManifest(version string) {
	binaryPath, err := backupBinaryPath()
	if err != nil {
		return
	}
	manifestPath, err := backupManifestPath()
	if err != nil {
		return
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}
	sum := sha256.Sum256(binary)
	manifest := binaryManifest{
		Version: version,
		SHA256:  hex.EncodeToString(sum[:]),
		GOOS:    runtime.GOOS,
		GOARCH:  runtime.GOARCH,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return
	}
	_ = writeFileAtomic(manifestPath, append(data, '\n'), 0o600)
}
