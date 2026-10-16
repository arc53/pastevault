package pastevault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func DefaultServerURL() string {
	if value := strings.TrimSpace(os.Getenv("PASTEVAULT_SERVER")); value != "" {
		return value
	}

	return "https://api.pastevault.dev"
}

func DefaultPublicURL() string {
	if value := strings.TrimSpace(os.Getenv("PASTEVAULT_PUBLIC_URL")); value != "" {
		return value
	}

	return "https://pastevault.dev"
}

func ResolvePublicBaseURL(server string) string {
	if value := strings.TrimSpace(os.Getenv("PASTEVAULT_PUBLIC_URL")); value != "" {
		return value
	}

	parsedURL, err := url.Parse(strings.TrimSpace(server))
	if err != nil {
		return DefaultPublicURL()
	}

	if parsedURL.Scheme == "" {
		if strings.HasPrefix(server, "localhost") || strings.HasPrefix(server, "127.0.0.1") {
			parsedURL, err = url.Parse("http://" + strings.TrimSpace(server))
		} else {
			parsedURL, err = url.Parse("https://" + strings.TrimSpace(server))
		}
		if err != nil {
			return DefaultPublicURL()
		}
	}

	host := parsedURL.Host
	if strings.HasPrefix(strings.ToLower(host), "api.") {
		host = host[4:]
	}

	trimmedPath := strings.TrimRight(parsedURL.Path, "/")
	if strings.HasSuffix(trimmedPath, "/api") {
		trimmedPath = strings.TrimSuffix(trimmedPath, "/api")
	}

	return (&url.URL{
		Scheme: parsedURL.Scheme,
		Host:   host,
		Path:   trimmedPath,
	}).String()
}

// MaxExpiresHours mirrors the server's upper bound for expires_in_hours.
const MaxExpiresHours = 8760

// ValidateExpiresHours rejects values the API would otherwise treat as "never
// expires" (0 is dropped from the request) or refuse outright.
func ValidateExpiresHours(hours int) error {
	if hours < 1 {
		return fmt.Errorf("--expires-hours must be at least 1 (got %d)", hours)
	}
	if hours > MaxExpiresHours {
		return fmt.Errorf("--expires-hours must be at most %d (got %d)", MaxExpiresHours, hours)
	}

	return nil
}

// CheckShareAccess verifies, before a share is opened, that the caller has
// what it needs to decrypt it. Opening a burn-after-read share destroys it, so
// this must fail early instead of after the only read.
func CheckShareAccess(meta FileShareMetaResponse, ref ShareReference, password string) error {
	if meta.PasswordProtected {
		if strings.TrimSpace(password) == "" {
			return fmt.Errorf("this share is password-protected; rerun with --password")
		}
		return nil
	}

	if len(ref.Key) == 0 {
		return fmt.Errorf("missing share key; provide the full URL or use --key")
	}

	return nil
}

func ResolveUploadInputs(paths []string) ([]UploadInput, int64, error) {
	inputs := make([]UploadInput, 0, len(paths))
	var totalSize int64

	for _, rawPath := range paths {
		cleanPath := filepath.Clean(rawPath)
		info, err := os.Stat(cleanPath)
		if err != nil {
			return nil, 0, err
		}

		if info.IsDir() {
			return nil, 0, fmt.Errorf("%s is a directory; directory uploads are not supported yet", cleanPath)
		}

		displayName := filepath.Base(cleanPath)
		contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(displayName)))

		inputs = append(inputs, UploadInput{
			Path:         cleanPath,
			DisplayName:  displayName,
			ContentType:  contentType,
			Size:         info.Size(),
			LastModified: info.ModTime().UnixMilli(),
		})
		totalSize += info.Size()
	}

	return inputs, totalSize, nil
}

func UploadFile(
	ctx context.Context,
	client *Client,
	input UploadInput,
	key []byte,
	slug string,
	uploadToken string,
	fileID string,
	chunkSize int,
) ([]FileShareChunkInfo, error) {
	file, err := os.Open(input.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if chunkSize <= 0 {
		return nil, fmt.Errorf("server reported invalid chunk size %d", chunkSize)
	}

	buffer := make([]byte, chunkSize)
	chunks := make([]FileShareChunkInfo, 0, (input.Size/int64(chunkSize))+1)

	for chunkIndex := 0; ; chunkIndex++ {
		readBytes, readErr := file.Read(buffer)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}

		if readBytes == 0 {
			break
		}

		plaintext := make([]byte, readBytes)
		copy(plaintext, buffer[:readBytes])

		ciphertext, nonce, err := EncryptFileChunk(plaintext, key, slug, fileID, chunkIndex)
		if err != nil {
			return nil, err
		}

		if err := client.UploadFileShareChunk(ctx, slug, uploadToken, fileID, chunkIndex, ciphertext); err != nil {
			return nil, err
		}

		chunks = append(chunks, FileShareChunkInfo{
			Index:         chunkIndex,
			Nonce:         nonce,
			PlaintextSize: readBytes,
		})

		if readErr == io.EOF {
			break
		}
	}

	return chunks, nil
}

// RenamedPath records a download target moved aside to avoid clobbering an
// existing file.
type RenamedPath struct {
	From string
	To   string
}

// DownloadPlan fixes every output path before any chunk is fetched, so path
// problems surface while the share is still downloadable.
type DownloadPlan struct {
	NotePath  string   // empty when the manifest carries no note
	FilePaths []string // parallel to manifest.Files
	Renamed   []RenamedPath
	Overwrite bool
}

// EnsureWritableDir creates dir (owner-only) and proves files can be created
// in it. Call it before opening a burn-after-read share: once opened, the share
// cannot be fetched again.
func EnsureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	probe, err := os.CreateTemp(dir, ".pastevault-write-check-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	probePath := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(probePath)
	if closeErr != nil {
		return closeErr
	}

	return removeErr
}

// PlanDownload chooses output paths for a manifest. Names repeated within the
// manifest are always renamed. An existing file is overwritten with overwrite,
// renamed to "name (1).ext" with renameOnConflict (used for burned shares,
// which cannot be fetched again), and otherwise reported as an error.
func PlanDownload(manifest FileShareManifest, targetDir string, overwrite, renameOnConflict bool) (DownloadPlan, error) {
	plan := DownloadPlan{
		FilePaths: make([]string, 0, len(manifest.Files)),
		Overwrite: overwrite,
	}
	taken := make(map[string]bool)

	choose := func(name string) (string, error) {
		wanted := filepath.Join(targetDir, name)
		exists := pathExists(wanted)
		if !taken[wanted] && (overwrite || !exists) {
			taken[wanted] = true
			return wanted, nil
		}
		if exists && !overwrite && !renameOnConflict {
			return "", fmt.Errorf("%s already exists; rerun with --overwrite", wanted)
		}

		extension := filepath.Ext(name)
		base := strings.TrimSuffix(name, extension)
		if base == "" {
			base, extension = name, ""
		}
		for counter := 1; ; counter++ {
			candidate := filepath.Join(targetDir, fmt.Sprintf("%s (%d)%s", base, counter, extension))
			if !taken[candidate] && !pathExists(candidate) {
				taken[candidate] = true
				plan.Renamed = append(plan.Renamed, RenamedPath{From: wanted, To: candidate})
				return candidate, nil
			}
		}
	}

	if manifest.Paste != nil {
		notePath, err := choose(manifestNoteFileName(manifest.Paste))
		if err != nil {
			return DownloadPlan{}, err
		}
		plan.NotePath = notePath
	}

	for _, fileEntry := range manifest.Files {
		filePath, err := choose(sanitizeFileName(fileEntry.Name, fileEntry.ID))
		if err != nil {
			return DownloadPlan{}, err
		}
		plan.FilePaths = append(plan.FilePaths, filePath)
	}

	return plan, nil
}

func DownloadManifest(
	ctx context.Context,
	client *Client,
	manifest FileShareManifest,
	key []byte,
	slug string,
	downloadGrant string,
	plan DownloadPlan,
) error {
	if len(plan.FilePaths) != len(manifest.Files) {
		return fmt.Errorf("download plan does not match the manifest")
	}

	if manifest.Paste != nil {
		if err := writeManifestNote(plan.NotePath, manifest.Paste, plan.Overwrite); err != nil {
			return err
		}
	}

	for index, fileEntry := range manifest.Files {
		output, err := createPrivateFile(plan.FilePaths[index], plan.Overwrite)
		if err != nil {
			return err
		}

		var writeErr error
		for _, chunk := range fileEntry.Chunks {
			encryptedChunk, err := client.downloadChunkWithRetry(ctx, slug, downloadGrant, fileEntry.ID, chunk.Index)
			if err != nil {
				writeErr = err
				break
			}

			plaintext, err := DecryptFileChunk(encryptedChunk, chunk.Nonce, key, slug, fileEntry.ID, chunk.Index)
			if err != nil {
				writeErr = err
				break
			}

			if _, err := output.Write(plaintext); err != nil {
				writeErr = err
				break
			}
		}

		closeErr := output.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}

	return nil
}

func PromptForPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(password)), nil
}

func NewShareOutputJSON(slug, shareURL, expiresAt string, fileCount int, totalBytes int64, passwordProtected, burnAfterRead bool) (string, error) {
	payload := struct {
		Slug              string `json:"slug"`
		URL               string `json:"url"`
		ExpiresAt         string `json:"expires_at,omitempty"`
		FileCount         int    `json:"file_count"`
		TotalSizeBytes    int64  `json:"total_size_bytes"`
		PasswordProtected bool   `json:"password_protected"`
		BurnAfterRead     bool   `json:"burn_after_read"`
	}{
		Slug:              slug,
		URL:               shareURL,
		ExpiresAt:         expiresAt,
		FileCount:         fileCount,
		TotalSizeBytes:    totalBytes,
		PasswordProtected: passwordProtected,
		BurnAfterRead:     burnAfterRead,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func pathExists(targetPath string) bool {
	_, err := os.Lstat(targetPath)
	return err == nil
}

// createPrivateFile opens targetPath for writing with owner-only permissions,
// since downloaded files contain decrypted content. Without overwrite it never
// replaces a file that appeared after the download was planned.
func createPrivateFile(targetPath string, overwrite bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	if overwrite {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}

	file, err := os.OpenFile(targetPath, flags, 0o600)
	if err != nil {
		return nil, err
	}

	// OpenFile keeps the mode of a file that already existed (--overwrite).
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}

	return file, nil
}

func sanitizeFileName(name, fallback string) string {
	cleaned := strings.ReplaceAll(name, "\\", "/")
	base := filepath.Base(cleaned)
	if base == "." || base == "/" || base == "" {
		return fallback
	}

	return base
}

func manifestNoteFileName(note *FileShareManifestPaste) string {
	if note.RenderMode == "markdown" {
		return "NOTE.md"
	}

	return "NOTE.txt"
}

func writeManifestNote(targetPath string, note *FileShareManifestPaste, overwrite bool) error {
	content := note.Body
	if strings.TrimSpace(note.Title) != "" && note.RenderMode != "markdown" {
		content = note.Title + "\n\n" + note.Body
	}

	output, err := createPrivateFile(targetPath, overwrite)
	if err != nil {
		return err
	}

	_, writeErr := output.WriteString(content)
	closeErr := output.Close()
	if writeErr != nil {
		return writeErr
	}

	return closeErr
}
