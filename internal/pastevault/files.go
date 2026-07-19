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

		if err := client.UploadFileShareChunk(ctx, slug, fileID, chunkIndex, ciphertext); err != nil {
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

func DownloadManifest(
	ctx context.Context,
	client *Client,
	manifest FileShareManifest,
	key []byte,
	slug string,
	targetDir string,
	overwrite bool,
) error {
	if manifest.Paste != nil {
		if err := writeManifestNote(targetDir, manifest.Paste, overwrite); err != nil {
			return err
		}
	}

	for _, fileEntry := range manifest.Files {
		fileName := sanitizeFileName(fileEntry.Name, fileEntry.ID)
		targetPath := filepath.Join(targetDir, fileName)
		if !overwrite {
			if _, err := os.Stat(targetPath); err == nil {
				return fmt.Errorf("%s already exists; rerun with --overwrite", targetPath)
			}
		}

		output, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}

		var writeErr error
		for _, chunk := range fileEntry.Chunks {
			encryptedChunk, err := client.DownloadFileShareChunk(ctx, slug, fileEntry.ID, chunk.Index)
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

func NewShareOutputJSON(slug, shareURL, expiresAt string, fileCount int, totalBytes int64, passwordProtected bool) (string, error) {
	payload := struct {
		Slug              string `json:"slug"`
		URL               string `json:"url"`
		ExpiresAt         string `json:"expires_at,omitempty"`
		FileCount         int    `json:"file_count"`
		TotalSizeBytes    int64  `json:"total_size_bytes"`
		PasswordProtected bool   `json:"password_protected"`
	}{
		Slug:              slug,
		URL:               shareURL,
		ExpiresAt:         expiresAt,
		FileCount:         fileCount,
		TotalSizeBytes:    totalBytes,
		PasswordProtected: passwordProtected,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func sanitizeFileName(name, fallback string) string {
	cleaned := strings.ReplaceAll(name, "\\", "/")
	base := filepath.Base(cleaned)
	if base == "." || base == "/" || base == "" {
		return fallback
	}

	return base
}

func writeManifestNote(targetDir string, note *FileShareManifestPaste, overwrite bool) error {
	extension := ".txt"
	if note.RenderMode == "markdown" {
		extension = ".md"
	}

	targetPath := filepath.Join(targetDir, "NOTE"+extension)
	if !overwrite {
		if _, err := os.Stat(targetPath); err == nil {
			return fmt.Errorf("%s already exists; rerun with --overwrite", targetPath)
		}
	}

	content := note.Body
	if strings.TrimSpace(note.Title) != "" && note.RenderMode != "markdown" {
		content = note.Title + "\n\n" + note.Body
	}

	return os.WriteFile(targetPath, []byte(content), 0o644)
}
