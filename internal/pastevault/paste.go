package pastevault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

// Pastes use the web app's /p/ format (frontend/src/lib/crypto.ts):
//
//	plaintext  = JSON {title, body, render_mode, language_hint?}
//	ciphertext = XChaCha20-Poly1305(key, nonce[24], plaintext, aad)
//	aad        = "pastevault:<slug>:v1"
//
// The key is a random 32-byte key carried in the URL fragment (#k=), or
// PBKDF2-SHA256(password, salt[16], 600000) with salt and kdf_params stored
// on the server. testdata/crypto/vectors.json pins the format.
const (
	pasteAADPrefix = "pastevault"
	pasteVersion   = "v1"

	RenderModePlain    = "plain"
	RenderModeMarkdown = "markdown"

	// DefaultMaxPasteBytes is the server's default MAX_PASTE_SIZE_BYTES. The
	// server checks the encrypted size, i.e. plaintext JSON plus a 16-byte tag.
	DefaultMaxPasteBytes = 1024 * 1024
)

// nanoid's URL-safe alphabet, as used by the web app for paste slugs.
const nanoidAlphabet = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict"

// GeneratePasteSlug returns a 12-character slug in nanoid(12) style, the
// same shape the web app uses. It never starts with "-", so the slug can be
// passed to the CLI without being taken for a flag.
func GeneratePasteSlug() (string, error) {
	for {
		data, err := randomBytes(12)
		if err != nil {
			return "", err
		}

		slug := make([]byte, len(data))
		for index, value := range data {
			slug[index] = nanoidAlphabet[value&63]
		}
		if slug[0] != '-' {
			return string(slug), nil
		}
	}
}

// GenerateShareSlug returns a random base64url slug of size bytes that does
// not start with "-" (see GeneratePasteSlug).
func GenerateShareSlug(size int) (string, error) {
	for {
		slug, err := GenerateSlug(size)
		if err != nil || !strings.HasPrefix(slug, "-") {
			return slug, err
		}
	}
}

func createPasteAssociatedData(slug string) []byte {
	return []byte(fmt.Sprintf("%s:%s:%s", pasteAADPrefix, slug, pasteVersion))
}

// MarshalPasteContent encodes content exactly as the web app's
// JSON.stringify does for ordinary text: same field order, no HTML escaping.
// (Go still escapes U+2028/U+2029 where JavaScript does not; both decode the
// same.)
func MarshalPasteContent(content PasteContent) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(content); err != nil {
		return nil, err
	}

	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// PasteEncryptedSize is the size the server checks against its paste limit.
func PasteEncryptedSize(content PasteContent) (int, error) {
	plaintext, err := MarshalPasteContent(content)
	if err != nil {
		return 0, err
	}

	return len(plaintext) + chacha20poly1305.Overhead, nil
}

// EncryptPaste encrypts content for slug with a fresh random nonce and returns
// base64url ciphertext and nonce.
func EncryptPaste(content PasteContent, key []byte, slug string) (string, string, error) {
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return "", "", err
	}

	return encryptPasteWithNonce(content, key, nonce, slug)
}

func encryptPasteWithNonce(content PasteContent, key, nonce []byte, slug string) (string, string, error) {
	plaintext, err := MarshalPasteContent(content)
	if err != nil {
		return "", "", err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", "", err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, createPasteAssociatedData(slug))
	return EncodeBase64URL(ciphertext), EncodeBase64URL(nonce), nil
}

// DecryptPaste opens a paste. Any failure (wrong key or password, tampered
// ciphertext, wrong slug) is reported as a decryption error (exit 7).
func DecryptPaste(ciphertextBase64, nonceBase64 string, key []byte, slug string) (PasteContent, error) {
	ciphertext, err := DecodeBase64URL(ciphertextBase64)
	if err != nil {
		return PasteContent{}, DecryptError("paste ciphertext is not valid base64url")
	}

	nonce, err := DecodeBase64URL(nonceBase64)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return PasteContent{}, DecryptError("paste nonce is invalid")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return PasteContent{}, DecryptError("share key is invalid: %v", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, createPasteAssociatedData(slug))
	if err != nil {
		return PasteContent{}, DecryptError("could not decrypt the paste: wrong key or password, or the content was tampered with")
	}

	var content PasteContent
	if err := json.Unmarshal(plaintext, &content); err != nil {
		return PasteContent{}, DecryptError("decrypted paste is not valid PasteVault content: %v", err)
	}

	return content, nil
}

// DerivePasteKey returns the key for a paste or file share: the PBKDF2 key for
// password-protected shares (salt set), otherwise the URL key.
func DerivePasteKey(urlKey []byte, salt, kdfParams, password string) ([]byte, error) {
	if salt == "" {
		if len(urlKey) == 0 {
			return nil, NewError(ExitUsage, CodeKeyRequired, "missing share key; pass the full URL (with #k=...) or use --key-file, --key-env or --key-stdin")
		}
		if len(urlKey) != chacha20poly1305.KeySize {
			return nil, DecryptError("share key must be %d bytes, got %d", chacha20poly1305.KeySize, len(urlKey))
		}
		return urlKey, nil
	}

	if password == "" {
		return nil, NewError(ExitUsage, CodePasswordNeeded, "this share is password-protected; use --password, --password-file or PASTEVAULT_PASSWORD")
	}

	saltBytes, err := DecodeBase64URL(salt)
	if err != nil {
		return nil, fmt.Errorf("invalid server salt: %w", err)
	}

	params := defaultPasswordKDFParams
	if strings.TrimSpace(kdfParams) != "" {
		if err := json.Unmarshal([]byte(kdfParams), &params); err != nil {
			return nil, fmt.Errorf("invalid kdf_params: %w", err)
		}
	}

	return deriveKeyFromPassword(password, saltBytes, params)
}

// BuildPasteURL returns the /p/ URL for a paste, with #k= when key is set.
func BuildPasteURL(baseURL, slug string, key []byte) string {
	shareURL := fmt.Sprintf("%s/p/%s", strings.TrimRight(baseURL, "/"), slug)
	if len(key) == 0 {
		return shareURL
	}

	return shareURL + "#k=" + EncodeBase64URL(key)
}

var fileNameTitlePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

var envFilePattern = regexp.MustCompile(`^\.env(\..+)?$|\.env$`)

// IsEnvFileName reports whether a file name looks like a dotenv file (.env,
// .env.local, prod.env), which "put --as auto" shares as a paste.
func IsEnvFileName(name string) bool {
	return envFilePattern.MatchString(filepath.Base(name))
}

// ValidatePasteText checks text before it becomes a paste body: it must be
// valid UTF-8 (JSON would silently replace invalid bytes) and not blank.
func ValidatePasteText(text []byte) error {
	if !utf8.Valid(text) {
		return UsageError("the input is not valid UTF-8 text; share it as a file instead (--as files)")
	}
	if strings.TrimSpace(string(text)) == "" {
		return UsageError("the paste is empty")
	}

	return nil
}

// PasteOutputFileName picks a file name for "get --out DIR" of a paste: the
// title when it is a plain file name (for example ".env"), otherwise the slug
// with an extension for the render mode.
func PasteOutputFileName(content PasteContent, slug string) string {
	title := strings.TrimSpace(content.Title)
	if fileNameTitlePattern.MatchString(title) && strings.Trim(title, ".") != "" {
		return title
	}
	if content.RenderMode == RenderModeMarkdown {
		return slug + ".md"
	}

	return slug + ".txt"
}
