package pastevault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	fileShareVersion   = "v1"
	fileShareAADPrefix = "pastevault:file-share"
)

var defaultPasswordKDFParams = PasswordKDFParams{
	Iterations: 600000,
	Algorithm:  "PBKDF2",
	Hash:       "SHA-256",
	KeyLen:     32,
}

func PrepareFileShareEncryption(password string) (FileShareEncryption, error) {
	if strings.TrimSpace(password) == "" {
		key, err := randomBytes(chacha20poly1305.KeySize)
		if err != nil {
			return FileShareEncryption{}, err
		}

		return FileShareEncryption{Key: key}, nil
	}

	salt, err := randomBytes(16)
	if err != nil {
		return FileShareEncryption{}, err
	}

	key, err := deriveKeyFromPassword(password, salt, defaultPasswordKDFParams)
	if err != nil {
		return FileShareEncryption{}, err
	}

	paramsJSON, err := json.Marshal(defaultPasswordKDFParams)
	if err != nil {
		return FileShareEncryption{}, err
	}

	return FileShareEncryption{
		Key:       key,
		Salt:      EncodeBase64URL(salt),
		KDFParams: string(paramsJSON),
	}, nil
}

func EncryptFileChunk(plaintext, key []byte, slug, fileID string, chunkIndex int) ([]byte, string, error) {
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, "", err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, "", err
	}

	aad := createChunkAssociatedData(slug, fileID, chunkIndex)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, EncodeBase64URL(nonce), nil
}

func DecryptFileChunk(ciphertext []byte, nonceBase64 string, key []byte, slug, fileID string, chunkIndex int) ([]byte, error) {
	nonce, err := DecodeBase64URL(nonceBase64)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, createChunkAssociatedData(slug, fileID, chunkIndex))
}

func EncryptFileShareManifest(manifest FileShareManifest, key []byte, slug string) (string, string, error) {
	plaintext, err := json.Marshal(manifest)
	if err != nil {
		return "", "", err
	}

	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return "", "", err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", "", err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, createManifestAssociatedData(slug))
	return EncodeBase64URL(ciphertext), EncodeBase64URL(nonce), nil
}

func DecryptFileShareManifest(ciphertextBase64, nonceBase64 string, key []byte, slug string) (FileShareManifest, error) {
	ciphertext, err := DecodeBase64URL(ciphertextBase64)
	if err != nil {
		return FileShareManifest{}, err
	}

	nonce, err := DecodeBase64URL(nonceBase64)
	if err != nil {
		return FileShareManifest{}, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return FileShareManifest{}, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, createManifestAssociatedData(slug))
	if err != nil {
		return FileShareManifest{}, err
	}

	var manifest FileShareManifest
	if err := json.Unmarshal(plaintext, &manifest); err != nil {
		return FileShareManifest{}, err
	}

	return manifest, nil
}

func BuildFileShareURL(baseURL, slug string, key []byte) string {
	trimmed := strings.TrimRight(baseURL, "/")
	shareURL := fmt.Sprintf("%s/f/%s", trimmed, slug)
	if len(key) == 0 {
		return shareURL
	}

	return shareURL + "#k=" + EncodeBase64URL(key)
}

func BuildShortShareRef(slug string, key []byte) string {
	if len(key) == 0 {
		return slug
	}

	return slug + "#k=" + EncodeBase64URL(key)
}

func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func DecodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func GenerateSlug(size int) (string, error) {
	data, err := randomBytes(size)
	if err != nil {
		return "", err
	}

	return EncodeBase64URL(data), nil
}

func createManifestAssociatedData(slug string) []byte {
	return []byte(fmt.Sprintf("%s:manifest:%s:%s", fileShareAADPrefix, slug, fileShareVersion))
}

func createChunkAssociatedData(slug, fileID string, chunkIndex int) []byte {
	return []byte(fmt.Sprintf("%s:chunk:%s:%s:%d:%s", fileShareAADPrefix, slug, fileID, chunkIndex, fileShareVersion))
}

func deriveKeyFromPassword(password string, salt []byte, params PasswordKDFParams) ([]byte, error) {
	if params.Algorithm != "" && params.Algorithm != "PBKDF2" {
		return nil, fmt.Errorf("unsupported KDF algorithm %q", params.Algorithm)
	}

	if params.Hash != "" && params.Hash != "SHA-256" {
		return nil, fmt.Errorf("unsupported KDF hash %q", params.Hash)
	}

	if params.Iterations <= 0 {
		return nil, fmt.Errorf("invalid KDF iteration count %d", params.Iterations)
	}

	if params.KeyLen <= 0 {
		return nil, fmt.Errorf("invalid KDF key length %d", params.KeyLen)
	}

	key := pbkdf2.Key([]byte(password), salt, params.Iterations, params.KeyLen, sha256.New)
	return key, nil
}

func randomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}

	return data, nil
}
