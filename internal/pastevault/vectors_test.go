package pastevault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// The vectors are generated from the web app's crypto code by
// scripts/crypto-vectors.mjs; these tests prove the CLI reads and writes the
// exact same formats.
type cryptoVectors struct {
	Version  int              `json:"version"`
	Paste    []pasteVector    `json:"paste"`
	Chunk    []chunkVector    `json:"chunk"`
	Manifest []manifestVector `json:"manifest"`
}

type pasteVector struct {
	Name       string       `json:"name"`
	Mode       string       `json:"mode"`
	Slug       string       `json:"slug"`
	AAD        string       `json:"aad"`
	Content    PasteContent `json:"content"`
	Plaintext  string       `json:"plaintext"`
	Password   string       `json:"password"`
	Salt       string       `json:"salt"`
	KDFParams  string       `json:"kdf_params"`
	Key        string       `json:"key"`
	Nonce      string       `json:"nonce"`
	Ciphertext string       `json:"ciphertext"`
}

type chunkVector struct {
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	FileID     string `json:"file_id"`
	Index      int    `json:"index"`
	AAD        string `json:"aad"`
	Key        string `json:"key"`
	Nonce      string `json:"nonce"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type manifestVector struct {
	Name       string            `json:"name"`
	Slug       string            `json:"slug"`
	AAD        string            `json:"aad"`
	Manifest   FileShareManifest `json:"manifest"`
	Plaintext  string            `json:"plaintext"`
	Key        string            `json:"key"`
	Nonce      string            `json:"nonce"`
	Ciphertext string            `json:"ciphertext"`
}

func loadCryptoVectors(t *testing.T) cryptoVectors {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "crypto", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors cryptoVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if vectors.Version != 1 || len(vectors.Paste) == 0 || len(vectors.Chunk) == 0 || len(vectors.Manifest) == 0 {
		t.Fatalf("unexpected vectors file: version %d, %d paste, %d chunk, %d manifest", vectors.Version, len(vectors.Paste), len(vectors.Chunk), len(vectors.Manifest))
	}

	return vectors
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()

	data, err := DecodeBase64URL(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}

	return data
}

func TestPasteVectors(t *testing.T) {
	t.Parallel()

	for _, vector := range loadCryptoVectors(t).Paste {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			if got := string(createPasteAssociatedData(vector.Slug)); got != vector.AAD {
				t.Fatalf("AAD = %q, want %q", got, vector.AAD)
			}

			plaintext, err := MarshalPasteContent(vector.Content)
			if err != nil {
				t.Fatal(err)
			}
			if string(plaintext) != vector.Plaintext {
				t.Fatalf("plaintext differs from the web's JSON.stringify:\n got %s\nwant %s", plaintext, vector.Plaintext)
			}

			key := mustDecode(t, vector.Key)
			if vector.Mode == "password" {
				derived, err := DerivePasteKey(nil, vector.Salt, vector.KDFParams, vector.Password)
				if err != nil {
					t.Fatalf("DerivePasteKey: %v", err)
				}
				if !bytes.Equal(derived, key) {
					t.Fatal("PBKDF2 key differs from the web's")
				}

				// The CLI writes the same kdf_params the web stores.
				prepared, err := PrepareFileShareEncryption(vector.Password)
				if err != nil {
					t.Fatal(err)
				}
				if prepared.KDFParams != vector.KDFParams {
					t.Fatalf("kdf_params = %s, want %s", prepared.KDFParams, vector.KDFParams)
				}
			}

			ciphertext, nonce, err := encryptPasteWithNonce(vector.Content, key, mustDecode(t, vector.Nonce), vector.Slug)
			if err != nil {
				t.Fatal(err)
			}
			if ciphertext != vector.Ciphertext || nonce != vector.Nonce {
				t.Fatal("ciphertext differs from the web's")
			}

			content, err := DecryptPaste(vector.Ciphertext, vector.Nonce, key, vector.Slug)
			if err != nil {
				t.Fatalf("DecryptPaste: %v", err)
			}
			if content != vector.Content {
				t.Fatalf("content = %+v, want %+v", content, vector.Content)
			}

			// Wrong slug (AAD) and wrong key are decryption failures (exit 7).
			for _, attempt := range []struct {
				key  []byte
				slug string
			}{
				{key, vector.Slug + "x"},
				{bytes.Repeat([]byte{9}, 32), vector.Slug},
			} {
				_, err := DecryptPaste(vector.Ciphertext, vector.Nonce, attempt.key, attempt.slug)
				var cliErr *CLIError
				if !errors.As(err, &cliErr) || cliErr.Exit != ExitDecrypt {
					t.Fatalf("expected a decryption error (exit 7), got %v", err)
				}
			}
		})
	}
}

func TestChunkVectors(t *testing.T) {
	t.Parallel()

	for _, vector := range loadCryptoVectors(t).Chunk {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			if got := string(createChunkAssociatedData(vector.Slug, vector.FileID, vector.Index)); got != vector.AAD {
				t.Fatalf("AAD = %q, want %q", got, vector.AAD)
			}

			key := mustDecode(t, vector.Key)
			aead, err := chacha20poly1305.NewX(key)
			if err != nil {
				t.Fatal(err)
			}
			sealed := aead.Seal(nil, mustDecode(t, vector.Nonce), mustDecode(t, vector.Plaintext), []byte(vector.AAD))
			if EncodeBase64URL(sealed) != vector.Ciphertext {
				t.Fatal("chunk ciphertext differs from the web's")
			}

			plaintext, err := DecryptFileChunk(mustDecode(t, vector.Ciphertext), vector.Nonce, key, vector.Slug, vector.FileID, vector.Index)
			if err != nil {
				t.Fatalf("DecryptFileChunk: %v", err)
			}
			if !bytes.Equal(plaintext, mustDecode(t, vector.Plaintext)) {
				t.Fatal("chunk plaintext mismatch")
			}

			if _, err := DecryptFileChunk(mustDecode(t, vector.Ciphertext), vector.Nonce, key, vector.Slug, vector.FileID, vector.Index+1); err == nil {
				t.Fatal("a chunk must not open at another index")
			}
		})
	}
}

func TestManifestVectors(t *testing.T) {
	t.Parallel()

	for _, vector := range loadCryptoVectors(t).Manifest {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			if got := string(createManifestAssociatedData(vector.Slug)); got != vector.AAD {
				t.Fatalf("AAD = %q, want %q", got, vector.AAD)
			}

			plaintext, err := json.Marshal(vector.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			if string(plaintext) != vector.Plaintext {
				t.Fatalf("manifest JSON differs:\n got %s\nwant %s", plaintext, vector.Plaintext)
			}

			key := mustDecode(t, vector.Key)
			aead, err := chacha20poly1305.NewX(key)
			if err != nil {
				t.Fatal(err)
			}
			if EncodeBase64URL(aead.Seal(nil, mustDecode(t, vector.Nonce), plaintext, []byte(vector.AAD))) != vector.Ciphertext {
				t.Fatal("manifest ciphertext differs from the web's")
			}

			manifest, err := DecryptFileShareManifest(vector.Ciphertext, vector.Nonce, key, vector.Slug)
			if err != nil {
				t.Fatalf("DecryptFileShareManifest: %v", err)
			}
			again, _ := json.Marshal(manifest)
			if string(again) != vector.Plaintext {
				t.Fatalf("decrypted manifest = %s", again)
			}
		})
	}
}
