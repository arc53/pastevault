package main

import (
	"os"
	"path/filepath"
	"testing"

	"aead.dev/minisign"
)

func TestGenerateAndSign(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	if err := generate(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	privateText, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(privateKeyEnvironment, string(privateText))

	inputPath := filepath.Join(dir, "checksums.txt")
	signaturePath := filepath.Join(dir, "checksums.txt.minisig")
	message := []byte("abc123  pastevault_darwin_arm64.tar.gz\n")
	if err := os.WriteFile(inputPath, message, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sign(inputPath, signaturePath); err != nil {
		t.Fatal(err)
	}

	publicText, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	var publicKey minisign.PublicKey
	if err := publicKey.UnmarshalText(publicText); err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !minisign.Verify(publicKey, message, signature) {
		t.Fatal("generated signature did not verify")
	}
	if err := verify(publicPath, inputPath, signaturePath); err != nil {
		t.Fatalf("verify() error: %v", err)
	}
}
