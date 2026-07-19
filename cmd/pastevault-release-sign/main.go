package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
)

const privateKeyEnvironment = "PASTEVAULT_MINISIGN_PRIVATE_KEY"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pastevault-release-sign <generate|public-key|sign|verify>")
	}
	switch args[0] {
	case "generate":
		if len(args) != 3 {
			return errors.New("usage: pastevault-release-sign generate <private-key-path> <public-key-path>")
		}
		return generate(args[1], args[2])
	case "public-key":
		if len(args) != 1 {
			return errors.New("usage: pastevault-release-sign public-key")
		}
		privateKey, err := loadPrivateKey()
		if err != nil {
			return err
		}
		publicKey, ok := privateKey.Public().(minisign.PublicKey)
		if !ok {
			return errors.New("failed to derive minisign public key")
		}
		fmt.Println(publicKey.String())
		return nil
	case "sign":
		if len(args) != 3 {
			return errors.New("usage: pastevault-release-sign sign <input> <signature-output>")
		}
		return sign(args[1], args[2])
	case "verify":
		if len(args) != 4 {
			return errors.New("usage: pastevault-release-sign verify <public-key-path> <input> <signature>")
		}
		return verify(args[1], args[2], args[3])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func generate(privatePath, publicPath string) error {
	publicKey, privateKey, err := minisign.GenerateKey(nil)
	if err != nil {
		return err
	}
	privateText, err := privateKey.MarshalText()
	if err != nil {
		return err
	}
	publicText, err := publicKey.MarshalText()
	if err != nil {
		return err
	}
	if err := writeNewFile(privatePath, append(privateText, '\n'), 0o600); err != nil {
		return err
	}
	if err := writeNewFile(publicPath, append(publicText, '\n'), 0o644); err != nil {
		return err
	}
	return nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func sign(inputPath, signaturePath string) error {
	privateKey, err := loadPrivateKey()
	if err != nil {
		return err
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	signature := minisign.Sign(privateKey, input)
	if err := os.WriteFile(signaturePath, signature, 0o644); err != nil {
		return err
	}
	return nil
}

func verify(publicPath, inputPath, signaturePath string) error {
	publicText, err := os.ReadFile(publicPath)
	if err != nil {
		return err
	}
	var publicKey minisign.PublicKey
	if err := publicKey.UnmarshalText(publicText); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		return err
	}
	if !minisign.Verify(publicKey, input, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

func loadPrivateKey() (minisign.PrivateKey, error) {
	value := strings.TrimSpace(os.Getenv(privateKeyEnvironment))
	if value == "" {
		return minisign.PrivateKey{}, fmt.Errorf("%s is not set", privateKeyEnvironment)
	}
	var privateKey minisign.PrivateKey
	if err := privateKey.UnmarshalText([]byte(value)); err != nil {
		return minisign.PrivateKey{}, fmt.Errorf("invalid %s: %w", privateKeyEnvironment, err)
	}
	return privateKey, nil
}
