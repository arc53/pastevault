package pastevault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// EnvPassword supplies a share password without a prompt or file.
const EnvPassword = "PASTEVAULT_PASSWORD"

const maxSecretInputBytes = 64 * 1024

// KeySource lists the ways "get" can be given a share key. At most one may be
// used. Flag (--key) is deprecated because argv is visible to other users and
// shell history.
type KeySource struct {
	Flag  string
	File  string
	Env   string
	Stdin bool
}

func (k KeySource) count() int {
	count := 0
	for _, set := range []bool{k.Flag != "", k.File != "", k.Env != "", k.Stdin} {
		if set {
			count++
		}
	}

	return count
}

// ReadShareKey returns the key from the configured source, or nil when none
// is configured. The source may hold the bare base64url key, "k=KEY", or a
// share URL/reference with #k=KEY. Errors never include the key.
func ReadShareKey(source KeySource, stdin io.Reader) ([]byte, error) {
	if source.count() > 1 {
		return nil, UsageError("use only one of --key, --key-file, --key-env and --key-stdin")
	}

	var raw string
	switch {
	case source.Flag != "":
		raw = source.Flag
	case source.File != "":
		data, err := readSmallFile(source.File, "--key-file")
		if err != nil {
			return nil, err
		}
		raw = string(data)
	case source.Env != "":
		value, ok := os.LookupEnv(source.Env)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, UsageError("environment variable %s (from --key-env) is not set", source.Env)
		}
		raw = value
	case source.Stdin:
		data, err := readLimited(stdin, maxSecretInputBytes, "the key on stdin")
		if err != nil {
			return nil, err
		}
		raw = string(data)
	default:
		return nil, nil
	}

	return parseKeyText(raw)
}

func parseKeyText(raw string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if _, fragment, found := strings.Cut(value, "#"); found {
		value = fragment
	}
	value = strings.TrimPrefix(value, "k=")
	if value == "" {
		return nil, UsageError("the share key is empty")
	}

	return DecodeShareKey(value)
}

// PasswordSource lists the ways a password can be supplied. File wins over
// PASTEVAULT_PASSWORD, which wins over an interactive prompt.
type PasswordSource struct {
	// Prompt allows asking on the terminal (put/get --password).
	Prompt bool
	File   string
}

// Requested reports whether the caller asked for password protection
// (used by put, where the environment variable alone does not enable it).
func (p PasswordSource) Requested() bool {
	return p.Prompt || p.File != ""
}

// ResolvePassword returns the password from --password-file, then
// PASTEVAULT_PASSWORD, then a terminal prompt when allowed and stdin is a
// terminal. It returns "" when no source is available.
func ResolvePassword(source PasswordSource, stdinIsTerminal bool, prompt func(string) (string, error)) (string, error) {
	if source.File != "" {
		data, err := readSmallFile(source.File, "--password-file")
		if err != nil {
			return "", err
		}
		password := trimLineEnding(string(data))
		if password == "" {
			return "", UsageError("the --password-file is empty")
		}
		return password, nil
	}

	if value := os.Getenv(EnvPassword); value != "" {
		return value, nil
	}

	if source.Prompt {
		if !stdinIsTerminal {
			return "", NewError(ExitUsage, CodePasswordNeeded, "--password needs a terminal to prompt; use --password-file or PASTEVAULT_PASSWORD")
		}
		password, err := prompt("Password: ")
		if err != nil {
			return "", err
		}
		if password == "" {
			return "", UsageError("password cannot be empty")
		}
		return password, nil
	}

	return "", nil
}

// trimLineEnding removes one trailing newline (\n or \r\n), so files written
// by editors or "echo" work, while other whitespace (a lone \r included)
// stays part of the secret.
func trimLineEnding(value string) string {
	if trimmed, found := strings.CutSuffix(value, "\r\n"); found {
		return trimmed
	}
	return strings.TrimSuffix(value, "\n")
}

// TrimTrailingNewline is trimLineEnding for bytes (secret values read from a
// file or stdin as text).
func TrimTrailingNewline(value []byte) []byte {
	return []byte(trimLineEnding(string(value)))
}

// ReadTextInput reads paste text (stdin or --text source) up to limit bytes.
func ReadTextInput(reader io.Reader, limit int64) ([]byte, error) {
	data, err := readLimited(reader, limit, "the input")
	if err != nil {
		return nil, err
	}
	if err := ValidatePasteText(data); err != nil {
		return nil, err
	}

	return data, nil
}

func readLimited(reader io.Reader, limit int64, what string) ([]byte, error) {
	if reader == nil {
		return nil, UsageError("%s is not available", what)
	}

	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", what, err)
	}
	if int64(len(data)) > limit {
		return nil, NewError(ExitUsage, CodeTooLarge, "%s is larger than %d bytes", what, limit)
	}

	return data, nil
}

func readSmallFile(path, flagName string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, WrapError(ExitLocalFile, CodeLocalFile, err, "could not read %s", flagName)
	}
	defer file.Close()

	data, err := readLimited(file, maxSecretInputBytes, flagName)
	if err != nil {
		return nil, err
	}

	return bytes.Clone(data), nil
}

// WritePrivateFile writes data to a new file readable only by the owner
// (0600 on Unix; Windows applies the directory's ACLs). It never replaces an
// existing file unless overwrite is set (exit 13 otherwise).
func WritePrivateFile(path string, data []byte, overwrite bool) error {
	file, err := createPrivateFile(path, overwrite)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return NewError(ExitLocalFile, CodeLocalFile, "%s already exists; remove it first or pass --overwrite", path)
		}
		return WrapError(ExitLocalFile, CodeLocalFile, err, "could not write %s", path)
	}

	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return WrapError(ExitLocalFile, CodeLocalFile, writeErr, "could not write %s", path)
	}
	if closeErr != nil {
		return WrapError(ExitLocalFile, CodeLocalFile, closeErr, "could not write %s", path)
	}

	return nil
}

// CheckWritableTarget fails early (before a share is consumed) when path
// exists and may not be replaced, or its directory does not exist.
func CheckWritableTarget(path string, overwrite bool) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.IsDir():
		return NewError(ExitLocalFile, CodeLocalFile, "%s is a directory", path)
	case err == nil && !overwrite:
		return NewError(ExitLocalFile, CodeLocalFile, "%s already exists; remove it first or pass --overwrite", path)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return WrapError(ExitLocalFile, CodeLocalFile, err, "cannot use %s", path)
	}

	if dir, err := os.Stat(filepath.Dir(path)); err != nil || !dir.IsDir() {
		return NewError(ExitLocalFile, CodeLocalFile, "the directory for %s does not exist", path)
	}

	return nil
}
