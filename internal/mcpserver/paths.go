package mcpserver

import (
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

// File access of send_file and receive is confined to roots (spec §8, §9):
// the --root directories, the client's MCP roots, or failing both the
// working directory (unless that is the home directory or the filesystem
// root). Inside the roots, credential stores and the PasteVault config dir
// are refused, symlinks are resolved before checking, and receive never
// writes through a symlink or into tool configuration directories.

// CodePathRefused is the error code for a path outside the roots or on the
// deny list (exit 13, like other local file refusals).
const CodePathRefused = "path_refused"

// deniedComponents are directory names refused anywhere in a path, for
// reading and writing: credential stores of common tools.
var deniedComponents = map[string]bool{
	".ssh":            true,
	".gnupg":          true,
	".aws":            true,
	".azure":          true,
	".kube":           true,
	".docker":         true,
	".password-store": true,
	".terraform.d":    true,
	".oci":            true,
}

// deniedHomePaths are refused below the home directory (directories and
// single credential files).
var deniedHomePaths = []string{
	".config/pastevault",
	".config/gcloud",
	".config/gh",
	".config/op",
	".local/share/keyrings",
	".netrc",
	".git-credentials",
	".pgpass",
	".npmrc",
	".pypirc",
	".vault-token",
	".bash_history",
	".zsh_history",
}

// writeDeniedComponents are additionally refused as receive targets: files
// written there could run code (git hooks) or reconfigure an agent harness.
var writeDeniedComponents = map[string]bool{
	".git":    true,
	".claude": true,
	".codex":  true,
	".gemini": true,
	".cursor": true,
	".vscode": true,
	".idea":   true,
}

// pathPolicy holds the effective roots of one tool call.
type pathPolicy struct {
	roots  []string // absolute, symlinks resolved
	denied []string // absolute; both as given and symlink-resolved
}

// refused builds the error returned for a refused path.
func refused(format string, args ...any) error {
	return pv.NewError(pv.ExitLocalFile, CodePathRefused, format, args...)
}

// resolveRoots turns directories into absolute, symlink-resolved roots,
// skipping ones that don't exist.
func resolveRoots(dirs []string) []string {
	var roots []string
	seen := map[string]bool{}
	for _, dir := range dirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			continue
		}
		info, err := os.Stat(real)
		if err != nil || !info.IsDir() || seen[real] {
			continue
		}
		seen[real] = true
		roots = append(roots, real)
	}

	return roots
}

// fileURIToPath converts an MCP root URI (file:///path) to a local path.
func fileURIToPath(uri string) (string, bool) {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "file" {
		return "", false
	}
	if parsed.Host != "" && parsed.Host != "localhost" {
		return "", false
	}
	path := parsed.Path
	if runtime.GOOS == "windows" {
		// file:///C:/dir → C:/dir
		path = strings.TrimPrefix(path, "/")
	}
	if path == "" {
		return "", false
	}

	return filepath.FromSlash(path), true
}

// fallbackRoot is the working directory, unless it is too broad to be a
// sensible default (home directory or filesystem root).
func fallbackRoot() []string {
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	roots := resolveRoots([]string{cwd})
	if len(roots) == 0 {
		return nil
	}
	root := roots[0]
	if filepath.Dir(root) == root {
		return nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		if homeRoots := resolveRoots([]string{home}); len(homeRoots) == 1 && homeRoots[0] == root {
			return nil
		}
	}

	return roots
}

// newPathPolicy combines --root directories and client roots. Without
// either it falls back to the working directory.
func newPathPolicy(declared []string, clientRoots []string) *pathPolicy {
	roots := resolveRoots(append(append([]string{}, declared...), clientRoots...))
	if len(roots) == 0 {
		roots = fallbackRoot()
	}

	return &pathPolicy{roots: roots, denied: deniedPaths()}
}

// deniedPaths lists absolute paths that are never read or written: the
// PasteVault config dir (keys, store, credentials) and credential files
// under the home directory.
func deniedPaths() []string {
	var paths []string
	if dir, err := pv.ConfigDir(); err == nil {
		paths = append(paths, dir)
	}
	if dir, err := os.UserConfigDir(); err == nil {
		paths = append(paths, filepath.Join(dir, "pastevault"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, relative := range deniedHomePaths {
			paths = append(paths, filepath.Join(home, filepath.FromSlash(relative)))
		}
	}

	var result []string
	for _, path := range paths {
		abs, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		result = append(result, abs)
		if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
			result = append(result, real)
		}
	}

	return result
}

// within reports whether path is base or inside it.
func within(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		rel = strings.ToLower(rel)
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func (p *pathPolicy) inRoots(path string) bool {
	for _, root := range p.roots {
		if within(root, path) {
			return true
		}
	}

	return false
}

func (p *pathPolicy) rootsDescription() string {
	if len(p.roots) == 0 {
		return "no roots are configured (start pastevault mcp with --root DIR, or use a client that provides MCP roots)"
	}

	return "the allowed roots are " + strings.Join(p.roots, ", ")
}

// checkDenied refuses credential locations (both lexically and resolved).
func (p *pathPolicy) checkDenied(path string, writing bool) error {
	for _, denied := range p.denied {
		if within(denied, path) {
			return refused("%s is in a protected location (credentials or the PasteVault config dir); it cannot be read or written through MCP", path)
		}
	}
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		name := component
		if runtime.GOOS == "windows" {
			name = strings.ToLower(name)
		}
		if deniedComponents[name] {
			return refused("%s is inside %s, a credential directory; it cannot be read or written through MCP", path, component)
		}
		if writing && writeDeniedComponents[name] {
			return refused("%s is inside %s; receive does not write into repository or tool configuration directories", path, component)
		}
	}

	return nil
}

// absolute makes path absolute: relative paths are taken relative to the
// first root.
func (p *pathPolicy) absolute(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", pv.UsageError("empty path")
	}
	if strings.ContainsRune(path, 0) {
		return "", pv.UsageError("invalid path")
	}
	if !filepath.IsAbs(path) {
		if len(p.roots) == 0 {
			return "", refused("cannot use the relative path %s: %s", path, p.rootsDescription())
		}
		path = filepath.Join(p.roots[0], path)
	}

	return filepath.Clean(path), nil
}

// resolveRead returns the resolved path of an existing regular file inside
// the roots (send_file).
func (p *pathPolicy) resolveRead(path string) (string, error) {
	abs, err := p.absolute(path)
	if err != nil {
		return "", err
	}
	if err := p.checkDenied(abs, false); err != nil {
		return "", err
	}
	if !p.inRoots(abs) {
		return "", refused("%s is outside the allowed roots: %s", abs, p.rootsDescription())
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "%s does not exist", abs)
		}
		return "", pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot read %s", abs)
	}
	if !p.inRoots(real) {
		return "", refused("%s is a symlink to %s, outside the allowed roots", abs, real)
	}
	if err := p.checkDenied(real, false); err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot read %s", abs)
	}
	if !info.Mode().IsRegular() {
		return "", refused("%s is not a regular file (send_file shares files, not directories or devices)", abs)
	}

	return real, nil
}

// writeTarget is where receive writes: a file (-o) or a directory (--out).
type writeTarget struct {
	path string
	dir  bool
}

// resolveWrite checks a receive destination. An existing directory, or a
// path ending in a separator, is a directory target; anything else a file
// target, whose directory must exist. Symlinked files are refused, and
// symlinked directories are resolved and checked against the roots.
func (p *pathPolicy) resolveWrite(path string) (writeTarget, error) {
	wantDir := strings.HasSuffix(path, "/") || strings.HasSuffix(path, string(filepath.Separator))
	abs, err := p.absolute(path)
	if err != nil {
		return writeTarget{}, err
	}
	if err := p.checkDenied(abs, true); err != nil {
		return writeTarget{}, err
	}
	if !p.inRoots(abs) {
		return writeTarget{}, refused("%s is outside the allowed roots: %s", abs, p.rootsDescription())
	}

	info, err := os.Lstat(abs)
	switch {
	case err == nil && info.Mode()&fs.ModeSymlink != 0:
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return writeTarget{}, refused("%s is a dangling symlink; receive does not write through symlinks", abs)
		}
		realInfo, err := os.Stat(real)
		if err != nil || !realInfo.IsDir() {
			return writeTarget{}, refused("%s is a symlink; receive does not write through symlinks", abs)
		}
		return p.checkResolvedWrite(real, true)
	case err == nil && info.IsDir():
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return writeTarget{}, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot use %s", abs)
		}
		return p.checkResolvedWrite(real, true)
	case err == nil:
		if wantDir {
			return writeTarget{}, pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "%s is a file, not a directory", abs)
		}
		if !info.Mode().IsRegular() {
			return writeTarget{}, refused("%s is not a regular file", abs)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return writeTarget{}, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot use %s", abs)
	}

	if wantDir {
		// A new directory: its nearest existing ancestor decides.
		ancestor, rest := abs, []string{}
		for {
			if _, err := os.Lstat(ancestor); err == nil {
				break
			}
			parent := filepath.Dir(ancestor)
			if parent == ancestor {
				return writeTarget{}, pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "cannot create %s", abs)
			}
			rest = append([]string{filepath.Base(ancestor)}, rest...)
			ancestor = parent
		}
		real, err := filepath.EvalSymlinks(ancestor)
		if err != nil {
			return writeTarget{}, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot use %s", abs)
		}
		return p.checkResolvedWrite(filepath.Join(append([]string{real}, rest...)...), true)
	}

	parent := filepath.Dir(abs)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return writeTarget{}, pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "the directory for %s does not exist", abs)
	}

	return p.checkResolvedWrite(filepath.Join(realParent, filepath.Base(abs)), false)
}

func (p *pathPolicy) checkResolvedWrite(real string, dir bool) (writeTarget, error) {
	if !p.inRoots(real) {
		return writeTarget{}, refused("%s is outside the allowed roots: %s", real, p.rootsDescription())
	}
	if err := p.checkDenied(real, true); err != nil {
		return writeTarget{}, err
	}

	return writeTarget{path: real, dir: dir}, nil
}
