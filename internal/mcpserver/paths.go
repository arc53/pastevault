package mcpserver

import (
	"errors"
	"fmt"
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
// working directory. The home directory, filesystem roots and ancestors of
// the home directory are never roots unless --allow-home-root is given.
//
// Inside the roots, credential stores, the PasteVault config dir and
// repository/tool configuration directories are refused. The deny lists are
// matched case-insensitively and without trailing dots and spaces on every
// platform (macOS and Windows file systems ignore case, and Windows ignores
// trailing dots and spaces), symlinks are resolved before checking, and
// paths are canonicalised again from the opened file or directory handle
// (which also resolves Windows 8.3 short names) before anything is read or
// placed.

// CodePathRefused is the error code for a path outside the roots or on a
// deny list (exit 13, like other local file refusals).
const CodePathRefused = "path_refused"

// caseInsensitiveRoots: root containment compares paths without case on
// file systems that ignore case. (The deny lists always ignore case.)
// A variable so tests can simulate a case-insensitive file system.
var caseInsensitiveRoots = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// deniedComponents are directory names refused anywhere in a path, for
// reading and writing: credential stores of common tools, and git
// repositories' internals (remotes with tokens, hooks).
var deniedComponents = setOf(
	".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".password-store",
	".terraform.d", ".oci", ".git",
)

// deniedNames are file names refused anywhere, for reading and writing.
var deniedNames = setOf(
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
	".netrc", "_netrc", ".git-credentials", ".pgpass", ".npmrc", ".pypirc", ".vault-token",
	".bash_history", ".zsh_history", ".sh_history", ".python_history", "fish_history",
	".credentials.json", "credentials", "credentials.toml",
)

// deniedHomePaths are refused below the home directory (directories and
// single files): CLI credentials and agent harness state.
var deniedHomePaths = []string{
	".config/pastevault",
	".config/gcloud",
	".config/gh",
	".config/hub",
	".config/op",
	".local/share/keyrings",
	".local/share/fish",
	"Library/Keychains",
	".claude",
	".claude.json",
	".codex",
	".gemini",
	".cursor",
	".cargo/credentials",
	".cargo/credentials.toml",
	".m2/settings.xml",
	".gradle/gradle.properties",
}

// writeDeniedComponents are additionally refused as receive targets: files
// written there could run code (git hooks, CI workflows, package bins) or
// reconfigure an agent harness or editor.
var writeDeniedComponents = setOf(
	".git", ".github", ".gitlab", ".husky", ".devcontainer", ".vscode", ".idea",
	".claude", ".codex", ".gemini", ".cursor", ".agents", ".circleci", ".direnv",
	"node_modules",
)

func setOf(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[foldName(value)] = true
	}
	return set
}

// foldName is how names are compared against the deny lists: lower case,
// without the trailing dots and spaces Windows ignores.
func foldName(name string) string {
	return strings.TrimRight(strings.ToLower(name), ". ")
}

// foldPath folds every component of path (see foldName).
func foldPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for index, part := range parts {
		if index == 0 && strings.HasSuffix(part, ":") {
			parts[index] = strings.ToLower(part) // a Windows volume
			continue
		}
		parts[index] = foldName(part)
	}
	return strings.Join(parts, "/")
}

// pathPolicy holds the effective roots of one tool call.
type pathPolicy struct {
	roots  []string // absolute, symlinks resolved
	denied []string // folded (foldPath) absolute paths
}

// refused builds the error returned for a refused path.
func refused(format string, args ...any) error {
	return pv.NewError(pv.ExitLocalFile, CodePathRefused, format, args...)
}

// TooBroadRoot reports whether dir (resolved) may only be a root with
// --allow-home-root.
func TooBroadRoot(dir string) bool {
	roots := resolveRoots([]string{dir}, true)
	return len(roots) == 1 && tooBroadRoot(roots[0])
}

// tooBroadRoot reports a directory that may only be a root with
// --allow-home-root: a filesystem root, the home directory, or one of its
// ancestors.
func tooBroadRoot(dir string) bool {
	if filepath.Dir(dir) == dir {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	for _, candidate := range resolveRoots([]string{home}, true) {
		if within(dir, candidate) {
			return true
		}
	}
	return false
}

// resolveRoots turns directories into absolute, symlink-resolved roots,
// skipping ones that don't exist and, unless allowBroad, ones that are too
// broad (tooBroadRoot).
func resolveRoots(dirs []string, allowBroad bool) []string {
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
		if !allowBroad && tooBroadRoot(real) {
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

// newPathPolicy combines --root directories and client roots. Without
// either it falls back to the working directory. Too broad roots (home,
// filesystem root, ancestors of home) are dropped unless allowBroad.
func newPathPolicy(declared []string, clientRoots []string, allowBroad bool) *pathPolicy {
	roots := resolveRoots(append(append([]string{}, declared...), clientRoots...), allowBroad)
	if len(roots) == 0 {
		if cwd, err := os.Getwd(); err == nil {
			roots = resolveRoots([]string{cwd}, false)
		}
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
		paths = append(paths, filepath.Join(dir, "pastevault"), filepath.Join(dir, "gcloud"), filepath.Join(dir, "gh"))
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
		result = append(result, foldPath(abs))
		if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
			result = append(result, foldPath(real))
		}
	}

	return result
}

// within reports whether path is base or inside it (case-insensitively on
// case-insensitive file systems).
func within(base, path string) bool {
	if caseInsensitiveRoots {
		base, path = foldPath(base), foldPath(path)
		base, path = filepath.FromSlash(base), filepath.FromSlash(path)
	}
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

// withinFolded is within for already folded slash paths.
func withinFolded(base, path string) bool {
	return path == base || strings.HasPrefix(path, strings.TrimSuffix(base, "/")+"/")
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
		return "no usable roots are configured (start pastevault mcp with --root DIR, or use a client that provides MCP roots; the home directory and / are never roots without --allow-home-root)"
	}

	return "the allowed roots are " + strings.Join(p.roots, ", ")
}

// checkDenied refuses credential locations and, for writes, configuration
// directories. Matching ignores case and trailing dots and spaces.
func (p *pathPolicy) checkDenied(path string, writing bool) error {
	folded := foldPath(path)
	for _, denied := range p.denied {
		if withinFolded(denied, folded) {
			return refused("%s is in a protected location (credentials, agent harness state or the PasteVault config dir); it cannot be read or written through MCP", path)
		}
	}
	components := strings.Split(filepath.ToSlash(path), "/")
	for index, component := range components {
		name := foldName(component)
		if deniedComponents[name] && index < len(components)-1 {
			return refused("%s is inside %s; credential and repository directories cannot be read or written through MCP", path, component)
		}
		if writing && writeDeniedComponents[name] && index < len(components)-1 {
			return refused("%s is inside %s; receive does not write into repository, CI, editor or agent configuration directories", path, component)
		}
	}
	last := foldName(components[len(components)-1])
	if deniedNames[last] || deniedComponents[last] {
		return refused("%s is a credential file (or directory); it cannot be read or written through MCP", path)
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

// checkAllowed is the full check of a resolved or canonical path.
func (p *pathPolicy) checkAllowed(path string, writing bool) error {
	if err := p.checkDenied(path, writing); err != nil {
		return err
	}
	if !p.inRoots(path) {
		return refused("%s is outside the allowed roots: %s", path, p.rootsDescription())
	}
	return nil
}

// resolveRead opens an existing regular file inside the roots (send_file)
// and returns its canonical path, checked again from the open handle. The
// caller shares that path.
func (p *pathPolicy) resolveRead(path string) (string, error) {
	abs, err := p.absolute(path)
	if err != nil {
		return "", err
	}
	if err := p.checkAllowed(abs, false); err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "%s does not exist", abs)
		}
		return "", pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot read %s", abs)
	}
	if err := p.checkAllowed(real, false); err != nil {
		if !p.inRoots(real) {
			return "", refused("%s is a symlink to %s, outside the allowed roots", abs, real)
		}
		return "", err
	}

	file, err := openNoFollow(real)
	if err != nil {
		return "", pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot read %s", abs)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot read %s", abs)
	}
	if !info.Mode().IsRegular() {
		return "", refused("%s is not a regular file (send_file shares files, not directories or devices)", abs)
	}
	canonical, err := canonicalPath(file)
	if err != nil {
		return "", pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot resolve %s", abs)
	}
	if err := p.checkAllowed(canonical, false); err != nil {
		return "", err
	}

	return canonical, nil
}

// writeTarget is where receive places content: a file, or a directory
// whose file names receive chooses.
type writeTarget struct {
	path string
	dir  bool
}

// resolveWrite checks a receive destination before anything is opened. An
// existing directory, or a path ending in a separator, is a directory
// target; anything else a file target, whose directory must exist.
// Symlinked files are refused, symlinked directories are resolved and
// checked against the roots. A file target's name must be a safe name.
func (p *pathPolicy) resolveWrite(path string) (writeTarget, error) {
	wantDir := strings.HasSuffix(path, "/") || strings.HasSuffix(path, string(filepath.Separator))
	abs, err := p.absolute(path)
	if err != nil {
		return writeTarget{}, err
	}
	if err := p.checkAllowed(abs, true); err != nil {
		return writeTarget{}, err
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

	name := filepath.Base(abs)
	if reason := unsafeNameReason(name); reason != "" {
		return writeTarget{}, refused("receive does not create %s: %s. Choose another file name, a directory (receive then picks safe names), or save_as for secrets", name, reason)
	}
	realParent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return writeTarget{}, pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "the directory for %s does not exist", abs)
	}

	return p.checkResolvedWrite(filepath.Join(realParent, name), false)
}

func (p *pathPolicy) checkResolvedWrite(real string, dir bool) (writeTarget, error) {
	if err := p.checkAllowed(real, true); err != nil {
		return writeTarget{}, err
	}

	return writeTarget{path: real, dir: dir}, nil
}

// ── safe names ────────────────────────────────────────────────────────────

// riskyNames are files that agents, package managers, build tools or shells
// load from a project directory. receive never creates them from a
// sender-chosen name.
var riskyNames = setOf(
	"mcp.json", "claude.md", "claude.local.md", "agents.md", "gemini.md", "copilot-instructions.md",
	"makefile", "gnumakefile", "justfile", "taskfile.yml", "taskfile.yaml", "rakefile",
	"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "pnpm-workspace.yaml",
	"go.mod", "go.sum", "go.work", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "pipfile", "pipfile.lock",
	"cargo.toml", "cargo.lock", "gemfile", "gemfile.lock", "composer.json", "pom.xml", "build.gradle", "settings.gradle",
	"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "tsconfig.json",
)

// scriptExtensions are names receive prefixes so a share cannot take the
// place of a script a project runs.
var scriptExtensions = setOf(
	"sh", "bash", "zsh", "fish", "ps1", "psm1", "bat", "cmd", "exe", "com", "scr", "command", "msi", "dll", "so", "dylib",
)

var windowsReservedNames = setOf(
	"con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
	"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
)

// unsafeNameReason says why receive must not create a file with this name,
// or "" when it may.
func unsafeNameReason(name string) string {
	folded := foldName(name)
	stem := strings.SplitN(folded, ".", 2)[0]
	switch {
	case folded == "" || folded == "." || folded == "..":
		return "it is not a file name"
	case strings.HasPrefix(name, ".") || strings.HasPrefix(folded, "."):
		return "names starting with a dot are configuration files (.env, .envrc, .mcp.json, ...)"
	case riskyNames[folded]:
		return "tools and agents load files with this name from a project"
	case deniedNames[folded]:
		return "it is a credential file name"
	case windowsReservedNames[stem]:
		return "it is a reserved device name on Windows"
	case scriptExtensions[strings.TrimPrefix(strings.ToLower(filepath.Ext(folded)), ".")]:
		return "it is a script or executable name"
	}
	return ""
}

// safeFileName turns a sender-chosen name into one receive may create in a
// directory: control and separator characters replaced, trailing dots and
// spaces dropped, and risky names prefixed with "received-<slug>-".
func safeFileName(name, slug string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return '_'
		case strings.ContainsRune(`/\:*?"<>|`, r):
			return '_'
		}
		return r
	}, name)
	cleaned = strings.TrimRight(strings.TrimSpace(cleaned), ". ")
	if cleaned == "" {
		cleaned = "file"
	}
	if len(cleaned) > 200 {
		extension := filepath.Ext(cleaned)
		if len(extension) > 20 {
			extension = ""
		}
		cleaned = cleaned[:200-len(extension)] + extension
	}
	if unsafeNameReason(cleaned) == "" {
		return cleaned
	}

	renamed := fmt.Sprintf("received-%s-%s", slug, strings.TrimLeft(cleaned, ". "))
	if strings.HasSuffix(renamed, "-") {
		renamed += "file"
	}
	if scriptExtensions[strings.TrimPrefix(strings.ToLower(filepath.Ext(renamed)), ".")] {
		renamed += ".txt"
	}
	return renamed
}
