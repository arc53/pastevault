//go:build unix && !linux && !darwin

package mcpserver

import (
	"os"
	"path/filepath"
)

// canonicalPath falls back to resolving the name the file was opened with.
func canonicalPath(file *os.File) (string, error) {
	return filepath.EvalSymlinks(file.Name())
}
