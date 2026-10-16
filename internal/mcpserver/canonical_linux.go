//go:build linux

package mcpserver

import (
	"fmt"
	"os"
	"path/filepath"
)

// canonicalPath is the path the kernel has for an open file.
func canonicalPath(file *os.File) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
	if err == nil && filepath.IsAbs(path) {
		return path, nil
	}
	return filepath.EvalSymlinks(file.Name())
}
