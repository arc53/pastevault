//go:build windows

package mcpserver

import (
	"errors"
	"os"
	"path/filepath"
)

// linkNoReplace makes name in dir a hard link to source, failing with
// os.ErrExist when name exists.
func linkNoReplace(source string, dir *os.File, name string) error {
	err := os.Link(source, filepath.Join(dir.Name(), name))
	if errors.Is(err, os.ErrExist) {
		return os.ErrExist
	}
	return err
}

// replaceIn renames source over name in dir.
func replaceIn(source string, dir *os.File, name string) error {
	return os.Rename(source, filepath.Join(dir.Name(), name))
}
