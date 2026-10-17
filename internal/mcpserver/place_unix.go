//go:build unix

package mcpserver

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// linkNoReplace makes name in dir a hard link to source, failing with
// os.ErrExist when name exists (a symlink at name is never followed).
func linkNoReplace(source string, dir *os.File, name string) error {
	err := unix.Linkat(unix.AT_FDCWD, source, int(dir.Fd()), name, 0)
	if errors.Is(err, unix.EEXIST) {
		return os.ErrExist
	}
	return err
}

// replaceIn renames source over name in dir.
func replaceIn(source string, dir *os.File, name string) error {
	return unix.Renameat(unix.AT_FDCWD, source, int(dir.Fd()), name)
}
