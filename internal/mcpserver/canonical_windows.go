//go:build windows

package mcpserver

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// FILE_NAME_NORMALIZED | VOLUME_NAME_DOS (both 0): a normalized C:\ path.
const fileNameNormalizedDOS = 0

// openNoFollow opens a file for reading. (Symlinks were resolved and checked
// before; the handle's final path is checked again by the caller.)
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

// openDirNoFollow opens a directory.
func openDirNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

// canonicalPath is the final path of an open handle
// (GetFinalPathNameByHandle): links resolved, 8.3 short names expanded,
// the file system's own letter case.
func canonicalPath(file *os.File) (string, error) {
	handle := windows.Handle(file.Fd())
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), fileNameNormalizedDOS)
		if err != nil {
			return "", &os.PathError{Op: "GetFinalPathNameByHandle", Path: file.Name(), Err: err}
		}
		if int(n) < len(buffer) {
			path := windows.UTF16ToString(buffer[:n])
			switch {
			case strings.HasPrefix(path, `\\?\UNC\`):
				path = `\\` + path[len(`\\?\UNC\`):]
			case strings.HasPrefix(path, `\\?\`):
				path = path[len(`\\?\`):]
			}
			return path, nil
		}
		buffer = make([]uint16, n+1)
	}
}
