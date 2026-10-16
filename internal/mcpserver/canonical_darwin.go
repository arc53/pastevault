//go:build darwin

package mcpserver

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"
)

// canonicalPath is the path the kernel has for an open file (F_GETPATH),
// with the file system's own letter case.
func canonicalPath(file *os.File) (string, error) {
	buffer := make([]byte, 1024) // MAXPATHLEN
	//nolint:staticcheck // F_GETPATH has no libSystem wrapper in syscall or x/sys.
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETPATH, uintptr(unsafe.Pointer(&buffer[0])))
	if errno != 0 {
		return "", &os.PathError{Op: "fcntl F_GETPATH", Path: file.Name(), Err: errno}
	}
	if end := bytes.IndexByte(buffer, 0); end >= 0 {
		buffer = buffer[:end]
	}
	return string(buffer), nil
}
