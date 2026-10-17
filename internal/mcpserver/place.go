package mcpserver

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	pv "github.com/arc53/pastevault/internal/pastevault"
)

// receive never lets get write into the destination directly. get writes
// into a private staging directory (0700) inside the destination directory;
// receive then re-checks the destination from an open directory handle,
// chooses the final names itself, and links the files into place without
// following or replacing anything, except files it placed itself earlier in
// this session when the call asks to overwrite.

// stagingPrefix names receive's temporary directories.
const stagingPrefix = ".pastevault-receive-"

// placedFiles remembers what receive wrote in this session, so overwrite
// can only replace those files. Guarded by Server.localLock.
type placedFiles map[string]os.FileInfo

func placedKey(path string) string {
	return foldPath(path)
}

// mayReplace reports whether path is a file receive placed earlier in this
// session and that is still that same file.
func (p placedFiles) mayReplace(path string) bool {
	recorded, ok := p[placedKey(path)]
	if !ok {
		return false
	}
	current, err := os.Lstat(path)
	return err == nil && current.Mode().IsRegular() && os.SameFile(recorded, current)
}

func (p placedFiles) record(path string) {
	if info, err := os.Lstat(path); err == nil {
		p[placedKey(path)] = info
	}
}

// stagedReceive is an opened, re-checked destination directory with its
// staging directory.
type stagedReceive struct {
	dir       *os.File
	dirPath   string // canonical
	staging   string
	slug      string
	placed    []fileOutput
	writtenTo string
}

// openDestination opens dir (creating it when it is a new directory target
// whose ancestors were checked), canonicalises it from the handle, checks
// it against the roots and write deny lists again, and creates the staging
// directory inside it.
func (p *pathPolicy) openDestination(dir string, create bool) (*stagedReceive, error) {
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot create %s", dir)
		}
	}
	handle, err := openDirNoFollow(dir)
	if err != nil {
		return nil, refused("cannot open %s as a directory (receive does not write through symlinks): %v", dir, err)
	}
	canonical, err := canonicalPath(handle)
	if err == nil {
		err = p.checkAllowed(canonical, true)
	}
	if err != nil {
		handle.Close()
		return nil, err
	}
	staging, err := os.MkdirTemp(canonical, stagingPrefix)
	if err != nil {
		handle.Close()
		return nil, pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "cannot write to %s", canonical)
	}

	return &stagedReceive{dir: handle, dirPath: canonical, staging: staging}, nil
}

func (r *stagedReceive) close() {
	_ = os.RemoveAll(r.staging)
	_ = r.dir.Close()
}

// stagedFiles lists the regular files get wrote into the staging directory.
func (r *stagedReceive) stagedFiles() ([]string, error) {
	entries, err := os.ReadDir(r.staging)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// place moves one staged file to name in the destination. With replace
// (only for files placed earlier in this session) an existing file is
// replaced; otherwise an existing name is an error, or with rename the
// next free "name (n).ext".
func (r *stagedReceive) place(staged, name string, replace, rename bool, placed placedFiles) (string, error) {
	source := filepath.Join(r.staging, staged)
	extension := filepath.Ext(name)
	base := strings.TrimSuffix(name, extension)
	candidate := name
	for attempt := 1; ; attempt++ {
		target := filepath.Join(r.dirPath, candidate)
		var err error
		if replace && placed.mayReplace(target) {
			err = replaceIn(source, r.dir, candidate)
		} else {
			err = linkNoReplace(source, r.dir, candidate)
			if err != nil && !errors.Is(err, os.ErrExist) {
				// File systems without hard links: rename, after checking
				// nothing is there (not atomic, but never follows a link).
				if _, statErr := os.Lstat(target); errors.Is(statErr, fs.ErrNotExist) {
					err = os.Rename(source, target)
				}
			}
		}
		switch {
		case err == nil:
			_ = os.Remove(source)
			placed.record(target)
			info, statErr := os.Lstat(target)
			size := int64(0)
			if statErr == nil {
				size = info.Size()
			}
			r.placed = append(r.placed, fileOutput{Name: candidate, Size: size, Path: target})
			return target, nil
		case errors.Is(err, os.ErrExist) && rename && attempt < 1000:
			candidate = fmt.Sprintf("%s (%d)%s", base, attempt, extension)
		case errors.Is(err, os.ErrExist):
			return "", pv.NewError(pv.ExitLocalFile, pv.CodeLocalFile, "%s already exists; overwrite only replaces files receive wrote earlier in this session", target)
		default:
			return "", pv.WrapError(pv.ExitLocalFile, pv.CodeLocalFile, err, "could not write %s", target)
		}
	}
}
