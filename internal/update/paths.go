package update

import (
	"fmt"
	"os"
	"path/filepath"
)

func ExecutablePath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not determine executable path: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("could not resolve executable path: %w", err)
	}
	return realPath, nil
}

func IsWritableDir(dir string) bool {
	file, err := os.CreateTemp(dir, ".pastevault-write-test-*")
	if err != nil {
		return false
	}
	path := file.Name()
	closeErr := file.Close()
	removeErr := os.Remove(path)
	return closeErr == nil && removeErr == nil
}
