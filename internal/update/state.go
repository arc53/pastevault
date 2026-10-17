package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	checkInterval      = 24 * time.Hour
	stageRetryInterval = time.Hour
	stateLockTimeout   = 2 * time.Second
	stateLockStaleAge  = time.Minute
)

type settings struct {
	AutoUpdate string `json:"auto_update"`
}

type checkState struct {
	LastChecked      time.Time `json:"last_checked"`
	LatestVersion    string    `json:"latest_version"`
	SkipVersion      string    `json:"skip_version,omitempty"`
	LastStageAttempt time.Time `json:"last_stage_attempt,omitempty"`
	StageVersion     string    `json:"stage_version,omitempty"`
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("could not determine user config directory: %w", err)
	}
	return filepath.Join(base, "pastevault"), nil
}

func settingsPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}

func statePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "update-check.json"), nil
}

func LoadMode() (string, error) {
	path, err := settingsPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ModeOn, nil
		}
		return "", err
	}

	var value settings
	if err := json.Unmarshal(data, &value); err != nil {
		return "", fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if value.AutoUpdate == "" {
		return ModeOn, nil
	}
	if !validMode(value.AutoUpdate) {
		return "", fmt.Errorf("invalid auto-update mode %q in %s", value.AutoUpdate, path)
	}
	return value.AutoUpdate, nil
}

func SetMode(mode string) error {
	if !validMode(mode) {
		return fmt.Errorf("invalid auto-update mode %q (use on, notify, or off)", mode)
	}
	path, err := settingsPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings{AutoUpdate: mode}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if mode != ModeOn {
		ClearStaging()
	}
	return nil
}

func validMode(mode string) bool {
	return mode == ModeOn || mode == ModeNotify || mode == ModeOff
}

func loadState() checkState {
	path, err := statePath()
	if err != nil {
		return checkState{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return checkState{}
	}
	var state checkState
	if json.Unmarshal(data, &state) != nil {
		return checkState{}
	}
	return state
}

func saveState(state checkState) error {
	path, err := statePath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".pastevault-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func mutateState(mutate func(*checkState)) error {
	release, err := acquireStateLock(stateLockTimeout)
	if err != nil {
		return err
	}
	defer release()
	state := loadState()
	mutate(&state)
	return saveState(state)
}

func acquireStateLock(timeout time.Duration) (func(), error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "update-state.lock")
	deadline := time.Now().Add(timeout)
	for {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = file.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		// On Windows, creating a file whose deletion by the previous holder
		// is still pending fails with "Access is denied": wait as for a
		// held lock.
		if !os.IsExist(err) && !(runtime.GOOS == "windows" && os.IsPermission(err)) {
			return nil, err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) >= stateLockStaleAge {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for update state lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func RecordCheck(release *Release) error {
	return mutateState(func(state *checkState) {
		state.LastChecked = time.Now()
		state.LatestVersion = release.TagName
	})
}

func recordStageAttempt(version string) error {
	return mutateState(func(state *checkState) {
		state.LastStageAttempt = time.Now()
		state.StageVersion = version
	})
}

func SkipVersion() string {
	return loadState().SkipVersion
}

func SetSkipVersion(version string) error {
	return mutateState(func(state *checkState) {
		state.SkipVersion = version
	})
}

func CachedNotice(current string) string {
	if !IsReleaseVersion(current) {
		return ""
	}
	state := loadState()
	if state.LatestVersion == "" || !IsNewer(state.LatestVersion, current) || state.LatestVersion == state.SkipVersion {
		return ""
	}
	return state.LatestVersion
}
