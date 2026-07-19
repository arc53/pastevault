package update

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func ShouldSpawnWorker(currentVersion, mode string) bool {
	if !IsReleaseVersion(currentVersion) || mode == ModeOff {
		return false
	}
	state := loadState()
	if time.Since(state.LastChecked) >= checkInterval {
		return true
	}
	if mode != ModeOn {
		return false
	}
	latest := state.LatestVersion
	if latest == "" || !IsNewer(latest, currentVersion) || latest == state.SkipVersion || StagedVersion() == latest {
		return false
	}
	return state.StageVersion != latest || time.Since(state.LastStageAttempt) >= stageRetryInterval
}

func SpawnWorker() {
	executable, err := os.Executable()
	if err != nil {
		return
	}
	command := exec.Command(executable, "update", "--worker")
	detachProcess(command)
	if command.Start() == nil {
		_ = command.Process.Release()
	}
}

func RunWorker(currentVersion string) {
	if os.Getenv("PASTEVAULT_NO_UPDATE_CHECK") != "" || !IsReleaseVersion(currentVersion) {
		return
	}
	mode, err := LoadMode()
	if err != nil || mode == ModeOff {
		return
	}

	releaseLock, ok := acquireStageLock()
	if !ok {
		return
	}
	defer releaseLock()

	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	release, err := FetchLatest(ctx, 30*time.Second)
	if err != nil {
		return
	}
	if RecordCheck(release) != nil {
		return
	}
	if mode != ModeOn || !IsNewer(release.TagName, currentVersion) ||
		release.TagName == SkipVersion() || StagedVersion() == release.TagName || !HasEmbeddedPublicKey() {
		return
	}

	executable, err := ExecutablePath()
	if err != nil || IsHomebrewPath(executable) || !IsWritableDir(filepath.Dir(executable)) {
		return
	}
	if recordStageAttempt(release.TagName) != nil {
		return
	}
	_ = Stage(ctx, release)
}
