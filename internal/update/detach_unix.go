//go:build !windows

package update

import (
	"os/exec"
	"syscall"
)

func detachProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
