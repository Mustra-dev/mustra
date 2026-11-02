//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// configureSoftwareProcess puts a package command in its own process group
// so a timeout can kill everything it started, not just the shell.
//
// Killing only /bin/sh left `sleep`, apt or an installer running,
// re-parented to PID 1 and still holding the output pipe, so the call
// blocked until that grandchild exited on its own. Unlike the custom-sensor
// helper this does not kill the group after a normal exit: a package may
// legitimately leave a daemon running.
func configureSoftwareProcess(cmd *exec.Cmd) (afterStart func() error, release func(), err error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return func() error { return nil }, func() {}, nil
}
