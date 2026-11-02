//go:build !windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// startInNewSession runs the updater as a session leader, so it is not in
// the agent's process group and does not die with it.
//
// Setsid on the exec rather than a `setsid` command: the syscall is in
// every Unix kernel, while the binary is util-linux and absent on macOS and
// the BSDs. Depending on the binary is what silently demoted macOS to
// running the updater as a plain child.
func startInNewSession(command string) error {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// stopAgentService and startAgentService are what the updater helper uses
// around the binary swap.
//
// systemd: a plain stop and start of the unit. launchd: nothing to stop —
// with KeepAlive, launchd would only respawn the old binary, and a running
// process keeps the file it was started from anyway — then kickstart -k,
// which kills the running job and starts whatever the path holds now.
// Neither (a Linux host without systemd, where something else supervises
// the agent): ask the running agent to exit, and let its supervisor start
// whatever the path now holds.
func stopAgentService(dataDir string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if !hasSystemd() {
		return signalRecordedAgent(dataDir)
	}
	return exec.Command("systemctl", "stop", "mustra-agent").Run()
}

func startAgentService(dataDir string) error {
	switch runtime.GOOS {
	case "linux":
		if !hasSystemd() {
			return nil // the supervisor restarts it
		}
		return exec.Command("systemctl", "start", "mustra-agent").Run()
	case "darwin":
		return exec.Command("launchctl", "kickstart", "-k", "system/com.mustra.agent").Run()
	}
	return fmt.Errorf("no service manager to restart the agent on %s", runtime.GOOS)
}

func hasSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// signalRecordedAgent sends SIGTERM to the agent that recorded its PID and
// waits for it to go.
func signalRecordedAgent(dataDir string) error {
	raw, err := os.ReadFile(filepath.Join(dataDir, agentPIDFile))
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 || pid == os.Getpid() {
		return fmt.Errorf("no usable agent pid recorded")
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return err
	}
	for i := 0; i < 30; i++ {
		if syscall.Kill(pid, 0) != nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("agent pid %d did not exit", pid)
}
