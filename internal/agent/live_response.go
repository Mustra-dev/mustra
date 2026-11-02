package agent

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

// Live response: acting on one endpoint during an incident, as opposed to
// deploying something to many.
//
// Killing a process is the smallest useful version of this and the one with
// the sharpest edge, so the guard matters more than the action. A PID is
// only meaningful at the instant it was observed: between the sensor
// collection that showed something suspicious and the moment an operator
// clicks kill, that PID may have been recycled onto an unrelated process —
// possibly one holding the machine up. So the console sends what it thinks
// the process is called, and the agent refuses if the name no longer
// matches. Killing the wrong process on somebody's server because a number
// got reused is not a failure mode worth accepting to save a round trip.

func killProcess(pid int32, expectedName string) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("refusing to signal pid %d", pid)
	}
	// Signalling our own process group would take the agent down with the
	// target, and the agent is how anyone finds out what happened.
	if int(pid) == os.Getpid() {
		return "", fmt.Errorf("refusing to kill the mustra agent itself")
	}
	// No name, no kill. The name is the only thing that tells a recycled
	// PID from the process the operator saw; skipping the check when it was
	// missing made the guard optional.
	if strings.TrimSpace(expectedName) == "" {
		return "", fmt.Errorf("refusing to kill pid %d without the expected process name", pid)
	}
	// PID 1 is init/launchd/System. Nothing good follows.
	if pid == 1 {
		return "", fmt.Errorf("refusing to kill pid 1")
	}

	p, err := process.NewProcess(pid)
	if err != nil {
		return "", fmt.Errorf("no process with pid %d is running (it may have already exited)", pid)
	}
	name, err := p.Name()
	if err != nil {
		return "", fmt.Errorf("could not read pid %d to confirm what it is: %w", pid, err)
	}
	// The whole point of carrying the name. A mismatch means the PID was
	// recycled between the operator seeing it and this arriving.
	if !strings.EqualFold(name, strings.TrimSpace(expectedName)) {
		return "", fmt.Errorf("pid %d is now %q, not %q — the pid was reused, so nothing was killed",
			pid, name, expectedName)
	}

	if err := p.Kill(); err != nil {
		return "", fmt.Errorf("could not kill %s (pid %d): %w", name, pid, err)
	}
	return fmt.Sprintf("killed %s (pid %s) on %s", name, strconv.Itoa(int(pid)), runtime.GOOS), nil
}
