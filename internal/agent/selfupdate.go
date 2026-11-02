package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Updating the agent from the machine it is running on.
//
// The whole difficulty is that the updater has to outlive the thing it is
// updating. A service cannot overwrite its own running binary, so the update
// must stop the service, replace the file and start it again -- which means
// the process doing that work cannot be a child of the service, or it dies
// halfway through and leaves the endpoint with no agent at all.
//
// So the command is not just run; it is deliberately detached from this
// process, differently on each platform, because "detached" means something
// different on each:
//
//   - systemd kills a unit's whole control group on stop, so a plain
//     background child is killed the instant the installer stops the service.
//     systemd-run puts the updater in its own transient unit, outside that
//     cgroup, which is the only reliable answer on a systemd host.
//   - Windows can terminate a service's children when the service stops, so
//     Start-Process is used to create a genuinely independent process rather
//     than a child.
//   - macOS has neither systemd-run nor setsid — setsid is a util-linux
//     tool, not something BSDs ship — so the original code fell through to
//     running the updater as a plain child of the agent, with a comment
//     asserting that was safe "which includes macOS". It is not. The
//     installer's first act is to unload the launchd job, which is the
//     agent, and a child of a job launchd is tearing down is not a process
//     with a future. launchctl submit is the macOS answer to systemd-run:
//     it hands the updater to launchd as a job of its own.
//   - Elsewhere, a new session detaches the updater from this process's
//     group. Done with Setsid on the exec rather than by shelling out to a
//     setsid binary, so it does not depend on a tool the platform may not
//     have — which is precisely how macOS ended up on the last resort.
//
// The command is never the server's any more. It is always this agent's own
// updater helper (selfupdate_apply.go), run with paths the agent chose,
// after the update it applies has been verified against the pinned key.

// spawnDetachedHelper starts "<helper> --apply-update <state>" detached.
func spawnDetachedHelper(ctx context.Context, helper, statePath string) error {
	if runtime.GOOS == "windows" {
		return spawnDetachedUpdater(ctx, "& "+psQuote(helper)+" --apply-update "+psQuote(statePath))
	}
	return spawnDetachedUpdater(ctx, shQuoteArg(helper)+" --apply-update "+shQuoteArg(statePath))
}

// shQuoteArg renders a POSIX shell single-quoted word.
func shQuoteArg(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func spawnDetachedUpdater(ctx context.Context, command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("no update command was provided")
	}

	switch runtime.GOOS {
	case "windows":
		// Start-Process detaches properly; a plain child can be terminated
		// with the service when the installer stops it.
		// Full paths, both times. A service's PATH is not a user's, and a
		// bare "powershell.exe" here resolved to "Access is denied" on a
		// real endpoint -- inside a detached process, so the update
		// reported success and did nothing.
		shell := powershellPath()
		ps := "Start-Process -FilePath " + psQuote(shell) + " -WindowStyle Hidden -ArgumentList " +
			"'-NoProfile','-ExecutionPolicy','Bypass','-Command'," + psQuote(command)
		cmd := exec.Command(shell, "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-Command", ps)
		return cmd.Start()

	case "darwin":
		// launchd's equivalent of systemd-run. The updater becomes its own
		// job, so unloading the agent's job — the installer's first act —
		// cannot take it down mid-update.
		//
		// A unique label per attempt: launchctl refuses to submit a label
		// that is already known, and a failed update from an hour ago must
		// not stop this one.
		label := fmt.Sprintf("com.mustra.agent-update.%d", time.Now().UnixNano())
		// The job removes itself when the update finishes. launchctl submit
		// has no --collect, so a submitted job stays registered after it
		// exits -- and because the label is unique per attempt, every
		// update left another dead entry in `launchctl list` for good. One
		// is untidy; one per update, forever, is the kind of residue that
		// makes somebody distrust the agent that left it.
		cmd := exec.Command("launchctl", "submit", "-l", label, "--", "/bin/sh", "-c",
			command+"; /bin/launchctl remove "+label)
		if err := cmd.Run(); err == nil {
			return nil
		}
		// Fall through to a new session if launchctl would not take it.
		return startInNewSession(command)

	default:
		// systemd-run is often installed where systemd is not running (a
		// container, a chroot); it then fails, so check the system was
		// actually booted with it.
		if _, err := exec.LookPath("systemd-run"); err == nil && hasSystemd() {
			// --collect so the transient unit is cleaned up when it exits
			// rather than lingering as a failed unit somebody has to reset.
			// A unique name per attempt: a fixed one made a second update
			// fail with "unit already exists" while the first was still
			// winding down, and Start() without a wait reported success
			// regardless. systemd-run returns once the unit is queued, so
			// Run() is quick and its error is real.
			unit := fmt.Sprintf("mustra-agent-update-%d", time.Now().UnixNano())
			out, err := exec.Command("systemd-run", "--collect", "--unit", unit, "/bin/sh", "-c", command).CombinedOutput()
			if err != nil {
				return fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
		return startInNewSession(command)
	}
}

// psQuote renders a string as a PowerShell single-quoted literal, doubling
// embedded quotes. The command is server-authored, but quoting it correctly
// is still the difference between an update and a syntax error on every
// Windows endpoint at once.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// powershellPath resolves Windows PowerShell by absolute path. Relying on
// PATH is what turned a working update into a silent one.
func powershellPath() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
}
