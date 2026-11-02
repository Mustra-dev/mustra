//go:build !windows

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// processAlive reports whether pid is a live (non-zombie) process. A
// re-parented child that has exited can linger as a zombie when PID 1 does
// not reap, and kill(pid, 0) still succeeds on one, so ask ps for its state.
func processAlive(t *testing.T, pid int) bool {
	t.Helper()
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	state := strings.TrimSpace(string(out))
	if err != nil || state == "" {
		return false
	}
	return !strings.HasPrefix(state, "Z")
}

func readPIDs(t *testing.T, path string) []int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the command never recorded its children: %v", err)
	}
	var pids []int
	for _, f := range strings.Fields(string(raw)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("bad pid %q", f)
		}
		pids = append(pids, pid)
	}
	return pids
}

// A timed-out package used to kill only /bin/sh: its children kept running
// re-parented to PID 1, held the output pipe open, and the call returned
// (as a plain failure) only when they finished on their own.
func TestSoftwareTimeoutKillsTheWholeProcessTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	command := "sh -c 'sleep 60 & echo $! >> " + pidFile + "; echo $$ >> " + pidFile + "; sleep 60'"
	start := time.Now()
	out, err := runSoftwareCommandIn(context.Background(), command, 1, "")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected a timeout, got success with %q", out)
	}
	if !strings.HasPrefix(err.Error(), "command exceeded its ") || !strings.HasSuffix(err.Error(), " timeout") {
		t.Fatalf("timeout must be reported in the wording the server maps to timed_out, got %q", err)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("a 1s budget took %s to come back", elapsed)
	}
	pids := readPIDs(t, pidFile)
	deadline := time.Now().Add(2 * time.Second)
	for _, pid := range pids {
		for processAlive(t, pid) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if processAlive(t, pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Errorf("pid %d survived the timeout", pid)
		}
	}
}

// A package that starts something in the background and exits must not
// be held until its timeout because the background process inherited the
// output pipe, and must not have that process killed: leaving a daemon
// running can be what the package is for.
func TestSoftwareCommandDoesNotWaitForOrKillBackgroundChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	command := "sleep 30 & echo $! > " + pidFile + "; echo installed"
	start := time.Now()
	out, err := runSoftwareCommandIn(context.Background(), command, 20, "")
	elapsed := time.Since(start)
	pids := readPIDs(t, pidFile)
	t.Cleanup(func() {
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	if err != nil {
		t.Fatalf("a command that exited 0 must succeed, got %v (%q)", err, out)
	}
	if !strings.Contains(out, "installed") {
		t.Errorf("output lost: %q", out)
	}
	if elapsed > softwareWaitDelay+3*time.Second {
		t.Errorf("returned after %s; the background child held the call", elapsed)
	}
	if !processAlive(t, pids[0]) {
		t.Error("the background child of a successful command was killed")
	}
}

func TestSoftwareCommandStillReportsExitFailures(t *testing.T) {
	out, err := runSoftwareCommandIn(context.Background(), "echo nope; exit 7", 10, "")
	if err == nil || !strings.Contains(err.Error(), "exit status 7") {
		t.Fatalf("want exit status 7, got %v", err)
	}
	if !strings.Contains(out, "nope") {
		t.Errorf("output lost: %q", out)
	}
}
