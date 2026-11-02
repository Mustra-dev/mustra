package agent

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestKillProcessRefusesTheObviouslyWrongTargets(t *testing.T) {
	cases := map[string]int32{
		"pid 0":            0,
		"a negative pid":   -1,
		"init":             1,
		"the agent itself": int32(os.Getpid()),
	}
	for name, pid := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := killProcess(pid, ""); err == nil {
				t.Fatalf("killProcess(%d) succeeded; it must refuse", pid)
			}
		})
	}
}

// The guard that matters: a pid is only meaningful at the instant it was
// observed, so a name that no longer matches means the number was recycled
// and the operator is about to kill something they never saw.
func TestKillProcessRefusesARecycledPID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX sleep as the victim")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start a victim process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	pid := int32(cmd.Process.Pid)

	_, err := killProcess(pid, "definitely-not-sleep")
	if err == nil {
		t.Fatal("killed a process whose name did not match what the console saw")
	}
	if !strings.Contains(err.Error(), "reused") {
		t.Errorf("error should explain the pid was reused, got: %v", err)
	}
	// And it must still be running — a refusal that killed it anyway is the
	// worst outcome of all, because the console reports failure.
	select {
	case <-waitFor(cmd):
		t.Fatal("the victim exited despite the kill being refused")
	case <-time.After(150 * time.Millisecond):
	}

	if _, err := killProcess(pid, "sleep"); err != nil {
		t.Fatalf("killing with the right name failed: %v", err)
	}
	select {
	case <-waitFor(cmd):
	case <-time.After(5 * time.Second):
		t.Fatal("process survived a kill it should not have")
	}
}

func waitFor(cmd *exec.Cmd) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()
	return done
}

// Without an expected name there is nothing to check a recycled PID
// against, so the kill is refused rather than done by number alone.
func TestKillProcessRequiresTheExpectedName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX sleep as the victim")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start a victim process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	for _, name := range []string{"", "   "} {
		if _, err := killProcess(int32(cmd.Process.Pid), name); err == nil || !strings.Contains(err.Error(), "expected process name") {
			t.Fatalf("killProcess with name %q: %v", name, err)
		}
	}
	select {
	case <-waitFor(cmd):
		t.Fatal("the victim exited although the kill was refused")
	case <-time.After(100 * time.Millisecond):
	}
}
