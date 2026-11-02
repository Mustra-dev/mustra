package agent

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two updaters on the same files once left an endpoint with no agent
// binary at all; only one may hold the lock, and a dead one's lock expires.
func TestUpdateLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	release, ok := acquireUpdateLock(dir)
	if !ok {
		t.Fatal("first updater could not take the lock")
	}
	if _, ok := acquireUpdateLock(dir); ok {
		t.Fatal("second updater took a held lock")
	}
	if _, busy := updateInProgress(dir); !busy {
		t.Error("a held lock should read as an update in progress")
	}
	release()
	if _, ok := acquireUpdateLock(dir); !ok {
		t.Fatal("lock not reusable after release")
	}
	old := time.Now().Add(-updateStale - time.Minute)
	if err := os.Chtimes(filepath.Join(dir, updateLockFile), old, old); err != nil {
		t.Fatal(err)
	}
	if _, ok := acquireUpdateLock(dir); !ok {
		t.Error("a stale lock should be taken over")
	}
}

func TestUpdateInProgressFromPendingState(t *testing.T) {
	dir := t.TempDir()
	write := func(started time.Time) {
		raw, _ := json.Marshal(updateState{Version: "0.57.3", Started: started})
		if err := os.WriteFile(filepath.Join(dir, updateStateFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(time.Now())
	if v, busy := updateInProgress(dir); !busy || v != "0.57.3" {
		t.Errorf("fresh pending update: got %q, %v", v, busy)
	}
	write(time.Now().Add(-updateStale - time.Minute))
	if _, busy := updateInProgress(dir); busy {
		t.Error("an abandoned pending update should not block a new one")
	}
}

// A second updater whose staged build is gone must not move the installed
// binary; that move is what lost the binary.
func TestApplyUpdateWithoutStagedBuildTouchesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the updater's 2s grace")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "mustra-agent")
	if err := os.WriteFile(exe, []byte("installed"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := updateState{Exe: exe, New: exe + ".new", Previous: exe + ".previous", Version: "0.57.3", DataDir: dir, Started: time.Now()}
	raw, _ := json.Marshal(st)
	statePath := filepath.Join(dir, updateStateFile)
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// The check comes before the service is stopped, so nothing outside
	// dir is touched here.
	if err := ApplyUpdate(statePath, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected a failure with no staged build")
	}
	if b, err := os.ReadFile(exe); err != nil || string(b) != "installed" {
		t.Fatalf("installed binary was disturbed: %q, %v", b, err)
	}
}

// The agent waits for the detached updater to take its lock before saying
// "updating"; one that never starts withdraws the staged update so the
// next try is not refused as already in progress.
func TestConfirmHelperStarted(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, updateStateFile)
	staged := filepath.Join(dir, "agent.new")
	write := func() {
		if err := os.WriteFile(state, []byte(`{"version":"9.9.9"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(staged, []byte("new build"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	write()
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(dir, updateLockFile), []byte("1\n"), 0o600)
	}()
	if err := confirmHelperStarted(dir, state, staged, "helper", 3*time.Second); err != nil {
		t.Fatalf("an updater that took its lock: %v", err)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatal("a started update lost its state file")
	}

	_ = os.Remove(filepath.Join(dir, updateLockFile))
	write()
	err := confirmHelperStarted(dir, state, staged, "helper", 400*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("an updater that never started: %v", err)
	}
	if v, busy := updateInProgress(dir); busy {
		t.Fatalf("withdrawn update still blocks retries (%q)", v)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatal("the staged build was left behind")
	}
}
