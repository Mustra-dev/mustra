package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDecideRecovery(t *testing.T) {
	healthy := recoverFacts{ServiceInstalled: true, ServiceEnabled: true, HeartbeatKnown: true, HeartbeatAge: time.Minute, ExeExists: true, ExeIsLKG: true}
	stale := healthy
	stale.HeartbeatAge = time.Hour
	for _, c := range []struct {
		name  string
		f     func(recoverFacts) recoverFacts
		first bool
		want  recoverAction
	}{
		{"running agent is left alone", func(f recoverFacts) recoverFacts { return healthy }, false, recoverNothing},
		{"uninstalled: the job removes itself", func(f recoverFacts) recoverFacts { f.ServiceInstalled = false; return f }, false, recoverUnregister},
		{"disabled on purpose is never restarted", func(f recoverFacts) recoverFacts { f.ServiceEnabled = false; return f }, false, recoverNothing},
		{"an update in progress is not interfered with", func(f recoverFacts) recoverFacts { f.UpdateInProgress = true; return f }, false, recoverNothing},
		{"a stale beat is looked at twice", func(f recoverFacts) recoverFacts { return f }, true, recoverStaleRecheck},
		{"still stale, right build: restart", func(f recoverFacts) recoverFacts { return f }, false, recoverRestart},
		{"still stale, other build: restore", func(f recoverFacts) recoverFacts { f.ExeIsLKG = false; return f }, false, recoverRestoreLKG},
		{"binary missing: restore at once", func(f recoverFacts) recoverFacts { f.ExeExists, f.ExeIsLKG = false, false; return f }, true, recoverRestoreLKG},
		{"no heartbeat ever: treated as stale", func(f recoverFacts) recoverFacts { f.HeartbeatKnown = false; return f }, false, recoverRestart},
	} {
		got, why := decideRecovery(c.f(stale), c.first)
		if got != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, got, why, c.want)
		}
	}
}

func TestLKGPathAndRefresh(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "mustra-agent"+exeSuffix())
	if got := lkgPath(exe); got != filepath.Join(dir, "mustra-agent.lkg"+exeSuffix()) {
		t.Fatalf("lkgPath = %s", got)
	}
	if !isInstalledAgent(exe) || isInstalledAgent(lkgPath(exe)) {
		t.Fatal("only the installed binary is the installed agent")
	}
	if err := os.WriteFile(exe, []byte("build-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := refreshLastKnownGood(exe, dir, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(lkgPath(exe)); string(b) != "build-1" {
		t.Fatalf("lkg holds %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(lkgPath(exe)); fi.Mode().Perm()&0o100 == 0 {
			t.Error("the known-good copy must stay executable")
		}
	}
	// A new build replaces it; the same build does not rewrite it.
	_ = os.WriteFile(exe, []byte("build-2"), 0o755)
	if err := refreshLastKnownGood(exe, dir, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(lkgPath(exe)); string(b) != "build-2" {
		t.Fatalf("lkg holds %q after a new build", b)
	}
	fi1, _ := os.Stat(lkgPath(exe))
	time.Sleep(10 * time.Millisecond)
	_ = refreshLastKnownGood(exe, dir, "1.1.0")
	fi2, _ := os.Stat(lkgPath(exe))
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Error("an unchanged build was copied again")
	}
	if _, err := os.Stat(filepath.Join(dir, lkgStateFile)); err != nil {
		t.Error("no last-known-good state written")
	}
}

func TestAppendBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	for i := 0; i < 100; i++ {
		appendBounded(p, "0123456789\n", 200)
	}
	if fi, _ := os.Stat(p); fi.Size() > 211 {
		t.Fatalf("log grew to %d bytes", fi.Size())
	}
}

// The whole run: a build that is down and is not the known-good one is
// replaced by it, the failed build is kept aside, the service is started,
// and the agent will report what happened when it next starts.
func TestRecoverRestoresLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "mustra-agent"+exeSuffix())
	lkg := lkgPath(exe)
	_ = os.WriteFile(exe, []byte("broken-2.0"), 0o755)
	_ = os.WriteFile(lkg, []byte("good-1.9"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, lkgStateFile), []byte(`{"version":"1.9.0"}`), 0o600)
	hb := filepath.Join(dir, heartbeatFile)
	_ = os.WriteFile(hb, []byte("x"), 0o600)
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(hb, old, old)

	var stopped, started, waited int
	defer func() {
		recoverServiceRegistered, recoverStopService, recoverStartService = agentServiceRegistered, stopAgentService, restartAgentService
		recoverUnregisterJob, recoverWait, recoverSelf = uninstallRecoveryJob, time.Sleep, os.Executable
	}()
	recoverServiceRegistered = func() (bool, bool) { return true, true }
	recoverStopService = func(string) error { stopped++; return nil }
	recoverStartService = func(string) error { started++; return nil }
	recoverUnregisterJob = func() error { t.Fatal("must not unregister an installed agent"); return nil }
	recoverWait = func(time.Duration) { waited++ }
	recoverSelf = func() (string, error) { return lkg, nil }

	if err := Recover(dir, exe, testLogger()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "good-1.9" {
		t.Fatalf("installed binary is %q, want the known-good build", b)
	}
	if b, _ := os.ReadFile(exe + ".failed"); string(b) != "broken-2.0" {
		t.Fatalf("the failed build was not kept aside: %q", b)
	}
	if waited != 1 || stopped != 1 || started != 1 {
		t.Fatalf("waited %d, stopped %d, started %d", waited, stopped, started)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, updateResultFile)); err != nil || !strings.Contains(string(raw), "1.9.0") {
		t.Fatalf("no update result for the agent to report: %s %v", raw, err)
	}

	// A healthy agent afterwards: nothing more happens.
	_ = os.Chtimes(hb, time.Now(), time.Now())
	stopped, started = 0, 0
	if err := Recover(dir, exe, testLogger()); err != nil || stopped+started != 0 {
		t.Fatalf("acted on a running agent: %v %d %d", err, stopped, started)
	}
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// An agent that runs but cannot reach the control plane keeps the
// recovery heartbeat fresh, so the recovery job does not take it for dead
// and roll it back to the previous build. It does not beat while an update
// is pending: an uncommitted build is the updater's to roll back.
func TestBeatWhileRunningWithoutControlPlane(t *testing.T) {
	defer func(d time.Duration) { heartbeatEvery = d }(heartbeatEvery)
	heartbeatEvery = 10 * time.Millisecond
	dir := t.TempDir()
	a := &Agent{cfg: Config{DataDir: filepath.Join(dir, "agent.db")}}
	hb := filepath.Join(dir, heartbeatFile)

	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		a.beatWhileRunning(ctx)
	}

	st, _ := json.Marshal(updateState{Version: "2.0.0", Started: time.Now()})
	_ = os.WriteFile(filepath.Join(dir, updateStateFile), st, 0o600)
	run()
	if _, err := os.Stat(hb); err == nil {
		t.Fatal("beat while an update was pending")
	}

	_ = os.Remove(filepath.Join(dir, updateStateFile))
	run()
	fi, err := os.Stat(hb)
	if err != nil {
		t.Fatal("no heartbeat from a running agent without a control plane")
	}
	f := recoverFacts{ServiceInstalled: true, ServiceEnabled: true, HeartbeatKnown: true,
		HeartbeatAge: time.Since(fi.ModTime()), ExeExists: true, ExeIsLKG: false}
	if got, why := decideRecovery(f, false); got != recoverNothing {
		t.Fatalf("recovery would %s a running agent within an update's first minutes: %s", got, why)
	}
}
