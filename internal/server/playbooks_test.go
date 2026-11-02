package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestShouldRunStep(t *testing.T) {
	cases := []struct {
		runIf, prev string
		want        bool
	}{
		{"always", "failed", true},
		{"", "failed", true}, // blank means always
		{"previous_succeeded", "succeeded", true},
		{"previous_succeeded", "failed", false},
		{"previous_succeeded", "skipped", false},
		{"previous_failed", "failed", true},
		{"previous_failed", "succeeded", false},
	}
	for _, c := range cases {
		reason, run := shouldRunStep(c.runIf, c.prev)
		if run != c.want {
			t.Errorf("run_if=%q prev=%q -> %v, want %v", c.runIf, c.prev, run, c.want)
		}
		// A skipped step has to say why, or a table full of "skipped" is
		// unreadable.
		if !run && reason == "" {
			t.Errorf("run_if=%q prev=%q skipped with no reason", c.runIf, c.prev)
		}
	}
}

func TestPlaybookRunStatus(t *testing.T) {
	if got := playbookRunStatus(3, 0); got != "succeeded" {
		t.Errorf("all good -> %q", got)
	}
	if got := playbookRunStatus(0, 3); got != "failed" {
		t.Errorf("none good -> %q", got)
	}
	// The common case, and the one worth its own word.
	if got := playbookRunStatus(36, 3); got != "partial" {
		t.Errorf("mixed -> %q, want partial", got)
	}
}

func TestPlaybookStepLabelFallsBackToSomethingUseful(t *testing.T) {
	if got := (playbookStep{Kind: "patch"}).label(2); got != "step 3 (patch)" {
		t.Errorf("unnamed step labelled %q", got)
	}
	if got := (playbookStep{Name: "  ", Kind: "wait"}).label(0); got != "step 1 (wait)" {
		t.Errorf("whitespace name should not count as a name, got %q", got)
	}
	if got := (playbookStep{Name: "Reboot", Kind: "package"}).label(0); got != "Reboot" {
		t.Errorf("named step labelled %q", got)
	}
}

func TestPlaybookStepTimeoutFallsBack(t *testing.T) {
	if got := (playbookStep{}).timeout(5 * time.Minute); got != 5*time.Minute {
		t.Errorf("no timeout set -> %v, want the per-kind default", got)
	}
	if got := (playbookStep{TimeoutSeconds: 90}).timeout(5 * time.Minute); got != 90*time.Second {
		t.Errorf("explicit timeout -> %v", got)
	}
}

func TestPlaybookTargetDescSaysWhatItWillTouch(t *testing.T) {
	if got := playbookTargetDesc(store.Playbook{}); got != "every endpoint" {
		t.Errorf("untargeted playbook described as %q", got)
	}
	if got := playbookTargetDesc(store.Playbook{GroupID: "g", GroupName: "Domain Controllers", OS: "windows"}); got != "group: Domain Controllers · windows" {
		t.Errorf("described as %q", got)
	}
	// A group that has been deleted leaves the id behind. Describing that
	// as "every endpoint" would misreport the blast radius of the run.
	if got := playbookTargetDesc(store.Playbook{GroupID: "gone"}); got == "every endpoint" {
		t.Error("a playbook with a group must never be described as targeting everything")
	}
}

// A schedule and a person can both start the same playbook. Two passes at
// once means the same endpoint gets the same reboot step twice,
// concurrently — so the second must be refused rather than queued.
func TestInflightRefusesASecondRunOfTheSameThing(t *testing.T) {
	f := newInflight()
	if !f.claim("playbook:pb-1") {
		t.Fatal("the first claim was refused")
	}
	if f.claim("playbook:pb-1") {
		t.Fatal("a second run of the same playbook was allowed")
	}
	// A different playbook running at the same time is fine, and often the
	// point — the guard is per id, not global.
	if !f.claim("playbook:pb-2") {
		t.Error("an unrelated playbook was blocked by the first")
	}
	if !f.running("playbook:pb-1") {
		t.Error("running() disagrees with claim()")
	}
	f.release("playbook:pb-1")
	if f.running("playbook:pb-1") {
		t.Error("still reported as running after release")
	}
	if !f.claim("playbook:pb-1") {
		t.Error("could not re-claim after release — a failed run would block it for ever")
	}
}

// The guard is touched from HTTP handlers and two scheduler loops at once.
func TestInflightIsSafeUnderConcurrency(t *testing.T) {
	f := newInflight()
	const goroutines = 50
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.claim("enforce:p-1") {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("%d goroutines claimed the same id, want exactly 1", got)
	}
}
