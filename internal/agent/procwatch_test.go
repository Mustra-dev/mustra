package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

func newTestProcWatcher() *procWatcher {
	return &procWatcher{
		events:  make(chan proto.ProcessEvent, 8),
		pending: map[string]*proto.ProcessEvent{},
		since:   time.Now().UTC(),
	}
}

// Measured on a real hypervisor: 1530 execs a minute, 169 distinct
// commands. Collapsing is what makes the feed both affordable to keep and
// possible to read.
func TestRecordCollapsesIdenticalInvocations(t *testing.T) {
	pw := newTestProcWatcher()
	for i := 0; i < 40; i++ {
		pw.record(proto.ProcessEvent{
			PID: int32(1000 + i), Name: "systemctl",
			Cmdline: "/usr/bin/systemctl status canary.service", Username: "root",
		})
	}
	pw.record(proto.ProcessEvent{PID: 2000, Name: "systemctl",
		Cmdline: "/usr/bin/systemctl restart nginx", Username: "root"})

	if len(pw.pending) != 2 {
		t.Fatalf("got %d rows, want 2 (one per distinct command)", len(pw.pending))
	}
	var collapsed *proto.ProcessEvent
	for _, ev := range pw.pending {
		if ev.Cmdline == "/usr/bin/systemctl status canary.service" {
			collapsed = ev
		}
	}
	if collapsed == nil {
		t.Fatal("the repeated command is missing")
	}
	if collapsed.Count != 40 {
		t.Errorf("count = %d, want 40", collapsed.Count)
	}
	// A different user running the same command is a different fact.
	pw.record(proto.ProcessEvent{PID: 3000, Name: "systemctl",
		Cmdline: "/usr/bin/systemctl status canary.service", Username: "www-data"})
	if len(pw.pending) != 3 {
		t.Errorf("got %d rows, want 3 — the user is part of the identity", len(pw.pending))
	}
}

// An exec the kernel reported but /proc could not describe is a number, not
// a row: a row with no name is one nobody can act on, and a guessed name
// would be worse than the gap.
func TestRecordCountsUnidentifiedRatherThanListingThem(t *testing.T) {
	pw := newTestProcWatcher()
	pw.record(proto.ProcessEvent{PID: 10}) // no name
	pw.record(proto.ProcessEvent{PID: 11, Name: "sshd"})
	if len(pw.pending) != 1 {
		t.Fatalf("pending = %d, want only the named one", len(pw.pending))
	}
	if pw.unidentified != 1 {
		t.Errorf("unidentified = %d, want 1", pw.unidentified)
	}
}

// A build machine can start hundreds of processes a second. Past the cap
// they are counted, and every one is still accounted for.
func TestRecordCapsAndCounts(t *testing.T) {
	pw := newTestProcWatcher()
	const burst = maxProcEventsPerBatch + 40
	for i := 0; i < burst; i++ {
		// Distinct command lines: the cap bites on variety, not repetition.
		pw.record(proto.ProcessEvent{PID: int32(i), Name: "cc1", Cmdline: fmt.Sprintf("cc1 -c f%d.c", i)})
	}
	if len(pw.pending) != maxProcEventsPerBatch {
		t.Fatalf("pending = %d, want %d", len(pw.pending), maxProcEventsPerBatch)
	}
	_ = burst
	if len(pw.pending)+pw.suppressed != burst {
		t.Errorf("%d + %d = %d, want every start accounted for (%d)",
			len(pw.pending), pw.suppressed, len(pw.pending)+pw.suppressed, burst)
	}
}

// One pathological command line must not dominate a batch.
func TestRecordTruncatesTheCommandLine(t *testing.T) {
	pw := newTestProcWatcher()
	pw.record(proto.ProcessEvent{PID: 1, Name: "sh", Cmdline: strings.Repeat("x", maxCmdlineEventChars*3)})
	var got string
	for _, ev := range pw.pending {
		got = ev.Cmdline
	}
	if len(got) > maxCmdlineEventChars+16 {
		t.Fatalf("command line kept at %d chars, want it truncated near %d", len(got), maxCmdlineEventChars)
	}
	if !strings.Contains(got, "…") {
		t.Error("a truncated command line should say it was truncated")
	}
}
