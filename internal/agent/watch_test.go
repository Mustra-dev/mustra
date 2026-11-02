package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/mustra-dev/mustra/internal/proto"
)

func newTestWatcher() *fileWatcher {
	return &fileWatcher{pending: map[string]proto.FileEvent{}, since: time.Now().UTC()}
}

// Writing a file produces several events. Reporting the change four times
// teaches the reader to skim, so one path is one row per flush.
func TestRecordCoalescesPerPath(t *testing.T) {
	fw := newTestWatcher()
	for _, op := range []fsnotify.Op{fsnotify.Create, fsnotify.Write, fsnotify.Write, fsnotify.Chmod} {
		fw.record(fsnotify.Event{Name: "/etc/cron.d/job", Op: op})
	}
	if len(fw.pending) != 1 {
		t.Fatalf("got %d pending events, want 1", len(fw.pending))
	}
	// The last operation wins: it describes where the file ended up.
	if fw.pending["/etc/cron.d/job"].Op != "chmod" {
		t.Errorf("op = %q, want the last one seen", fw.pending["/etc/cron.d/job"].Op)
	}
}

// The failure this guards against is a package install touching hundreds of
// files under /etc and drowning the feed. Past the cap the events are
// counted, not sent — and the count is kept so the window is never
// reported as quiet.
func TestRecordCapsABurstAndCountsTheRest(t *testing.T) {
	fw := newTestWatcher()
	const burst = maxEventsPerBatch + 50
	for i := 0; i < burst; i++ {
		fw.record(fsnotify.Event{Name: filepath.Join("/etc", "f", string(rune('a'+i%26)), string(rune(i))), Op: fsnotify.Create})
	}
	if len(fw.pending) > maxEventsPerBatch {
		t.Fatalf("pending = %d, want no more than %d", len(fw.pending), maxEventsPerBatch)
	}
	if fw.suppressed == 0 {
		t.Fatal("events past the cap were dropped silently; the count must survive")
	}
	if len(fw.pending)+fw.suppressed != burst {
		t.Errorf("%d kept + %d suppressed = %d, want every event accounted for (%d)",
			len(fw.pending), fw.suppressed, len(fw.pending)+fw.suppressed, burst)
	}
}

// A path already pending must not be turned away by the cap: it costs no
// new slot, and refusing it would freeze the batch's view of that file at
// its first operation.
func TestRecordStillUpdatesAKnownPathAtTheCap(t *testing.T) {
	fw := newTestWatcher()
	for i := 0; i < maxEventsPerBatch; i++ {
		fw.record(fsnotify.Event{Name: filepath.Join("/etc", string(rune(i))), Op: fsnotify.Create})
	}
	known := filepath.Join("/etc", string(rune(0)))
	fw.record(fsnotify.Event{Name: known, Op: fsnotify.Remove})
	if fw.pending[known].Op != "remove" {
		t.Errorf("op = %q, want remove — a known path must still update at the cap", fw.pending[known].Op)
	}
	if fw.suppressed != 0 {
		t.Errorf("updating a known path counted as suppression (%d)", fw.suppressed)
	}
}

func TestOpNameIgnoresWhatItCannotName(t *testing.T) {
	if got := opName(0); got != "" {
		t.Errorf("an empty op should be ignored, got %q", got)
	}
	for op, want := range map[fsnotify.Op]string{
		fsnotify.Create: "create", fsnotify.Write: "write",
		fsnotify.Remove: "remove", fsnotify.Rename: "rename", fsnotify.Chmod: "chmod",
	} {
		if got := opName(op); got != want {
			t.Errorf("opName(%v) = %q, want %q", op, got, want)
		}
	}
}

// The watch set must be the integrity set, not the filesystem: watching /
// would bury the one interesting write under build artefacts and log
// rotation. It must also stay inside the descriptor budget.
func TestWatchDirsIsBoundedAndReal(t *testing.T) {
	dirs := watchDirs()
	if len(dirs) > maxWatchDirs {
		t.Fatalf("watching %d directories, over the %d cap", len(dirs), maxWatchDirs)
	}
	for _, d := range dirs {
		// Stat rather than Lstat: the watcher opens the path, which follows
		// symlinks, and on macOS /etc is one (to /private/etc).
		info, err := os.Stat(d)
		if err != nil {
			t.Errorf("watch list contains %q, which does not exist", d)
			continue
		}
		if !info.IsDir() {
			t.Errorf("watch list contains %q, which is not a directory", d)
		}
	}
	if runtime.GOOS == "linux" && len(dirs) == 0 {
		t.Error("no directories to watch on a Linux box; the integrity set should have matched something")
	}
}

// A watched *file* is watched through its parent directory, because that is
// how a replacement (write to temp, rename over) is seen at all.
func TestWatchDirsWatchesAFilesParent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("checks a Linux integrity path")
	}
	if _, err := os.Lstat("/etc/passwd"); err != nil {
		t.Skip("no /etc/passwd here")
	}
	for _, d := range watchDirs() {
		if d == "/etc" {
			return
		}
	}
	t.Error("/etc is not watched, so a replacement of /etc/passwd would be missed")
}

// The macOS incident in one test.
//
// fsnotify emulates a directory watch on kqueue by opening a descriptor per
// file inside it, and a launchd job gets 256 by default. Budgeting by
// directory — which is all this code did — measured the wrong thing, and the
// agent went quiet ninety seconds after starting. The Linux budget is
// unaffected, because an inotify watch does not consume a process
// descriptor at all.
func TestWatchBudgetCountsWhatThePlatformActuallySpends(t *testing.T) {
	root := t.TempDir()
	// Two directories, one of them far more expensive than the other on a
	// kqueue platform and identical to it on Linux.
	cheap := filepath.Join(root, "a-cheap")
	pricey := filepath.Join(root, "b-pricey")
	for _, d := range []string{cheap, pricey} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < maxWatchFilesKqueue*2; i++ {
		if err := os.WriteFile(filepath.Join(pricey, fmt.Sprintf("f%d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := countEntries(pricey); got <= maxWatchFilesKqueue {
		t.Fatalf("the expensive directory costs %d, which is not over the budget the test needs", got)
	}
	if got := countEntries(cheap); got != 1 {
		t.Errorf("an empty directory costs %d, want 1 (itself)", got)
	}
	// A directory that cannot be read must not read as free — that would
	// let an unreadable tree past a budget it should be charged against.
	if got := countEntries(filepath.Join(root, "does-not-exist")); got < 1 {
		t.Errorf("an unreadable directory costs %d, want at least 1", got)
	}
}
