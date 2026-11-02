package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// Real-time file monitoring, endpoint half.
//
// The hash baseline in integrity.go answers "has this changed since last
// time". This answers "it changed just now", which is a different and
// complementary question: the baseline cannot miss a change made while the
// agent was down, and this cannot wait fifteen minutes to notice a dropper.
// Both run; neither replaces the other.
//
// Three things bound it, because an unbounded event feed is worse than no
// event feed:
//
//	The watch set is the integrity set, not the filesystem. Watching /
//	would produce a firehose of build artefacts and log rotations in which
//	the one interesting write is invisible.
//
//	Events are coalesced per path per flush. Writing a file produces
//	several inotify events; reporting a change four times teaches the
//	reader to skim.
//
//	Past a cap the events are counted rather than sent, and the count is
//	published. A package install touches hundreds of files under /etc in a
//	second, and the honest report of that is "412 more, suppressed", not
//	412 rows nobody reads.

const (
	// watchFlushInterval is how long events are gathered before publishing.
	// Long enough to coalesce an editor's write-rename-chmod dance into one
	// row; short enough that "real-time" still means something.
	watchFlushInterval = 5 * time.Second
	// maxWatchDirs caps inotify watch descriptors. The kernel's per-user
	// limit is finite and shared with everything else on the box, so an
	// agent that quietly consumed thousands would break the machine's other
	// software rather than its own.
	maxWatchDirs = 512
	// maxWatchFilesKqueue is the budget that matters on macOS and the BSDs,
	// where the cost is completely different from Linux.
	//
	// inotify watches a directory with one descriptor from a kernel pool.
	// kqueue has no such thing: fsnotify emulates directory watching by
	// opening a file descriptor for every *file* inside it. So a watch set
	// that costs six descriptors on Linux costs several hundred on a Mac —
	// /Library/LaunchDaemons alone is often more than a hundred plists —
	// and a launchd job's default descriptor limit is 256.
	//
	// The agent that hit this went quiet ninety seconds after starting.
	// Budgeting by directory, as this code originally did on every
	// platform, measures the wrong thing entirely.
	maxWatchFilesKqueue = 160
	// maxWatchDepth stops a deep tree under a watched root from expanding
	// into a watch per directory.
	maxWatchDepth = 6
	// maxEventsPerBatch is how many events one flush may carry in full.
	maxEventsPerBatch = 200
	// rewatchInterval re-scans for directories created since the last scan.
	// inotify watches an inode, not a name, so a directory created after
	// start is not watched until something adds it.
	rewatchInterval = 10 * time.Minute
	// integrityRepublishGap throttles the hash re-collection a burst of
	// events triggers. Without it, a package install would kick off a
	// full re-hash every five seconds for the length of the install.
	integrityRepublishGap = 2 * time.Minute
)

type fileWatcher struct {
	agent   *Agent
	watcher *fsnotify.Watcher

	mu         sync.Mutex
	pending    map[string]proto.FileEvent
	suppressed int
	since      time.Time

	lastIntegrityRepublish time.Time

	// How many directories are under watch, as counted by the last
	// rewatch. Cached because the flush used to recompute it by walking
	// every integrity root again — a full re-walk of /etc/ssh,
	// /etc/systemd/system and the rest every five seconds, precisely while
	// a package install was generating the events that triggered it.
	watching int
}

// runFileWatch starts the watcher and blocks until ctx is done. A platform
// or a kernel that will not give us a watcher is not fatal: the hash
// baseline still runs, and losing the real-time half quietly is much better
// than losing the agent.
func (a *Agent) runFileWatch(ctx context.Context) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		a.logger.Warn("real-time file monitoring unavailable; the hash baseline still runs", "error", err)
		return
	}
	defer w.Close()

	fw := &fileWatcher{
		agent: a, watcher: w,
		pending: map[string]proto.FileEvent{},
		since:   time.Now().UTC(),
	}
	a.logger.Info("real-time file monitoring started", "directories", fw.rewatch())

	flush := time.NewTicker(watchFlushInterval)
	defer flush.Stop()
	rescan := time.NewTicker(rewatchInterval)
	defer rescan.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			fw.record(ev)
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			// Overflow is the interesting one: the kernel dropped events
			// because we did not read them fast enough, which means the
			// batch we are about to publish is incomplete.
			a.logger.Warn("file watch error", "error", err)
			fw.mu.Lock()
			fw.suppressed++
			fw.mu.Unlock()
		case <-flush.C:
			fw.flush(ctx)
		case <-rescan.C:
			fw.rewatch()
		case <-a.watchRefresh:
			// A new watch set from the server: add its directories now.
			a.logger.Info("integrity watch set changed; re-scanning", "directories", fw.rewatch())
		}
	}
}

// watchDirs is the set of directories to watch: every watched directory in
// the integrity set, plus the parent of every watched file. inotify reports
// on a directory's entries, so watching a file's parent is how you learn
// that the file was replaced — which is exactly how most of them change.
func watchDirs() []string {
	seen := map[string]bool{}
	var out []string
	// On kqueue platforms every file in a watched directory costs a
	// descriptor, so the budget is counted in files rather than
	// directories. On Linux this stays zero and only maxWatchDirs applies.
	budget := 0
	if kqueueWatches {
		budget = maxWatchFilesKqueue
	}
	spent := 0

	add := func(p string) {
		if len(out) >= maxWatchDirs || seen[p] {
			return
		}
		if budget > 0 {
			cost := countEntries(p)
			// Always take the first directory, even an over-budget one:
			// watching part of the most important path beats watching
			// nothing because it happened to be listed first.
			if spent > 0 && spent+cost > budget {
				return
			}
			spent += cost
		}
		seen[p] = true
		out = append(out, p)
	}

	for _, root := range append(integrityPaths(), extraWatchPaths()...) {
		info, err := os.Lstat(root)
		if err != nil {
			continue // a path this OS does not have is not an error
		}
		if !info.IsDir() {
			add(filepath.Dir(root))
			continue
		}
		add(root)
		rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if len(out) >= maxWatchDirs {
				return filepath.SkipAll
			}
			if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth > maxWatchDepth {
				return filepath.SkipDir
			}
			add(path)
			return nil
		})
	}
	sort.Strings(out)
	return out
}

// countEntries is how many descriptors watching this directory will cost on
// a kqueue platform: one per entry, plus one for the directory itself.
func countEntries(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 1
	}
	return len(entries) + 1
}

// rewatch adds any directory not already watched and returns the total.
// Adding one that is already watched is a no-op in fsnotify, so this is
// cheap enough to run on a timer.
func (fw *fileWatcher) rewatch() int {
	dirs := watchDirs()
	added := 0
	for _, d := range dirs {
		if err := fw.watcher.Add(d); err != nil {
			// Running out of descriptors is not ordinary and must not be
			// swallowed: on a kqueue platform it means the watcher is about
			// to starve the rest of the agent — its NATS reconnect, its
			// sensor reads — of the descriptors they need. Stop adding and
			// say so, loudly, rather than taking the agent down quietly.
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
				fw.agent.logger.Error("file monitoring stopped adding watches: out of file descriptors",
					"watching", added, "wanted", len(dirs), "path", d)
				break
			}
			// A directory that vanished between the scan and the add, or one
			// we cannot read, is ordinary. Logging each would be noise.
			continue
		}
		added++
	}
	fw.mu.Lock()
	fw.watching = added
	fw.mu.Unlock()
	return added
}

func (fw *fileWatcher) record(ev fsnotify.Event) {
	op := opName(ev.Op)
	if op == "" {
		return
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	// Coalesce per path. The last operation wins, which is the one that
	// describes where the file ended up — a write followed by a chmod is
	// reported as a chmod on a file that is also newly written, and the
	// hash sweep this triggers settles what it now contains.
	if _, exists := fw.pending[ev.Name]; !exists && len(fw.pending) >= maxEventsPerBatch {
		fw.suppressed++
		return
	}
	fw.pending[ev.Name] = proto.FileEvent{Path: ev.Name, Op: op, At: time.Now().UTC()}
}

func opName(op fsnotify.Op) string {
	switch {
	case op.Has(fsnotify.Create):
		return "create"
	case op.Has(fsnotify.Remove):
		return "remove"
	case op.Has(fsnotify.Rename):
		return "rename"
	case op.Has(fsnotify.Write):
		return "write"
	case op.Has(fsnotify.Chmod):
		return "chmod"
	default:
		return ""
	}
}

func (fw *fileWatcher) flush(ctx context.Context) {
	fw.mu.Lock()
	if len(fw.pending) == 0 && fw.suppressed == 0 {
		now := time.Now().UTC()
		fw.agent.saveDeployHistory("file_events", fw.since, now, nil, fw.watching > 0, fw.watcher.WatchList())
		fw.since = now
		fw.mu.Unlock()
		return
	}
	events := make([]proto.FileEvent, 0, len(fw.pending))
	for _, e := range fw.pending {
		events = append(events, e)
	}
	watching := fw.watching
	batch := proto.FileEventBatch{
		AgentID: fw.agent.agentID, Events: events,
		Suppressed: fw.suppressed, Since: fw.since, Until: time.Now().UTC(),
	}
	fw.pending = map[string]proto.FileEvent{}
	fw.suppressed = 0
	fw.since = batch.Until
	fw.mu.Unlock()

	sort.Slice(batch.Events, func(i, j int) bool { return batch.Events[i].Path < batch.Events[j].Path })
	batch.Watching = watching
	fw.agent.saveDeployHistory("file_events", batch.Since, batch.Until, batch.Events, batch.Suppressed == 0 && batch.Watching > 0, fw.watcher.WatchList())

	payload, err := json.Marshal(batch)
	if err != nil {
		fw.agent.logger.Error("marshal file event batch failed", "error", err)
		return
	}
	if err := fw.agent.pub.Publish(ctx, bnats.AgentFileEvents(fw.agent.agentID), payload); err != nil {
		fw.agent.logger.Error("publish file events failed", "error", err)
		return
	}

	// The point of noticing in real time is not the event row: it is that
	// the hash sweep can now happen *now* rather than at the next interval.
	// This is what turns file integrity monitoring from a thing that tells
	// you about yesterday into one that tells you about this minute — and
	// the server's diff, notification and IOC matching all come along for
	// free because they already run on that snapshot.
	if time.Since(fw.lastIntegrityRepublish) < integrityRepublishGap {
		return
	}
	fw.lastIntegrityRepublish = time.Now()
	go fw.agent.collectAndPublishSensor(context.WithoutCancel(ctx), proto.SensorIntegrity,
		func(ctx context.Context) (any, error) { return collectIntegrity(ctx) })
}
