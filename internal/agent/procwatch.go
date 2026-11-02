package agent

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// Real-time process monitoring, endpoint half.
//
// The processes sensor is a snapshot on a timer. Anything that runs and
// exits between two collections never existed as far as the console is
// concerned, and "runs and exits quickly" describes most of what an
// attacker does: a curl piped to a shell, a base64-decoded one-liner, a
// scheduled task that fires and is gone. This is the half that sees those.
//
// How much it sees depends on the mechanism, and the mechanism differs by
// platform enough that the batch says which one produced it:
//
//	Linux   the kernel's process-events connector over netlink — every
//	        exec, including one that lives for two milliseconds.
//	other   a fast diff of the process table. Sees what was alive at a
//	        sample point, which means anything shorter-lived than the
//	        interval is invisible. That is a real limit, and the console
//	        says so rather than letting a quiet feed read as a quiet box.
//
// The same three bounds as file events apply, for the same reason: a build
// machine can start hundreds of processes a second, and an agent that
// reported every one faithfully would produce the flood that makes a
// security feed unreadable.

const (
	// procFlushInterval is how long events are gathered before publishing.
	procFlushInterval = 5 * time.Second
	// procPollInterval is how often the fallback samples the process table.
	// Short enough to catch most of what runs, long enough that sampling
	// does not become the busiest thing on the endpoint.
	procPollInterval = 5 * time.Second
	// maxProcEventsPerBatch is how many *distinct* commands one flush may
	// carry. Distinct rather than raw because identical invocations collapse
	// first: on a real hypervisor a minute of execs is 1530 events but only
	// 169 distinct commands, so this cap bites on genuine variety — which
	// is the thing worth capping — rather than on repetition.
	maxProcEventsPerBatch = 150
	// maxCmdlineEventChars keeps one pathological command line from
	// dominating a batch. Longer than the sensor's, because the interesting
	// part of an encoded payload is often at the end.
	maxCmdlineEventChars = 1024
)

type procWatcher struct {
	agent  *Agent
	source string

	events chan proto.ProcessEvent
	// Keyed by (name, command line, user) so identical invocations collapse
	// into one row with a count instead of hundreds of rows.
	pending      map[string]*proto.ProcessEvent
	order        []string
	suppressed   int
	unidentified int
	since        time.Time

	// Events the producers could not hand over because the channel was
	// full, and events the kernel dropped before we read them. Atomic
	// because the producers are not the flusher: readConnector and pollLoop
	// both run off the main loop. Counted rather than dropped silently —
	// a batch reporting Suppressed: 0 for a window that lost events is a
	// quiet-looking lie, which is the one thing this feed must not tell.
	dropped atomic.Int64

	// Guards source, which the fallback path rewrites at runtime.
	sourceMu sync.Mutex
}

// runProcessWatch starts the watcher and blocks until ctx is done. Like the
// file watcher, an unavailable mechanism is not fatal: the processes sensor
// still runs, and losing the real-time half quietly beats losing the agent.
func (a *Agent) runProcessWatch(ctx context.Context) {
	pw := &procWatcher{
		agent: a,
		// Buffered generously: an exec storm must be absorbed and counted
		// here rather than blocking the reader that is draining the kernel's
		// socket, which is how events get dropped by the kernel instead.
		events:  make(chan proto.ProcessEvent, 4096),
		pending: map[string]*proto.ProcessEvent{},
		since:   time.Now().UTC(),
	}

	pw.source = "poll"
	stop := func() {}

	// Called if the kernel feed degrades after starting. A nil error means
	// the kernel dropped events but the feed lives; anything else means it
	// is gone and sampling has to take over, because an endpoint silently
	// reporting nothing is worse than one openly reporting less.
	var fallbackOnce sync.Once
	degraded := func(err error) {
		if err == nil {
			pw.dropped.Add(1)
			return
		}
		fallbackOnce.Do(func() {
			a.logger.Error("kernel process feed failed; falling back to sampling",
				"error", err, "interval", procPollInterval)
			pw.sourceMu.Lock()
			pw.source = "poll"
			pw.sourceMu.Unlock()
			go pw.pollLoop(context.WithoutCancel(ctx))
		})
	}

	if started, cancel, err := startProcessConnector(ctx, pw.events, degraded); err == nil {
		pw.source, stop = "netlink", cancel
		_ = started
		a.logger.Info("real-time process monitoring started", "source", "netlink")
	} else {
		a.logger.Info("real-time process monitoring started", "source", "poll",
			"reason", err.Error(), "interval", procPollInterval)
		go pw.pollLoop(ctx)
	}
	defer stop()

	flush := time.NewTicker(procFlushInterval)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-pw.events:
			pw.record(ev)
		case <-flush.C:
			pw.flush(ctx)
		}
	}
}

func (pw *procWatcher) record(ev proto.ProcessEvent) {
	// The kernel told us something exec'd, but it was gone before /proc
	// could say what. That is a fact worth carrying as a number; it is not
	// a row, because a row with no name is a row nobody can act on.
	if ev.Name == "" {
		pw.unidentified++
		return
	}
	ev.Cmdline = truncate(redactCmdline(ev.Cmdline), maxCmdlineEventChars)
	key := ev.Name + "\x00" + ev.Cmdline + "\x00" + ev.Username
	if existing, ok := pw.pending[key]; ok {
		// Same command again. Count it and move the timestamp forward to
		// the most recent one, which is the answer to "is this still
		// happening".
		existing.Count++
		existing.At = ev.At
		return
	}
	if len(pw.pending) >= maxProcEventsPerBatch {
		pw.suppressed++
		return
	}
	ev.Count = 1
	pw.pending[key] = &ev
	pw.order = append(pw.order, key)
}

func (pw *procWatcher) flush(ctx context.Context) {
	if len(pw.pending) == 0 && pw.suppressed == 0 && pw.unidentified == 0 && pw.dropped.Load() == 0 {
		now := time.Now().UTC()
		pw.sourceMu.Lock()
		complete := pw.source != "poll"
		pw.sourceMu.Unlock()
		pw.agent.saveDeployHistory("process_events", pw.since, now, nil, complete)
		pw.since = now
		return
	}
	events := make([]proto.ProcessEvent, 0, len(pw.pending))
	for _, key := range pw.order {
		if ev := pw.pending[key]; ev != nil {
			events = append(events, *ev)
		}
	}
	pw.sourceMu.Lock()
	source := pw.source
	pw.sourceMu.Unlock()
	batch := proto.ProcessEventBatch{
		AgentID: pw.agent.agentID, Events: events,
		// Everything the window lost, however it was lost: past the batch
		// cap, or before it could even be handed to this loop.
		Suppressed:   pw.suppressed + int(pw.dropped.Swap(0)),
		Unidentified: pw.unidentified, Source: source,
		Since: pw.since, Until: time.Now().UTC(),
	}
	pw.pending = map[string]*proto.ProcessEvent{}
	pw.order = nil
	pw.suppressed = 0
	pw.unidentified = 0
	pw.since = batch.Until

	pw.agent.saveDeployHistory("process_events", batch.Since, batch.Until, batch.Events, batch.Suppressed == 0 && batch.Unidentified == 0 && batch.Source != "poll")
	sort.Slice(batch.Events, func(i, j int) bool { return batch.Events[i].At.Before(batch.Events[j].At) })
	payload, err := json.Marshal(batch)
	if err != nil {
		pw.agent.logger.Error("marshal process event batch failed", "error", err)
		return
	}
	if err := pw.agent.pub.Publish(ctx, bnats.AgentProcessEvents(pw.agent.agentID), payload); err != nil {
		pw.agent.logger.Error("publish process events failed", "error", err)
	}
}

// pollLoop is the portable fallback: sample the process table and report
// PIDs that were not there last time.
//
// The PID-reuse problem that makes killing dangerous is harmless here — a
// recycled PID is genuinely a new process, which is exactly what this
// reports. What it cannot do is see anything that started and finished
// inside one interval.
func (pw *procWatcher) pollLoop(ctx context.Context) {
	known := map[int32]bool{}
	self := int32(os.Getpid())

	// The first sample establishes what was already running. Reporting the
	// whole process table as "just started" on every agent restart would
	// bury the real starts under it.
	if pids, err := process.PidsWithContext(ctx); err == nil {
		for _, pid := range pids {
			known[pid] = true
		}
	}

	ticker := time.NewTicker(procPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		pids, err := process.PidsWithContext(ctx)
		if err != nil {
			continue
		}
		seen := make(map[int32]bool, len(pids))
		for _, pid := range pids {
			seen[pid] = true
			if known[pid] || pid == self {
				continue
			}
			if ev, ok := describeProcess(ctx, pid); ok {
				select {
				case pw.events <- ev:
				default:
					pw.dropped.Add(1)
				}
			}
		}
		known = seen
	}
}

// describeProcess reads what it can about a process that has just started.
//
// Everything past the PID is best-effort on purpose. A process that exits
// within milliseconds is gone before its command line can be read, and an
// event saying "something called sh started" is worth far more than no
// event at all — which is what strict error handling would produce for
// precisely the short-lived processes worth seeing.
func describeProcess(ctx context.Context, pid int32) (proto.ProcessEvent, bool) {
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return proto.ProcessEvent{}, false
	}
	ev := proto.ProcessEvent{PID: pid, At: time.Now().UTC()}
	ev.Name, _ = p.NameWithContext(ctx)
	if ev.Name == "" {
		return proto.ProcessEvent{}, false
	}
	if ppid, err := p.PpidWithContext(ctx); err == nil {
		ev.PPID = ppid
	}
	if cmd, err := p.CmdlineWithContext(ctx); err == nil {
		ev.Cmdline = cmd
	}
	if user, err := p.UsernameWithContext(ctx); err == nil {
		ev.Username = user
	}
	return ev, true
}
