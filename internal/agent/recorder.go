package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// The recorder: registry, network, DNS and logon events, endpoint half.
//
// The third real-time feed beside file and process events, and the one
// that turns "what ran" into "what it did": a process that connected out
// to port 4444, resolved a twenty-character hostname, wrote a Run key, or
// followed forty failed logons from one address. Each kind has its own
// producer per platform (recorder_*.go); this file is the shared loop —
// collapse identical events inside a flush, cap the batch, count what was
// dropped, and publish — which is the same discipline the other two feeds
// keep, for the same reason: an unbounded feed is worse than none.
//
// What each platform can see, honestly:
//
//	network   every platform — a diff of the connection table every few
//	          seconds. A connection shorter than the interval is missed.
//	logon     Linux from the journal (sshd, sudo, login); Windows from the
//	          Security log (4624/4625/4648); macOS from `last`.
//	registry  Windows only: a diff of the persistence keys every few
//	          seconds (Run, RunOnce, Winlogon, IFEO, services, tasks, LSA
//	          packages, Defender exclusions), plus Sysmon 12/13/14 when
//	          Sysmon is installed. Linux and macOS have no registry.
//	dns       Windows only: new entries in the DNS client cache, plus Sysmon
//	          22 when present. Linux and macOS report none — seeing queries
//	          there needs eBPF or a packet tap the agent does not carry.
//
// The batch carries which mechanism produced each kind, so an empty feed
// is read correctly.
const (
	recorderFlushInterval = 5 * time.Second
	recorderPollInterval  = 5 * time.Second
	maxRecorderPerBatch   = 200
)

type recorder struct {
	agent      *Agent
	events     chan proto.RecorderEvent
	pending    map[string]*proto.RecorderEvent
	order      []string
	suppressed int
	// suppressedByKind splits suppressed by event kind, so the server can
	// book a DNS or registry storm under its own kind (#123).
	suppressedByKind map[string]int
	since            time.Time
	sourcesMu        sync.Mutex
	sources          map[string]string
	procNames        sync.Map // pid -> name, for the network producer
}

func (a *Agent) runRecorder(ctx context.Context) {
	r := &recorder{
		agent:   a,
		events:  make(chan proto.RecorderEvent, 4096),
		pending: map[string]*proto.RecorderEvent{},
		since:   time.Now().UTC(),
		sources: map[string]string{"network": "netpoll", "logon": "none", "registry": "none", "dns": "none"},
	}
	go r.networkLoop(ctx)
	startRecorderPlatform(ctx, r)
	a.logger.Info("recorder started", "sources", r.sourceSnapshot())
	flush := time.NewTicker(recorderFlushInterval)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-r.events:
			r.record(ev)
		case <-flush.C:
			r.flush(ctx)
		}
	}
}

func (r *recorder) setSource(kind, source string) {
	r.sourcesMu.Lock()
	r.sources[kind] = source
	r.sourcesMu.Unlock()
}

func (r *recorder) sourceSnapshot() map[string]string {
	r.sourcesMu.Lock()
	defer r.sourcesMu.Unlock()
	out := map[string]string{}
	for k, v := range r.sources {
		out[k] = v
	}
	return out
}

// emit hands an event to the loop without ever blocking a producer: a
// storm is counted as suppressed rather than stalling the poller that
// would otherwise see the next one.
func (r *recorder) emit(ev proto.RecorderEvent) {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	select {
	case r.events <- ev:
	default:
		r.countSuppressed(ev.Kind)
	}
}

// countSuppressed counts one event dropped, under the lock emit's
// producers share with flush.
func (r *recorder) countSuppressed(kind string) {
	r.sourcesMu.Lock()
	defer r.sourcesMu.Unlock()
	r.suppressed++
	if r.suppressedByKind == nil {
		r.suppressedByKind = map[string]int{}
	}
	r.suppressedByKind[kind]++
}

func (r *recorder) record(ev proto.RecorderEvent) {
	key := ev.Kind + "\x00" + ev.Summary + "\x00" + ev.Process + "\x00" + ev.User
	if existing, ok := r.pending[key]; ok {
		existing.Count++
		existing.At = ev.At
		return
	}
	if len(r.pending) >= maxRecorderPerBatch {
		r.countSuppressed(ev.Kind)
		return
	}
	ev.Count = 1
	r.pending[key] = &ev
	r.order = append(r.order, key)
}

func (r *recorder) flush(ctx context.Context) {
	r.sourcesMu.Lock()
	suppressed, byKind := r.suppressed, r.suppressedByKind
	r.suppressed, r.suppressedByKind = 0, nil
	r.sourcesMu.Unlock()
	if len(r.pending) == 0 && suppressed == 0 {
		r.since = time.Now().UTC()
		return
	}
	events := make([]proto.RecorderEvent, 0, len(r.pending))
	for _, key := range r.order {
		if ev := r.pending[key]; ev != nil {
			events = append(events, *ev)
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })
	batch := proto.RecorderBatch{AgentID: r.agent.agentID, Events: events, Suppressed: suppressed, SuppressedByKind: byKind, Sources: r.sourceSnapshot(), Since: r.since, Until: time.Now().UTC()}
	r.pending = map[string]*proto.RecorderEvent{}
	r.order = nil
	r.since = batch.Until
	payload, err := json.Marshal(batch)
	if err != nil {
		r.agent.logger.Error("marshal recorder batch failed", "error", err)
		return
	}
	if err := r.agent.pub.Publish(ctx, bnats.AgentRecorderEvents(r.agent.agentID), payload); err != nil {
		r.agent.logger.Error("publish recorder events failed", "error", err)
	}
}

// processName resolves a PID to a name, cached, because the same few
// processes own nearly every connection on a box.
func (r *recorder) processName(pid int32) string {
	if pid <= 0 {
		return ""
	}
	if v, ok := r.procNames.Load(pid); ok {
		return v.(string)
	}
	name := ""
	if p, err := process.NewProcess(pid); err == nil {
		name, _ = p.Name()
	}
	r.procNames.Store(pid, name)
	return name
}

// networkLoop diffs the connection table. New established or connecting
// outbound flows become "connect"; new listeners become "listen".
// Loopback and link-local peers are skipped: a box talking to itself is
// not a signal, and reporting it would bury the ones that are.
func (r *recorder) networkLoop(ctx context.Context) {
	self := int32(os.Getpid())
	known := map[string]bool{}
	first := true
	tick := time.NewTicker(recorderPollInterval)
	defer tick.Stop()
	for {
		conns, err := gnet.ConnectionsWithContext(ctx, "inet")
		if err != nil {
			r.setSource("network", "none")
		} else {
			seen := map[string]bool{}
			for _, c := range conns {
				proto_ := "tcp"
				if c.Type == 2 { // SOCK_DGRAM
					proto_ = "udp"
				}
				op := ""
				switch {
				case c.Status == "LISTEN":
					op = "listen"
				case c.Status == "ESTABLISHED" || c.Status == "SYN_SENT" || (proto_ == "udp" && c.Raddr.Port != 0):
					op = "connect"
				default:
					continue
				}
				if op == "connect" && (c.Raddr.IP == "" || isLocalPeer(c.Raddr.IP)) {
					continue
				}
				key := fmt.Sprintf("%s|%s|%s:%d|%s:%d|%d", op, proto_, c.Laddr.IP, c.Laddr.Port, c.Raddr.IP, c.Raddr.Port, c.Pid)
				seen[key] = true
				if first || known[key] || c.Pid == self {
					continue
				}
				name := r.processName(c.Pid)
				ev := proto.RecorderEvent{Kind: "network", Op: op, PID: c.Pid, Process: name, Protocol: proto_,
					LocalIP: c.Laddr.IP, LocalPort: int(c.Laddr.Port), RemoteIP: c.Raddr.IP, RemotePort: int(c.Raddr.Port)}
				if op == "listen" {
					ev.Summary = fmt.Sprintf("%s listening on %s:%d (%s)", orUnknown(name), c.Laddr.IP, c.Laddr.Port, proto_)
				} else {
					ev.Summary = fmt.Sprintf("%s -> %s:%d (%s)", orUnknown(name), c.Raddr.IP, c.Raddr.Port, proto_)
				}
				r.emit(ev)
			}
			known = seen
			first = false
			// Names go stale when PIDs are reused; a table that only grows
			// would eventually mislabel. Cleared on the same rhythm as the
			// connection set.
			if len(seen) == 0 {
				r.procNames = sync.Map{}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func isLocalPeer(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "fe80:") || ip == "0.0.0.0" || ip == "::"
}

func orUnknown(name string) string {
	if strings.TrimSpace(name) == "" {
		return "(unknown process)"
	}
	return name
}
