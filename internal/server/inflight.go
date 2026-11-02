package server

import "sync"

// One run at a time, per thing that runs.
//
// Enforce policies and playbooks can both be started two ways — a schedule
// and a person clicking Run now — and nothing stopped those overlapping.
// Two concurrent passes of the same playbook means the same endpoint gets
// the same reboot step twice, or the same package installed by two
// processes at once; two concurrent Enforce passes run the same remediation
// command simultaneously on the same machine.
//
// Neither is hypothetical: a scheduled Enforce pass may take fifteen
// minutes per endpoint against a half-hour interval, so the window for a
// person to click into an in-flight run is most of the time.
//
// The guard is per ID rather than global. Two *different* playbooks running
// at once is fine and often the point; the same one twice is not.
type inflight struct {
	mu     sync.Mutex
	active map[string]bool
}

func newInflight() *inflight {
	return &inflight{active: map[string]bool{}}
}

// claim reserves an id, returning false if it is already running. The
// caller must release it when the run ends — including when it fails, which
// is why every caller does so in a defer.
func (i *inflight) claim(id string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.active[id] {
		return false
	}
	i.active[id] = true
	return true
}

func (i *inflight) release(id string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.active, id)
}

// running reports whether an id is currently in flight, for a console that
// wants to say so rather than offering a button that will be refused.
func (i *inflight) running(id string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.active[id]
}
