package agent

import (
	"context"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Endpoint performance, the right way round: sample often, keep the
// samples *on the endpoint*, and send a summary.
//
// The alternative — shipping a sample every 15 seconds to the server —
// would put ~5,700 rows per endpoint per day into Postgres to answer a
// question nobody asks in that form. What people actually ask is "is this
// machine healthy, and how often has it been unhealthy lately", which a
// counted summary answers exactly.
//
// The ring buffer is in memory and so resets when the agent restarts.
// That is a deliberate trade for v1: it costs nothing, needs no schema on
// the endpoint, and an agent that just restarted genuinely has no history
// to report. The sample count travels with the summary so a short window
// is visible as a short window rather than passing for a quiet one.

const (
	perfSampleEvery = 15 * time.Second
	perfWindow      = 24 * time.Hour
	perfRingSize    = int(perfWindow / perfSampleEvery) // 5,760 samples ≈ 140 KB

	// Thresholds at which a sample counts as an event. Chosen to fire on
	// sustained pressure rather than the momentary spikes every machine
	// has: a build, a backup, or a page-cache flush should not make a host
	// look unhealthy.
	cpuEventThreshold  = 90.0
	memEventThreshold  = 90.0
	diskEventThreshold = 90.0

	// How long each CPU reading measures over. Long enough to be a real
	// measurement, short enough that it costs nothing against a 15-second
	// cadence.
	cpuSampleWindow = 200 * time.Millisecond

	// Performance reports on its own, faster cadence than the other
	// sensors. The payload is twenty numbers rather than a list of every
	// installed package, so it costs almost nothing to send — and a health
	// dashboard fifteen minutes stale is a health dashboard nobody trusts.
	perfReportEvery = 60 * time.Second
)

type perfSample struct {
	at      time.Time
	cpu     float64
	memPct  float64
	diskPct float64
}

type perfRing struct {
	mu      sync.Mutex
	samples []perfSample
	next    int
	filled  bool
}

var perfBuffer = &perfRing{samples: make([]perfSample, perfRingSize)}

func (r *perfRing) add(s perfSample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samples[r.next] = s
	r.next = (r.next + 1) % len(r.samples)
	if r.next == 0 {
		r.filled = true
	}
}

// snapshot summarizes the window: current values, peaks, and how many
// samples crossed each threshold.
func (r *perfRing) snapshot() proto.PerformanceInfo {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := r.next
	if r.filled {
		count = len(r.samples)
	}
	info := proto.PerformanceInfo{Samples: count, WindowHours: perfWindow.Hours()}
	if count == 0 {
		return info
	}

	cutoff := time.Now().Add(-perfWindow)
	var sumCPU, sumMem float64
	var n int
	for i, s := range r.samples {
		if i >= count && !r.filled {
			break
		}
		if s.at.IsZero() || s.at.Before(cutoff) {
			continue
		}
		n++
		sumCPU += s.cpu
		sumMem += s.memPct
		if s.cpu > info.CPUPeak {
			info.CPUPeak = s.cpu
		}
		if s.memPct > info.MemoryPeak {
			info.MemoryPeak = s.memPct
		}
		if s.diskPct > info.DiskPeak {
			info.DiskPeak = s.diskPct
		}
		if s.cpu >= cpuEventThreshold {
			info.CPUEvents++
		}
		if s.memPct >= memEventThreshold {
			info.MemoryEvents++
		}
		if s.diskPct >= diskEventThreshold {
			info.DiskEvents++
		}
	}
	if n > 0 {
		info.CPUAverage = sumCPU / float64(n)
		info.MemoryAverage = sumMem / float64(n)
	}
	info.Samples = n

	// The most recent sample is "now", which is what a dashboard shows.
	last := r.next - 1
	if last < 0 {
		last = len(r.samples) - 1
	}
	if s := r.samples[last]; !s.at.IsZero() {
		info.CPUCurrent = s.cpu
		info.MemoryCurrent = s.memPct
		info.DiskCurrent = s.diskPct
	}
	return info
}

// runPerformanceSampler fills the ring. Separate from the sensor loop
// because sampling and reporting happen at very different rates — every
// 15 seconds versus every 15 minutes — and conflating them would mean
// either a coarse history or a chatty agent.
func (a *Agent) runPerformanceSampler(ctx context.Context) {
	// Let the first tick provide the first sample. Sampling at t=0 would
	// measure the agent's own startup burst rather than the machine.
	ticker := time.NewTicker(perfSampleEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			perfBuffer.add(takeSample(ctx))
		}
	}
}

func takeSample(ctx context.Context) perfSample {
	s := perfSample{at: time.Now()}
	// A short blocking interval rather than 0.
	//
	// Interval 0 means "since the previous call", which needs a previous
	// call to exist. On the very first sample there is none, so gopsutil
	// compares against a zero baseline and reports ~100% — which is
	// exactly what shipped: four endpoints reporting 100% CPU while
	// actually sitting at 20%. Measuring over a real window is correct
	// from the first call and costs 200ms once every 15 seconds.
	if pct, ok := containerCPUPercent(ctx, cpuSampleWindow); ok {
		s.cpu = pct
	} else if pct, err := cpu.PercentWithContext(ctx, cpuSampleWindow, false); err == nil && len(pct) > 0 {
		s.cpu = pct[0]
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil && vm != nil {
		s.memPct = vm.UsedPercent
	}
	// The fullest filesystem is the one that will break something, so the
	// max across mounts is the number worth keeping.
	if d := haosDataDisk(ctx); d != nil {
		s.diskPct = d.UsedPercent
	} else if parts, err := disk.PartitionsWithContext(ctx, false); err == nil {
		for _, p := range parts {
			if !countsTowardDiskPressure(p) {
				continue
			}
			if usage, err := disk.UsageWithContext(ctx, p.Mountpoint); err == nil && usage != nil {
				if usage.UsedPercent > s.diskPct {
					s.diskPct = usage.UsedPercent
				}
			}
		}
	}
	return s
}

// countsTowardDiskPressure leaves out mounts that always read as full and
// can never fill up: /dev on macOS (devfs, a few KB reported 100% used),
// snap and other squashfs images, mounted ISOs and DMGs. Any one of them
// made "the fullest filesystem" 100% and the disk score 0. Read-only mounts
// go too: nothing can write to them, so their fullness breaks nothing.
func countsTowardDiskPressure(p disk.PartitionStat) bool {
	switch p.Fstype {
	case "devfs", "squashfs", "iso9660", "cd9660", "udf", "autofs", "nullfs":
		return false
	}
	for _, o := range p.Opts {
		if o == "ro" || o == "rdonly" {
			return false
		}
	}
	return true
}

func collectPerformance(ctx context.Context) ([]proto.PerformanceInfo, error) {
	// Deliberately no cold-start sample here. An earlier version took one
	// if the ring was empty, which sampled the agent at the single worst
	// instant in its life: t=0, with every sensor's first collection
	// running at once — hashing thousands of integrity files and every
	// certificate on the box. That produced a genuine 100% reading of the
	// agent's own startup, which the console then showed as "current CPU"
	// until the next report. An empty window reported honestly as empty is
	// better than a real number that means something else.
	return []proto.PerformanceInfo{perfBuffer.snapshot()}, nil
}
