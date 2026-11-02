//go:build linux

package agent

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// inLXC reports whether the agent runs inside an LXC container. There,
// lxcfs serves /proc/stat from the host's counters (the "guest" column,
// time spent running VMs, shows up in a container that has none), so
// gopsutil's CPU percentage is the hypervisor's load rather than the
// container's. Docker is left alone: an agent in an app container (the
// HAOS add-on) is there to report on the host, and its cgroup is not the
// machine.
var inLXC = func() bool {
	if b, err := os.ReadFile("/run/systemd/container"); err == nil {
		return strings.TrimSpace(string(b)) == "lxc"
	}
	b, err := os.ReadFile("/proc/1/environ")
	if err != nil {
		return false
	}
	for _, kv := range strings.Split(string(b), "\x00") {
		if kv == "container=lxc" || kv == "container=lxc-libvirt" {
			return true
		}
	}
	return false
}()

// lastCgroupCPU is the previous cgroup reading, so each sample covers the
// whole interval since the one before rather than a short window.
var lastCgroupCPU struct {
	sync.Mutex
	usage uint64
	at    time.Time
}

// containerCPUPercent measures the container's own CPU use from its cgroup
// v2 counter, as a percentage of the CPUs it may use. ok is false outside
// LXC or without a readable counter, and the caller falls back to
// /proc/stat.
//
// The counter is cumulative, so after the first call a sample spans the
// full interval since the previous one. A short window would not do: the
// agent's own 5-second pollers start with the 15-second sampler and land
// inside every window, so a container idling at 8% read ~40% — the agent
// measuring itself. The first call, with nothing to compare against,
// measures over window.
func containerCPUPercent(ctx context.Context, window time.Duration) (pct float64, ok bool) {
	if !inLXC {
		return 0, false
	}
	lastCgroupCPU.Lock()
	defer lastCgroupCPU.Unlock()
	before, start := lastCgroupCPU.usage, lastCgroupCPU.at
	if start.IsZero() {
		var err error
		if before, err = cgroupCPUUsage(); err != nil {
			return 0, false
		}
		start = time.Now()
		select {
		case <-ctx.Done():
			return 0, false
		case <-time.After(window):
		}
	}
	after, err := cgroupCPUUsage()
	now := time.Now()
	if err != nil {
		return 0, false
	}
	lastCgroupCPU.usage, lastCgroupCPU.at = after, now
	elapsed := now.Sub(start)
	cpus := cgroupCPULimit()
	if after < before || elapsed <= 0 || cpus <= 0 {
		return 0, false
	}
	pct = float64(after-before) / (float64(elapsed.Microseconds()) * cpus) * 100
	if pct > 100 {
		pct = 100
	}
	return pct, true
}

// cgroupCPUUsage is the container's total CPU time so far, in microseconds.
func cgroupCPUUsage() (uint64, error) {
	b, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, found := strings.CutPrefix(line, "usage_usec "); found {
			return strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, os.ErrNotExist
}

// cgroupCPULimit is how many CPUs the container may use: its cpuset (the
// affinity runtime.NumCPU reports, which is how Proxmox applies "cores"),
// lowered by a cpu.max quota when one is set (Proxmox "cpulimit").
func cgroupCPULimit() float64 {
	cpus := float64(runtime.NumCPU())
	if b, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 && f[0] != "max" {
			quota, e1 := strconv.ParseFloat(f[0], 64)
			period, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && period > 0 && quota/period < cpus {
				cpus = quota / period
			}
		}
	}
	return cpus
}
