//go:build !linux

package agent

import (
	"context"
	"time"
)

// containerCPUPercent is Linux-only (LXC); elsewhere /proc-style host
// counters are the machine's own.
func containerCPUPercent(context.Context, time.Duration) (float64, bool) { return 0, false }
