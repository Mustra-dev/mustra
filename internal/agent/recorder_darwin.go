//go:build darwin

package agent

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// macOS: logons from `last`, which is cheap and needs no entitlement; the
// unified log would be richer but `log show` costs seconds per call. No
// registry; DNS would need a packet tap.
func startRecorderPlatform(ctx context.Context, r *recorder) {
	r.setSource("logon", "last")
	go r.lastLogons(ctx)
}

func (r *recorder) lastLogons(ctx context.Context) {
	known := map[string]bool{}
	first := true
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := exec.CommandContext(cctx, "last", "-20").Output()
		cancel()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				f := strings.Fields(line)
				if len(f) < 4 || f[0] == "reboot" || f[0] == "shutdown" || f[0] == "wtmp" {
					continue
				}
				if known[line] {
					continue
				}
				known[line] = true
				if first {
					continue
				}
				src := "console"
				if len(f) > 2 && strings.Contains(f[2], ".") {
					src = f[2]
				}
				r.emit(proto.RecorderEvent{Kind: "logon", Op: "success", User: f[0], LogonType: f[1], Source: src, Summary: "logon " + f[0] + " on " + f[1] + " from " + src})
			}
			first = false
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
