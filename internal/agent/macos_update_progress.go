package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// A macOS update the MDM asked for runs inside softwareupdated with no
// progress in System Settings, and the MDM's own OSUpdateStatus answer can
// stay stuck on an old error while it downloads. softwareupdated logs its
// overall progress, so the agent reads the newest of those lines for the
// console: "Reported progress (inter): phase:PREPARING_UPDATE stalled:NO
// portionComplete:0.897795 estimatedTimeRemaining:600.000000 …".

type macUpdateProgress struct {
	Phase   string  `json:"phase"`             // DOWNLOADING_UPDATE, PREPARING_UPDATE, …
	Percent float64 `json:"percent"`           // overall, 0–100
	Stalled bool    `json:"stalled,omitempty"` // softwareupdated says so
	At      string  `json:"at,omitempty"`      // the log line's time
}

var macProgressRE = regexp.MustCompile(`Reported progress \(\w+\): phase:([A-Z_]+) stalled:(YES|NO) portionComplete:([0-9.]+)`)

func parseMacUpdateProgress(out string) (macUpdateProgress, bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		m := macProgressRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		frac, _ := strconv.ParseFloat(m[3], 64)
		p := macUpdateProgress{Phase: m[1], Stalled: m[2] == "YES", Percent: frac * 100}
		if f := strings.Fields(lines[i]); len(f) >= 2 {
			p.At = f[0] + " " + f[1]
		}
		return p, true
	}
	return macUpdateProgress{}, false
}

func macOSUpdateProgress(ctx context.Context) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("macOS only")
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "log", "show", "--last", "10m", "--style", "compact",
		"--predicate", `process == "softwareupdated" AND eventMessage CONTAINS "Reported progress"`).Output()
	if err != nil {
		return "", err
	}
	p, ok := parseMacUpdateProgress(string(out))
	if !ok {
		return "", nil // nothing in progress in the last ten minutes
	}
	b, err := json.Marshal(p)
	return string(b), err
}
