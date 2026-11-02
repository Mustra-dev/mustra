//go:build linux

package agent

import (
	"context"
	"os"
	"os/user"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Linux is the straightforward case: root is genuinely the top, with no
// TCC-style layer above it and no present-but-disabled privileges to
// enable. The one thing worth measuring is whether the agent is actually
// running as root — and, in a container, whether its capability set has
// been trimmed, which is invisible from the uid alone.
func collectPrivileges(ctx context.Context) (proto.PrivilegeInfo, error) {
	info := proto.PrivilegeInfo{
		UID:      os.Geteuid(),
		Elevated: os.Geteuid() == 0,
		Service:  "systemd",
	}
	if u, err := user.Current(); err == nil {
		info.Account = u.Username
	}
	info.CapEffective = effectiveCaps()

	if !info.Elevated {
		info.Limitations = append(info.Limitations,
			"the agent is not running as root, so it cannot install packages or manage services")
		info.Remedy = append(info.Remedy,
			"reinstall with sudo; the installer registers a systemd unit, which runs as root")
	} else if info.CapEffective != "" && info.CapEffective != "0000003fffffffff" && !strings.HasPrefix(info.CapEffective, "000001ff") {
		// A trimmed capability set is normal and often deliberate inside a
		// container, so this is reported rather than treated as a failure —
		// it explains why an otherwise-root agent gets EPERM.
		info.Limitations = append(info.Limitations,
			"running as root but with a reduced capability set (likely an unprivileged container)")
		info.Remedy = append(info.Remedy,
			"expected inside an unprivileged LXC or a hardened container; grant the needed capabilities if an action fails")
	}

	info.FullRights = len(info.Limitations) == 0
	return info, nil
}

// effectiveCaps reads CapEff from /proc/self/status — the effective
// capability mask, as a hex string.
func effectiveCaps() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "CapEff:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
