//go:build darwin

package agent

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// On macOS, root is not the top of the privilege ladder — TCC sits above
// it. A root process still cannot read Mail, Messages, Safari history, the
// TCC database itself, or most of ~/Library without Full Disk Access, and
// nothing in the API tells you that you lack it: the read simply returns
// "operation not permitted". So the agent measures it directly, by
// attempting the canonical protected read, and reports the gap.
//
// Full Disk Access can only be granted two ways: a human clicking it in
// System Settings, or a PPPC configuration profile pushed by MDM. The
// console serves that profile (see the deploy page) so the second route
// doesn't require writing XML by hand.

// tccDatabase is readable only by a process holding Full Disk Access. It is
// the standard probe for FDA precisely because nothing else grants it.
const tccDatabase = "/Library/Application Support/com.apple.TCC/TCC.db"

func collectPrivileges(ctx context.Context) (proto.PrivilegeInfo, error) {
	info := proto.PrivilegeInfo{
		UID:      os.Geteuid(),
		Elevated: os.Geteuid() == 0,
		Service:  "launchd",
	}
	if u, err := user.Current(); err == nil {
		info.Account = u.Username
	}

	info.FullDiskAccess = canReadTCC()
	info.SIPEnabled = sipEnabled(ctx)
	info.MDMEnrolled = mdmEnrolled(ctx)

	if !info.Elevated {
		info.Limitations = append(info.Limitations,
			"the agent is not running as root, so it cannot install software or manage services")
		info.Remedy = append(info.Remedy,
			"reinstall with sudo; the installer registers a LaunchDaemon, which runs as root")
	}
	if !info.FullDiskAccess {
		info.Limitations = append(info.Limitations,
			"no Full Disk Access, so parts of the filesystem stay unreadable even as root")
		// Which fix to offer depends on whether this Mac is enrolled:
		// Apple honours a TCC payload only from an MDM the machine is
		// enrolled in, so on an unenrolled Mac the profile is not an
		// option and pointing at it would waste the operator's time.
		if info.MDMEnrolled {
			info.Remedy = append(info.Remedy,
				"push the PPPC profile from Deploy Agents → Manual Install through this Mac's MDM")
		} else if exe, err := os.Executable(); err == nil && mdmEnrollURL(exe) != "" {
			// The URL itself is not repeated here: it usually carries the
			// MDM's enroll secret, and this report is stored and shown
			// more widely than Settings.
			info.Remedy = append(info.Remedy,
				"this Mac is not MDM-enrolled; enroll it with the page the agent opens at startup (Settings → macOS MDM enrollment) and the MDM grants it, or grant it by hand: System Settings → Privacy & Security → Full Disk Access")
		} else {
			info.Remedy = append(info.Remedy,
				"this Mac is not MDM-enrolled, so grant it by hand: System Settings → Privacy & Security → Full Disk Access → + → press Cmd+Shift+G and enter /opt/mustra-agent, then pick mustra-agent")
		}
	}

	info.FullRights = len(info.Limitations) == 0
	return info, nil
}

// canReadTCC opens the TCC database. Reading one byte is enough — the
// permission check happens at open, and reading the contents would be both
// pointless and invasive.
func canReadTCC() bool {
	f, err := os.Open(tccDatabase)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 1)
	_, err = f.Read(buf)
	return err == nil
}

// mdmEnrolled reports whether this Mac is enrolled in an MDM. It decides
// which remedy is worth offering, because Apple honours a PPPC payload only
// when it arrives from an MDM the machine is actually enrolled in — a
// hand-installed profile carrying one is ignored, by design.
func mdmEnrolled(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "/usr/bin/profiles", "status", "-type", "enrollment").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "MDM enrollment: Yes")
}

func sipEnabled(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "/usr/bin/csrutil", "status").Output()
	if err != nil {
		return true // csrutil missing or refusing: assume the safe answer
	}
	return !strings.Contains(strings.ToLower(string(out)), "disabled")
}
