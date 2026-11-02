//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"strings"
)

// ianaZone reads the zone the way the C library does: $TZ, then the
// /etc/localtime symlink (…/zoneinfo/America/Los_Angeles on Linux and
// macOS), then Debian's /etc/timezone.
func ianaZone() string {
	if tz := strings.TrimPrefix(strings.TrimSpace(os.Getenv("TZ")), ":"); tz != "" && !strings.HasPrefix(tz, "/") {
		return tz
	}
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		target = filepath.ToSlash(target)
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			return strings.TrimPrefix(target[i+len("zoneinfo/"):], "posix/")
		}
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}
