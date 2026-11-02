package agent

import (
	"os"
	"testing"
	"time"
)

// The reported offset follows the named zone even when the process's own
// local time does not (no zoneinfo installed: Go falls back to UTC).
func TestHostZoneOffsetFollowsTheName(t *testing.T) {
	t.Setenv("TZ", "America/New_York")
	if os.Getenv("TZ") == "" {
		t.Skip("cannot set TZ")
	}
	name, offset := hostZone()
	if name != "America/New_York" {
		t.Skipf("zone not read from TZ on this platform: %q", name)
	}
	loc, _ := time.LoadLocation(name)
	if _, want := time.Now().In(loc).Zone(); offset != want {
		t.Fatalf("offset %d, want %d", offset, want)
	}
}
