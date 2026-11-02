package server

import (
	"context"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// An endpoint-local window is read in the endpoint's reported zone, by name
// when it has one and by offset when it does not, and in the window's own
// zone for an endpoint that has not reported (an agent before 0.57.0).
func TestWindowLocationPerEndpoint(t *testing.T) {
	w := store.MaintenanceWindow{TimeBase: "endpoint", Timezone: "America/Los_Angeles", ObserveDST: true}
	off := -5 * 3600
	july := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	name := func(loc *time.Location) string { n, _ := july.In(loc).Zone(); return n }
	if got := windowLocation(w, store.AgentZone{Timezone: "America/New_York"}).String(); got != "America/New_York" {
		t.Errorf("named zone: %s", got)
	}
	if _, o := july.In(windowLocation(w, store.AgentZone{UTCOffsetSeconds: &off})).Zone(); o != off {
		t.Errorf("offset zone: %d", o)
	}
	if got := windowLocation(w, store.AgentZone{}).String(); got != "America/Los_Angeles" {
		t.Errorf("fallback: %s", got)
	}
	if got := windowLocation(w, store.AgentZone{Timezone: "Not/AZone", UTCOffsetSeconds: &off}); name(got) != "endpoint" {
		t.Errorf("an unknown name should fall through to the offset, got %s", got)
	}
	zoned := store.MaintenanceWindow{TimeBase: "zone", Timezone: "America/Los_Angeles", ObserveDST: false}
	if _, o := july.In(windowLocation(zoned, store.AgentZone{Timezone: "Asia/Tokyo"})).Zone(); o != -8*3600 {
		t.Errorf("a zone window ignores the endpoint and, without DST, stays on PST in July: %d", o)
	}
}

// A window restricts nothing before its effective date or after a
// one-time window is over; an endpoint no other window covers is then
// unrestricted (issue #114). The gate is primed, so no store is read.
func TestWindowCheckIgnoresWindowsNotInEffect(t *testing.T) {
	now := time.Date(2026, 10, 20, 15, 0, 0, 0, time.UTC) // a Tuesday
	future := store.MaintenanceWindow{ID: "mw-future", Name: "Web servers weeknight window", Enabled: true, AppliesTo: []string{"patch"},
		Recurrence: "weekly", Weekdays: []int{2, 4}, StartTime: "22:00", DurationMinutes: 120, StartDate: "2026-11-03",
		Timezone: "America/New_York", TimeBase: "zone", ObserveDST: true}
	over := store.MaintenanceWindow{ID: "mw-over", Name: "Cutover", Enabled: true, AppliesTo: []string{"patch"},
		Recurrence: "once", StartTime: "22:00", DurationMinutes: 180, StartDate: "2026-10-10", TimeBase: "zone", ObserveDST: true}
	current := store.MaintenanceWindow{ID: "mw-now", Name: "Weeknights", Enabled: true, AppliesTo: []string{"patch"},
		Recurrence: "weekly", Weekdays: []int{1, 2, 3, 4}, StartTime: "22:00", DurationMinutes: 360, TimeBase: "zone", ObserveDST: true}
	check := func(windows ...store.MaintenanceWindow) windowVerdict {
		s := &Server{}
		s.windows.at, s.windows.cacheTTL = time.Now(), time.Hour
		s.windows.windows = windows
		s.windows.members = map[string]map[string]bool{}
		for _, w := range windows {
			s.windows.members[w.ID] = nil // every endpoint
		}
		s.windows.agents = map[string]store.AgentZone{"agt-web": {OS: "linux"}}
		return s.windowCheck(context.Background(), "agt-web", "patch", now)
	}
	if v := check(future); !v.Allowed {
		t.Errorf("before its start date: held, %q", v.Reason)
	}
	if v := check(over); !v.Allowed {
		t.Errorf("a one-time window that is over: held, %q", v.Reason)
	}
	// A one-time window still to come holds its endpoints until it opens:
	// that is what scheduling one is for.
	upcoming := store.MaintenanceWindow{ID: "mw-sat", Name: "Saturday cutover", Enabled: true, AppliesTo: []string{"patch"},
		Recurrence: "once", StartTime: "22:00", DurationMinutes: 180, StartDate: "2026-10-24", TimeBase: "zone", ObserveDST: true}
	if v := check(upcoming); v.Allowed {
		t.Error("a one-time window still to come should hold its endpoints")
	} else if want := time.Date(2026, 10, 24, 22, 0, 0, 0, time.UTC); !v.NextOpen.Equal(want) {
		t.Errorf("next open %v, want %v", v.NextOpen, want)
	}
	// Still held by a window that is in effect, and only that one is named.
	v := check(future, over, current)
	if v.Allowed {
		t.Fatal("a window in effect and closed should hold the endpoint")
	}
	if want := "Waiting for maintenance window Weeknights; next opens Tue 2026-10-20 22:00 UTC"; v.Reason != want {
		t.Errorf("reason %q, want %q", v.Reason, want)
	}

	// A window that takes effect later but opens sooner is when the
	// endpoint will next be allowed.
	monthly := store.MaintenanceWindow{ID: "mw-monthly", Name: "Monthly", Enabled: true, AppliesTo: []string{"patch"},
		Recurrence: "monthly", MonthDay: 15, StartTime: "02:00", DurationMinutes: 60, TimeBase: "zone", ObserveDST: true}
	soon := store.MaintenanceWindow{ID: "mw-soon", Name: "From tomorrow", Enabled: true, AppliesTo: []string{"patch"},
		Recurrence: "daily", StartTime: "22:00", DurationMinutes: 60, StartDate: "2026-10-21", TimeBase: "zone", ObserveDST: true}
	v = check(monthly, soon)
	if v.Allowed {
		t.Fatal("the monthly window is in effect and closed")
	}
	if want := time.Date(2026, 10, 21, 22, 0, 0, 0, time.UTC); !v.NextOpen.Equal(want) {
		t.Errorf("next open %v, want %v", v.NextOpen, want)
	}
	if want := "Waiting for maintenance window Monthly or From tomorrow; next opens Wed 2026-10-21 22:00 UTC"; v.Reason != want {
		t.Errorf("reason %q, want %q", v.Reason, want)
	}
}
