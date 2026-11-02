package maintenance

import (
	"testing"
	"time"
)

func at(s string, loc *time.Location) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
	if err != nil {
		panic(err)
	}
	return t
}

func TestWindowOpenAndNext(t *testing.T) {
	la, _ := time.LoadLocation("America/Los_Angeles")
	// Weeknights 22:00-02:00 Pacific.
	w := Window{Weekdays: []int{1, 2, 3, 4, 5}, Start: "22:00", DurationMinutes: 240, Timezone: "America/Los_Angeles"}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		when string
		open bool
	}{
		{"2026-09-14 21:59", false}, // Monday, a minute early
		{"2026-09-14 22:00", true},
		{"2026-09-15 01:59", true},  // Tuesday small hours: the Monday window
		{"2026-09-15 02:00", false}, // over
		{"2026-09-19 22:30", false}, // Saturday is not listed
		{"2026-09-20 01:00", false}, // Sunday small hours: Saturday had no window
		{"2026-09-13 01:00", false}, // Sunday small hours: Saturday 2026-09-12 is not listed either
	}
	for _, c := range cases {
		if got := w.Open(at(c.when, la)); got != c.open {
			t.Errorf("%s open=%v, want %v", c.when, got, c.open)
		}
	}
	// Friday small hours: the Thursday window.
	if !w.Open(at("2026-09-18 00:30", la)) {
		t.Error("Friday 00:30 should be inside Thursday's window")
	}
	// Next open from Saturday morning is Monday 22:00.
	next, ok := w.NextOpen(at("2026-09-19 09:00", la))
	if !ok || next.In(la).Format("2006-01-02 15:04") != "2026-09-21 22:00" {
		t.Errorf("next open = %v %v, want Monday 22:00", next.In(la), ok)
	}
	// From inside a window, next open is the following start, not now.
	next, _ = w.NextOpen(at("2026-09-14 23:00", la))
	if next.In(la).Format("2006-01-02 15:04") != "2026-09-15 22:00" {
		t.Errorf("next open from inside = %v", next.In(la))
	}
}

func TestWindowEveryDayAndUTC(t *testing.T) {
	w := Window{Start: "03:00", DurationMinutes: 60}
	if !w.Open(time.Date(2026, 9, 14, 3, 30, 0, 0, time.UTC)) || w.Open(time.Date(2026, 9, 14, 4, 0, 0, 0, time.UTC)) {
		t.Error("an every-day UTC window misjudged its hour")
	}
	// The instant is compared in the window's zone, whatever zone it came in.
	ny, _ := time.LoadLocation("America/New_York")
	if !w.Open(time.Date(2026, 9, 13, 23, 30, 0, 0, ny)) { // 03:30 UTC
		t.Error("an instant expressed in another zone should still be judged in the window's zone")
	}
}

func TestWindowValidation(t *testing.T) {
	for _, bad := range []Window{
		{Start: "25:00", DurationMinutes: 60},
		{Start: "3pm", DurationMinutes: 60},
		{Start: "03:00", DurationMinutes: 1},
		{Start: "03:00", DurationMinutes: 60, Timezone: "Mars/Olympus"},
		{Start: "03:00", DurationMinutes: 60, Weekdays: []int{7}},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v should not validate", bad)
		}
	}
}

// A recurring window governs from the start of its date on; a one-time
// window governs from when it is saved and stops once its occurrence is
// over (issue #114).
func TestWindowInEffect(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	weekly := Window{Recurrence: Weekly, Weekdays: []int{2, 4}, Start: "22:00", DurationMinutes: 120, StartDate: "2026-11-03", Timezone: "America/New_York"}
	once := Window{Recurrence: Once, Start: "22:00", DurationMinutes: 180, StartDate: "2026-11-03", Timezone: "America/New_York"}
	undated := Window{Weekdays: []int{1}, Start: "22:00", DurationMinutes: 60}
	cases := []struct {
		name string
		w    Window
		when string
		want bool
	}{
		{"weekly before its date", weekly, "2026-10-20 09:00", false},
		{"weekly the evening before", weekly, "2026-11-02 23:59", false},
		{"weekly from midnight of its date", weekly, "2026-11-03 00:00", true},
		{"weekly a year on", weekly, "2027-11-03 12:00", true},
		{"once days before its date", once, "2026-10-20 12:00", true},
		{"once on its date, before it opens", once, "2026-11-03 09:00", true},
		{"once while open, past midnight", once, "2026-11-04 00:30", true},
		{"once as it closes", once, "2026-11-04 01:00", false},
		{"once a week later", once, "2026-11-10 12:00", false},
		{"no start date", undated, "2020-01-01 00:00", true},
	}
	for _, c := range cases {
		if got := c.w.InEffectIn(at(c.when, ny), ny); got != c.want {
			t.Errorf("%s (%s): in effect %v, want %v", c.name, c.when, got, c.want)
		}
	}
}
