package maintenance

import (
	"testing"
	"time"
)

// "Every month on the second Tuesday from 6:30 PM to 1:00 AM": the window
// most patch schedules are written as, crossing midnight.
func TestMonthlyNthWeekdayAcrossMidnight(t *testing.T) {
	la, _ := time.LoadLocation("America/Los_Angeles")
	w := Window{Recurrence: Monthly, MonthWeek: 2, MonthWeekday: int(time.Tuesday), Start: "18:30", DurationMinutes: 390, Timezone: "America/Los_Angeles", StartDate: "2021-05-11"}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		when string
		open bool
	}{
		{"2026-11-10 18:29", false}, // second Tuesday of November, a minute early
		{"2026-11-10 18:30", true},
		{"2026-11-11 00:59", true}, // Wednesday small hours: still Tuesday's window
		{"2026-11-11 01:00", false},
		{"2026-11-03 19:00", false}, // first Tuesday
		{"2026-11-17 19:00", false}, // third Tuesday
	} {
		if got := w.Open(at(c.when, la)); got != c.open {
			t.Errorf("%s open=%v, want %v", c.when, got, c.open)
		}
	}
	next, ok := w.NextOpen(at("2026-10-15 12:00", la))
	if !ok || !next.Equal(at("2026-11-10 18:30", la)) {
		t.Errorf("next = %v, want 2026-11-10 18:30 PT", next)
	}
}

func TestMonthlyLastWeekdayAndShortMonths(t *testing.T) {
	last := Window{Recurrence: Monthly, MonthWeek: 5, MonthWeekday: int(time.Friday), Start: "22:00", DurationMinutes: 120}
	if !last.Open(at("2026-10-30 22:30", time.UTC)) || last.Open(at("2026-10-23 22:30", time.UTC)) {
		t.Error("last Friday of October 2026 is the 30th, not the 23rd")
	}
	day31 := Window{Recurrence: Monthly, MonthDay: 31, Start: "01:00", DurationMinutes: 60}
	if !day31.Open(at("2026-02-28 01:30", time.UTC)) {
		t.Error("the 31st falls back to February's last day")
	}
	if day31.Open(at("2026-03-28 01:30", time.UTC)) {
		t.Error("March has a 31st; the 28th is not it")
	}
}

func TestIntervalsAndStartDate(t *testing.T) {
	// Every other week, Tuesdays, from 2026-10-06.
	w := Window{Recurrence: Weekly, Interval: 2, Weekdays: []int{2}, StartDate: "2026-10-06", Start: "20:00", DurationMinutes: 60}
	for _, c := range []struct {
		when string
		open bool
	}{
		{"2026-09-29 20:30", false}, // before it takes effect
		{"2026-10-06 20:30", true},
		{"2026-10-13 20:30", false}, // the off week
		{"2026-10-20 20:30", true},
	} {
		if got := w.Open(at(c.when, time.UTC)); got != c.open {
			t.Errorf("%s open=%v, want %v", c.when, got, c.open)
		}
	}
	every3 := Window{Recurrence: Daily, Interval: 3, StartDate: "2026-10-01", Start: "02:00", DurationMinutes: 60}
	if !every3.Open(at("2026-10-04 02:30", time.UTC)) || every3.Open(at("2026-10-05 02:30", time.UTC)) {
		t.Error("every 3 days from the 1st is the 4th, not the 5th")
	}
}

func TestOnceSpanningDays(t *testing.T) {
	w := Window{Recurrence: Once, StartDate: "2026-06-19", Start: "18:00", DurationMinutes: 7 * 60}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	if !w.Open(at("2026-06-20 00:30", time.UTC)) || w.Open(at("2026-06-20 01:00", time.UTC)) || w.Open(at("2027-06-19 19:00", time.UTC)) {
		t.Error("a one-time window opens once")
	}
	weekend := Window{Recurrence: Once, StartDate: "2026-06-19", Start: "18:00", DurationMinutes: 60 * 60}
	if !weekend.Open(at("2026-06-21 12:00", time.UTC)) {
		t.Error("a 60-hour window is open on the Sunday")
	}
	if (Window{Recurrence: Once, Start: "18:00", DurationMinutes: 60}).Validate() == nil {
		t.Error("a one-time window without a date was accepted")
	}
}

// Unticking "Observe Daylight Saving Time" keeps the window on standard
// time: 18:30 PST is 19:30 PDT in summer.
func TestNoDSTStaysOnStandardTime(t *testing.T) {
	la, _ := time.LoadLocation("America/Los_Angeles")
	w := Window{Recurrence: Daily, Start: "18:30", DurationMinutes: 30, Timezone: "America/Los_Angeles", NoDST: true}
	if w.Open(at("2026-07-15 18:45", la)) || !w.Open(at("2026-07-15 19:45", la)) {
		t.Error("summer: the window should follow PST, an hour later on the wall clock")
	}
	if !w.Open(at("2026-01-15 18:45", la)) {
		t.Error("winter: PST is the wall clock")
	}
}

// A window in endpoint local time is the same rule read in each
// endpoint's own zone.
func TestOpenInEndpointZone(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	la, _ := time.LoadLocation("America/Los_Angeles")
	w := Window{Recurrence: Daily, Start: "22:00", DurationMinutes: 60}
	moment := at("2026-10-15 22:30", ny) // 19:30 in Los Angeles
	if !w.OpenIn(moment, ny) || w.OpenIn(moment, la) {
		t.Error("22:30 in New York is open there and not yet in Los Angeles")
	}
	next, ok := w.NextOpenIn(moment, la)
	if !ok || !next.Equal(at("2026-10-15 22:00", la)) {
		t.Errorf("Los Angeles next = %v", next)
	}
}
