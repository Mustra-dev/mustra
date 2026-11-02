// Package maintenance decides when a maintenance window is open.
//
// A window is a start time and a duration that recur: once, every N days,
// on chosen weekdays every N weeks, or monthly on a date or on the Nth (or
// last) weekday -- "the second Tuesday" is how most patch windows are
// written. It is evaluated in a time zone: the window's own, or, for a
// window in endpoint local time, the endpoint's (the caller passes it).
// A window may run past midnight and may last several days; Open looks
// back far enough to see an occurrence that started earlier.
package maintenance

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Recurrence kinds. "" is the original form: Weekdays every week, or every
// day when Weekdays is empty, with no start date.
const (
	Once    = "once"
	Daily   = "daily"
	Weekly  = "weekly"
	Monthly = "monthly"
)

// MaxDuration bounds one occurrence. Long enough for a weekend window,
// short enough that Open's look-back stays cheap.
const MaxDuration = 7 * 24 * 60

type Window struct {
	Recurrence string
	// Interval repeats every N days, weeks or months; 0 means 1.
	Interval int
	Weekdays []int  // 0 Sunday .. 6 Saturday; weekly (and legacy) only
	Start    string // "HH:MM"
	// StartDate ("YYYY-MM-DD") is when the window takes effect and the
	// anchor its interval counts from; the date of a "once" window.
	StartDate       string
	DurationMinutes int
	// Monthly: MonthWeek 1-4 picks the Nth MonthWeekday, 5 the last one;
	// otherwise MonthDay (1-31, the month's last day when it is shorter).
	MonthDay     int
	MonthWeek    int
	MonthWeekday int
	Timezone     string // IANA name; "" is UTC
	// NoDST pins the zone to its standard offset all year ("Observe
	// Daylight Saving Time" unticked).
	NoDST bool
}

func (w Window) Validate() error {
	if _, _, err := w.startClock(); err != nil {
		return err
	}
	if w.DurationMinutes < 5 || w.DurationMinutes > MaxDuration {
		return fmt.Errorf("a window must last between 5 minutes and 7 days")
	}
	if _, err := w.location(); err != nil {
		return fmt.Errorf("unknown time zone %q", w.Timezone)
	}
	for _, d := range w.Weekdays {
		if d < 0 || d > 6 {
			return fmt.Errorf("weekday %d is not between 0 (Sunday) and 6 (Saturday)", d)
		}
	}
	if w.Interval < 0 || w.Interval > 366 {
		return fmt.Errorf("repeat interval must be between 1 and 366")
	}
	switch w.Recurrence {
	case "", Daily, Weekly:
	case Once:
		if w.StartDate == "" {
			return fmt.Errorf("a one-time window needs a date")
		}
	case Monthly:
		if w.MonthWeek < 0 || w.MonthWeek > 5 || w.MonthWeekday < 0 || w.MonthWeekday > 6 {
			return fmt.Errorf("monthly windows need a week (1st–4th or last) and a weekday")
		}
		if w.MonthWeek == 0 && (w.MonthDay < 1 || w.MonthDay > 31) {
			return fmt.Errorf("monthly windows need a day of the month (1–31) or a weekday")
		}
	default:
		return fmt.Errorf("unknown recurrence %q", w.Recurrence)
	}
	if w.StartDate != "" {
		if _, err := time.Parse("2006-01-02", w.StartDate); err != nil {
			return fmt.Errorf("start date must be YYYY-MM-DD, got %q", w.StartDate)
		}
	}
	return nil
}

func (w Window) location() (*time.Location, error) {
	if strings.TrimSpace(w.Timezone) == "" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		return nil, err
	}
	if w.NoDST {
		return StandardTime(loc), nil
	}
	return loc, nil
}

// StandardTime is loc pinned to its standard (non-daylight) offset.
func StandardTime(loc *time.Location) *time.Location {
	year := time.Now().Year()
	for _, m := range []time.Month{time.January, time.July} {
		t := time.Date(year, m, 1, 12, 0, 0, 0, loc)
		if !t.IsDST() {
			name, off := t.Zone()
			return time.FixedZone(name, off)
		}
	}
	return loc
}

func (w Window) startClock() (h, m int, err error) {
	parts := strings.Split(strings.TrimSpace(w.Start), ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("start must be HH:MM, got %q", w.Start)
	}
	h, e1 := strconv.Atoi(parts[0])
	m, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("start must be HH:MM, got %q", w.Start)
	}
	return h, m, nil
}

func (w Window) interval() int {
	if w.Interval < 1 {
		return 1
	}
	return w.Interval
}

// civil is a date with no time zone, so day and month arithmetic never
// trips over a daylight-saving change.
func civil(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func daysBetween(a, b time.Time) int { return int(b.Sub(a).Hours() / 24) }

// occursOn says whether an occurrence starts on day (a civil date).
func (w Window) occursOn(day time.Time) bool {
	var anchor time.Time
	if w.StartDate != "" {
		a, err := time.Parse("2006-01-02", w.StartDate)
		if err != nil {
			return false
		}
		anchor = a
		if day.Before(anchor) {
			return false
		}
	}
	n := w.interval()
	switch w.Recurrence {
	case Once:
		return day.Equal(anchor)
	case Daily:
		return anchor.IsZero() || daysBetween(anchor, day)%n == 0
	case Monthly:
		if !anchor.IsZero() {
			months := (day.Year()-anchor.Year())*12 + int(day.Month()-anchor.Month())
			if months%n != 0 {
				return false
			}
		}
		if w.MonthWeek > 0 {
			if int(day.Weekday()) != w.MonthWeekday {
				return false
			}
			if w.MonthWeek == 5 {
				return day.AddDate(0, 0, 7).Month() != day.Month()
			}
			return (day.Day()-1)/7+1 == w.MonthWeek
		}
		last := civil(day.Year(), day.Month()+1, 0).Day()
		want := w.MonthDay
		if want > last {
			want = last
		}
		return day.Day() == want
	default: // Weekly and the original form
		if len(w.Weekdays) > 0 && !containsInt(w.Weekdays, int(day.Weekday())) {
			return false
		}
		if anchor.IsZero() || n == 1 {
			return true
		}
		week := func(t time.Time) time.Time { return t.AddDate(0, 0, -int(t.Weekday())) }
		return (daysBetween(week(anchor), week(day))/7)%n == 0
	}
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// startOn is the occurrence starting on day's date, in loc.
func (w Window) startOn(day time.Time, h, m int, loc *time.Location) time.Time {
	return time.Date(day.Year(), day.Month(), day.Day(), h, m, 0, 0, loc)
}

// Open reports whether the window is open at at, in its own time zone.
func (w Window) Open(at time.Time) bool {
	loc, err := w.location()
	if err != nil {
		return false
	}
	return w.OpenIn(at, loc)
}

// OpenIn is Open evaluated in loc: the endpoint's zone, for a window in
// endpoint local time.
func (w Window) OpenIn(at time.Time, loc *time.Location) bool {
	h, m, err := w.startClock()
	if err != nil {
		return false
	}
	local := at.In(loc)
	dur := time.Duration(w.DurationMinutes) * time.Minute
	back := w.DurationMinutes/(24*60) + 1
	today := civil(local.Year(), local.Month(), local.Day())
	for i := 0; i <= back; i++ {
		day := today.AddDate(0, 0, -i)
		if !w.occursOn(day) {
			continue
		}
		start := w.startOn(day, h, m, loc)
		if !local.Before(start) && local.Before(start.Add(dur)) {
			return true
		}
	}
	return false
}

// NextOpen is the next time the window opens at or after at, in its own
// time zone.
func (w Window) NextOpen(at time.Time) (time.Time, bool) {
	loc, err := w.location()
	if err != nil {
		return time.Time{}, false
	}
	return w.NextOpenIn(at, loc)
}

// NextOpenIn is NextOpen evaluated in loc. It looks a little over a year
// ahead, which covers a monthly window every 12 months.
func (w Window) NextOpenIn(at time.Time, loc *time.Location) (time.Time, bool) {
	h, m, err := w.startClock()
	if err != nil {
		return time.Time{}, false
	}
	local := at.In(loc)
	today := civil(local.Year(), local.Month(), local.Day())
	for i := 0; i <= 400; i++ {
		day := today.AddDate(0, 0, i)
		if !w.occursOn(day) {
			continue
		}
		if start := w.startOn(day, h, m, loc); !start.Before(local) {
			return start, true
		}
	}
	return time.Time{}, false
}

// InEffectIn says whether the window governs at, evaluated in loc. A
// recurring window governs from the start of its StartDate (its effective
// date) on; one with no StartDate always does. A one-time window governs
// from when it is saved until its occurrence ends: its date is the
// occurrence, and holding its endpoints until then is what it is for
// ("patch these on Saturday night"). One that is not in effect restricts
// nothing; otherwise a window before its effective date, or a one-time
// window that is over, would hold its endpoints closed with no opening to
// wait for.
func (w Window) InEffectIn(at time.Time, loc *time.Location) bool {
	if w.StartDate == "" {
		return true
	}
	d, err := time.Parse("2006-01-02", w.StartDate)
	if err != nil {
		return true // Validate refuses it; held, as before
	}
	local := at.In(loc)
	if w.Recurrence != Once {
		return !local.Before(time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc))
	}
	h, m, err := w.startClock()
	if err != nil {
		return true
	}
	end := w.startOn(d, h, m, loc).Add(time.Duration(w.DurationMinutes) * time.Minute)
	return local.Before(end)
}
