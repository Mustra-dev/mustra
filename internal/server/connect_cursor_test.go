package server

import (
	"testing"
	"time"
)

func at(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A row started later in the same second as the cursor is exported, even
// when its stamp is longer than the cursor's: as strings, "14.5Z" sorts
// before "14Z" and "14.123Z" before "14.12Z" (#109).
func TestExportCursorTakesLaterRowInSameSecond(t *testing.T) {
	for _, c := range []struct{ cursor, row string }{
		{"2026-10-20T10:00:14Z", "2026-10-20T10:00:14.5Z"},
		{"2026-10-20T10:00:14.12Z", "2026-10-20T10:00:14.123Z"},
	} {
		cur := newExportCursor(c.cursor)
		if !cur.take(at(t, c.row)) {
			t.Errorf("cursor %s skipped the later row %s", c.cursor, c.row)
		}
	}
}

// A row at or before the cursor was exported by an earlier run.
func TestExportCursorSkipsExportedRows(t *testing.T) {
	cur := newExportCursor("2026-10-20T10:00:14.5Z")
	for _, row := range []string{"2026-10-20T10:00:14.5Z", "2026-10-20T10:00:14Z", "2026-10-20T10:00:13.9Z"} {
		if cur.take(at(t, row)) {
			t.Errorf("cursor 14.5Z took %s again", row)
		}
	}
}

// The cursor advances to the latest row taken, whatever order the rows
// come in, and never back to an earlier one.
func TestExportCursorAdvancesToLatestRow(t *testing.T) {
	cur := newExportCursor("2026-10-20T10:00:13Z")
	for _, row := range []string{"2026-10-20T10:00:14.5Z", "2026-10-20T10:00:14Z"} {
		cur.take(at(t, row))
	}
	if got := cur.String(); got != "2026-10-20T10:00:14.5Z" {
		t.Errorf("cursor %s, want 2026-10-20T10:00:14.5Z", got)
	}
}

// A run with nothing new keeps the stored cursor where it was.
func TestExportCursorWithNothingNewIsUnchanged(t *testing.T) {
	cur := newExportCursor("2026-10-20T10:00:14.120Z")
	cur.take(at(t, "2026-10-20T10:00:14Z"))
	if got := at(t, cur.String()); !got.Equal(at(t, "2026-10-20T10:00:14.12Z")) {
		t.Errorf("cursor %s, want the stored one", got)
	}
	if got := newExportCursor("").String(); got != "" {
		t.Errorf("an empty cursor became %q", got)
	}
}

// An export that has never run takes every row.
func TestExportCursorEmptyTakesEverything(t *testing.T) {
	cur := newExportCursor("")
	if !cur.take(at(t, "2001-01-01T00:00:00Z")) {
		t.Error("an empty cursor skipped a row")
	}
	if got := cur.String(); got != "2001-01-01T00:00:00Z" {
		t.Errorf("cursor %s, want the row's start", got)
	}
}
