package server

import (
	"strings"
	"testing"
	"time"
)

func sampleRows() []map[string]any {
	return []map[string]any{
		{"hostname": "dc01", "state": "fail", "severity": "high"},
		{"hostname": "dc02", "state": "pass", "severity": "high"},
		{"hostname": "web01", "state": "fail", "severity": "low"},
		{"hostname": "web02", "state": "unknown", "severity": ""},
	}
}

func TestFilterRowsContains(t *testing.T) {
	got := filterRows(sampleRows(), "state", "fail")
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
}

// "Fail" and "fail" being different answers is nobody's intent.
func TestFilterRowsIsCaseInsensitive(t *testing.T) {
	if got := filterRows(sampleRows(), "state", "FAIL"); len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
}

func TestFilterRowsNegation(t *testing.T) {
	got := filterRows(sampleRows(), "state", "!fail")
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (pass and unknown)", len(got))
	}
	for _, r := range got {
		if r["state"] == "fail" {
			t.Errorf("a negated filter kept a matching row: %v", r)
		}
	}
}

func TestFilterRowsWithoutAFilterKeepsEverything(t *testing.T) {
	if got := filterRows(sampleRows(), "", "fail"); len(got) != 4 {
		t.Errorf("a blank column should not filter, got %d", len(got))
	}
	if got := filterRows(sampleRows(), "state", ""); len(got) != 4 {
		t.Errorf("a blank value should not filter, got %d", len(got))
	}
}

func TestAggregateCountsAndSorts(t *testing.T) {
	got := aggregate(sampleRows(), "state")
	if len(got) != 3 {
		t.Fatalf("got %d buckets, want 3", len(got))
	}
	if got[0].Label != "fail" || got[0].Count != 2 {
		t.Errorf("biggest bucket should come first, got %+v", got[0])
	}
	if got[0].Share != 50 {
		t.Errorf("share = %v, want 50", got[0].Share)
	}
}

// "How many endpoints have no site" is a real question, and usually an
// unwelcome answer — so a blank must be a bucket, not a silent drop.
func TestAggregateNamesTheBlanks(t *testing.T) {
	got := aggregate(sampleRows(), "severity")
	var found bool
	total := 0
	for _, a := range got {
		total += a.Count
		if a.Label == "(not set)" {
			found = true
		}
	}
	if !found {
		t.Error("a blank value was not reported as its own bucket")
	}
	if total != 4 {
		t.Errorf("buckets total %d, want every row counted (4)", total)
	}
}

// A column nothing has must not silently look like every row agreeing.
func TestAggregateOnAMissingColumn(t *testing.T) {
	got := aggregate(sampleRows(), "nope")
	if len(got) != 1 || got[0].Label != "(not set)" || got[0].Count != 4 {
		t.Fatalf("got %+v, want one (not set) bucket of 4", got)
	}
}

func TestSectionLimitClamps(t *testing.T) {
	if got := sectionLimit(reportSection{}); got != defaultSectionLimit {
		t.Errorf("default = %d", got)
	}
	if got := sectionLimit(reportSection{Limit: 10}); got != 10 {
		t.Errorf("explicit = %d", got)
	}
	if got := sectionLimit(reportSection{Limit: 100000}); got != maxSectionLimit {
		t.Errorf("a report is meant to be read; got %d", got)
	}
}

func TestSafeFilename(t *testing.T) {
	at := time.Date(2026, 9, 1, 7, 0, 0, 0, time.UTC)
	got := safeFilename("Weekly fleet health / Q3", at)
	if strings.ContainsAny(got, `/\ `) {
		t.Errorf("filename %q still contains path or space characters", got)
	}
	if !strings.HasSuffix(got, "-20260901.html") {
		t.Errorf("filename %q should carry the date it describes", got)
	}
	if got := safeFilename("///", at); !strings.HasPrefix(got, "report-") {
		t.Errorf("a name with nothing usable left should fall back, got %q", got)
	}
}

// A hostname containing markup must not become markup in the document —
// this is data from endpoints, rendered into a file people open.
func TestRenderedSectionEscapesData(t *testing.T) {
	rows := []map[string]any{{"hostname": `<script>alert(1)</script>`}}
	agg := aggregate(rows, "hostname")
	doc := reportDocument("t", `<td>`+esc(agg[0].Label)+`</td>`)
	if strings.Contains(doc, "<script>alert") {
		t.Fatal("row data reached the document unescaped")
	}
	if !strings.Contains(doc, "&lt;script&gt;") {
		t.Fatal("expected the value to survive, escaped")
	}
}
