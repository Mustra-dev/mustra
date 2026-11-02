package server

import (
	"testing"
	"time"
)

func TestStackFixedSeriesOrderAndShares(t *testing.T) {
	rows := []map[string]any{
		{"site": "a", "platform": "debian"}, {"site": "a", "platform": "ubuntu"}, {"site": "a", "platform": "debian"},
		{"site": "b", "platform": "ubuntu"}, {"site": "b", "platform": ""},
	}
	bars := stack(rows, "site", "platform")
	if len(bars) != 2 || bars[0].Label != "a" || bars[0].Total != 3 {
		t.Fatalf("bars: %+v", bars)
	}
	// Labels are for a person, keys are what the row held: a drill-down
	// link built from "Debian" would match nothing.
	if bars[0].Parts[0].Label != "Debian" || bars[0].Parts[0].Key != "debian" || bars[0].Parts[0].Value != 2 {
		t.Fatalf("series order must be fixed across bars: %+v", bars)
	}
	if bars[1].Parts[0].Label != "Ubuntu" || bars[1].Parts[0].Key != "ubuntu" {
		t.Fatalf("series order must be fixed across bars: %+v", bars)
	}
	// The placeholder for a blank is not a value to tidy.
	if bars[1].Parts[1].Label != "(not set)" || bars[1].Parts[1].Key != "" {
		t.Fatalf("empty series label: %+v", bars[1])
	}
}

func TestFoldSeriesIntoOther(t *testing.T) {
	var in []seriesPoint
	for i := 0; i < 11; i++ {
		in = append(in, seriesPoint{Label: string(rune('a' + i)), Value: 11 - i})
	}
	out := foldSeries(in, 8, 66)
	if len(out) != 8 || out[7].Label != "Other" || out[7].Value != 4+3+2+1 {
		t.Fatalf("fold: %+v", out)
	}
}

func TestThresholds(t *testing.T) {
	d := panelData{Count: 12, Series: []seriesPoint{{Label: "fail", Value: 3, Share: 25}, {Label: "pass", Value: 9, Share: 75}}}
	cases := []struct {
		t    panelThreshold
		want bool
	}{
		{panelThreshold{Op: "gt", Value: 10}, true},
		{panelThreshold{Op: "lt", Value: 10}, false},
		{panelThreshold{Op: "zero"}, false},
		{panelThreshold{Op: "gte", Value: 3, Label: "FAIL"}, true},
		{panelThreshold{Op: "gt", Value: 30, Label: "fail", Percent: true}, false},
		{panelThreshold{Op: "lte", Value: 25, Label: "fail", Percent: true}, true},
		{panelThreshold{Op: "nonzero", Label: "missing"}, false},
	}
	for _, c := range cases {
		if got := thresholdHolds(c.t, d); got != c.want {
			t.Errorf("%+v: got %v want %v", c.t, got, c.want)
		}
	}
	if describeThreshold(panelThreshold{Op: "gt", Value: 30, Label: "fail", Percent: true}) != `"fail" share > 30%` {
		t.Fatal(describeThreshold(panelThreshold{Op: "gt", Value: 30, Label: "fail", Percent: true}))
	}
	_ = time.Now
}
