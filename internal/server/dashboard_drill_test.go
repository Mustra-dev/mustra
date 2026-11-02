package server

import (
	"encoding/json"
	"testing"
)

// The console links a chart mark to the rows behind it, and it can only do
// that if the evaluated panel says which source and column it was grouped
// on. It did not at first: the drill-down shipped, rendered no links at
// all, and looked exactly like a no-op because the panel JSON carried a
// picture and nothing to identify it. A field dropped from panelData would
// break it the same silent way, so the wire shape is pinned here.
func TestEvaluatedPanelCarriesItsDrillFields(t *testing.T) {
	blob, err := json.Marshal(panelData{
		ID: "pnl-1", Chart: "donut", Title: "By operating system", Width: 1,
		DrillSource: "endpoints", DrillGroupBy: "os", DrillSeriesBy: "platform",
		DrillFilterColumn: "online", DrillFilterValue: "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"source": "endpoints", "group_by": "os", "series_by": "platform",
		"filter_column": "online", "filter_value": "true",
	} {
		if got[key] != want {
			t.Errorf("evaluated panel %q = %v, want %q — the console cannot build a drill-down link without it",
				key, got[key], want)
		}
	}
}

// An ungrouped panel still links -- its number stands for a set of
// endpoints -- so it keeps its source. What it must not send is a grouping
// or a filter it does not have, since those become query conditions.
func TestUngroupedPanelOmitsDrillFields(t *testing.T) {
	blob, err := json.Marshal(panelData{ID: "pnl-2", Chart: "number", Title: "Managed endpoints", Width: 1})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"group_by", "series_by", "filter_column", "filter_value"} {
		if _, present := got[key]; present {
			t.Errorf("an ungrouped, unfiltered panel sent %q; there is nothing to put in the query", key)
		}
	}
}
