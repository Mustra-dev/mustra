package groups

import (
	"encoding/json"
	"testing"
)

func TestExplicitSameRow(t *testing.T) {
	d := Device{Sensors: map[string][]map[string]any{"custom_csn-test": {{"name": "a", "running": false}, {"name": "b", "running": true}}}}
	conditions := []Rule{{"custom_csn-test.name", OpEquals, "a"}, {"custom_csn-test.running", OpEquals, "true"}}
	if !Matches(d, conditions, true) {
		t.Fatal("legacy semantics changed")
	}
	data, _ := json.Marshal(conditions)
	rule := Rule{"custom_csn-test._row", "same_row", string(data)}
	if rule.Validate() != nil || Matches(d, []Rule{rule}, true) {
		t.Fatal("matched across rows")
	}
	conditions[0].Value = "b"
	data, _ = json.Marshal(conditions)
	rule.Value = string(data)
	if !Matches(d, []Rule{rule}, true) {
		t.Fatal("same row failed")
	}
	if Matches(Device{}, []Rule{{"custom_csn-test.name", OpNotContain, "a"}}, true) {
		t.Fatal("unknown matched negative condition")
	}
}

func TestCustomNullsCannotProveAbsence(t *testing.T) {
	d := Device{Sensors: map[string][]map[string]any{"custom_csn-test": {{"name": nil}, {"name": "a"}}}}
	if Matches(d, []Rule{{"custom_csn-test.name", OpNotEquals, "b"}}, true) {
		t.Fatal("unknown row was treated as evidence of absence")
	}
	d.Sensors["custom_csn-test"] = []map[string]any{{"name": nil}}
	if Matches(d, []Rule{{"custom_csn-test.name", OpExists, ""}}, true) {
		t.Fatal("null treated as present")
	}
}
