package groups

import "testing"

// Values and Matches read the same catalog, so these pin the two
// distinctions that are easy to lose and expensive to get wrong.

func TestValuesDistinguishesUnmeasuredFromEmpty(t *testing.T) {
	// A device that never reported the sensor must answer nil, not an empty
	// slice: "no antivirus installed" and "never told us" are different
	// answers, and a results grid that shows both as blank is lying.
	never := Device{AgentID: "a1"}
	if got := Values(never, "installed_apps.name"); got != nil {
		t.Fatalf("device that never reported the sensor: want nil, got %#v", got)
	}

	reportedNothing := Device{AgentID: "a2", Sensors: map[string][]map[string]any{
		"installed_apps": {},
	}}
	if got := Values(reportedNothing, "installed_apps.name"); got == nil {
		t.Fatal("device that reported an empty list should not read as unmeasured")
	}
	if got := Values(reportedNothing, "installed_apps.count"); len(got) != 1 || got[0] != "0" {
		t.Fatalf("count of an empty reported list: want [0], got %#v", got)
	}
}

func TestValuesDeduplicatesAndKeepsOrder(t *testing.T) {
	d := Device{Sensors: map[string][]map[string]any{
		"installed_apps": {
			{"name": "curl"}, {"name": "jq"}, {"name": "curl"},
		},
	}}
	got := Values(d, "installed_apps.name")
	want := []string{"curl", "jq"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}

func TestValuesReadsInventoryFields(t *testing.T) {
	d := Device{Hostname: "web-01", OS: "linux", CPUCount: 4, Online: true}
	for field, want := range map[string]string{
		"hostname":  "web-01",
		"os":        "linux",
		"cpu_count": "4",
		"online":    "true",
	} {
		got := Values(d, field)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: want [%s], got %#v", field, want, got)
		}
	}
	if got := Values(d, "not_a_field"); got != nil {
		t.Errorf("unknown field: want nil, got %#v", got)
	}
}
