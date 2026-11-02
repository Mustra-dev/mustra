package groups

import (
	"encoding/json"
	"testing"
)

// sampleDevice is a representative device the matcher runs against.
var sampleDevice = Device{
	AgentID: "agt-0123456789abcdef0123456789abcdef", Hostname: "host-1", OS: "linux",
	Arch: "amd64", Site: "default", CPUCount: 8, MemTotalMB: 16384, Online: true, Managed: true,
	Attributes: map[string]string{"owner": "ops", "": "empty"},
	Sensors: map[string][]map[string]any{
		"installed_apps": {{"name": "Docker", "version": "25.0"}, {"name": "curl"}},
		"patches":        {{"name": "KB1", "severity": "critical"}},
		"processes":      {{"pid": float64(1), "name": "init", "nested": map[string]any{"x": 1}}},
	},
	SensorStatus: map[string]map[string]string{"installed_apps": {"_error": "", "_count": "2"}},
}

// FuzzRuleValidateMatch drives the targeting rule validator and matcher
// with fuzzed field/op/value triples (and a fuzzed same_row child set).
// Properties: Validate never panics; a rule Validate accepts is evaluable
// by Matches without panic; and Matches never panics on any rule, valid or
// not — the matcher runs server-side against every device for every saved
// group, so a rule that crashes it is a denial of service across the fleet.
func FuzzRuleValidateMatch(f *testing.F) {
	seeds := []struct {
		field, op, value string
	}{
		{"hostname", "equals", "host-1"},
		{"installed_apps.name", "contains", "Docker"},
		{"patches.count", "gte", "1"},
		{"cpu_count", "gt", "4"},
		{"attr.owner", "equals", "ops"},
		{"installed_apps.name", "regex", "(a+)+$"},
		{"os", "in", "linux,darwin,windows"},
		{"installed_apps._row", "same_row", `[{"field":"installed_apps.name","op":"equals","value":"Docker"}]`},
		{"certificates.days_left", "lt", "-1"},
		{"", "", ""},
		{"a.b.c", "unknown", "x"},
		{"installed_apps._row", "same_row", `[{"field":"installed_apps._row","op":"same_row","value":"[]"}]`},
	}
	for _, s := range seeds {
		f.Add(s.field, s.op, s.value)
	}
	f.Fuzz(func(t *testing.T, field, op, value string) {
		if len(field)+len(op)+len(value) > 8192 {
			return
		}
		r := Rule{Field: field, Op: op, Value: value}
		valErr := r.Validate()
		// Matches must be total regardless of validity.
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("Matches panicked on rule %+v (validate=%v): %v", r, valErr, p)
				}
			}()
			_ = Matches(sampleDevice, []Rule{r}, true)
			_ = Matches(sampleDevice, []Rule{r}, false)
			_ = Values(sampleDevice, field)
		}()
		// A same_row value that is valid JSON of rules exercises the nested
		// path; make sure recursing cannot blow the stack via self-reference.
		if op == "same_row" {
			var children []Rule
			if json.Unmarshal([]byte(value), &children) == nil {
				_ = Matches(sampleDevice, []Rule{r}, true)
			}
		}
	})
}
