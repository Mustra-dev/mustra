package sensoroutput

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// FuzzParse drives the custom-sensor output parser with fuzzed raw output
// across every format, delimiter and field layout. The raw bytes are agent
// output for an operator-defined collector — attacker-adjacent on a
// compromised endpoint — and the parsed rows feed targeting, reports and
// the console. Properties: Parse never panics for any configuration, and
// when it succeeds it respects its own MaxRows bound and returns one value
// per declared field per row (the shape the rest of the system assumes).
func FuzzParse(f *testing.F) {
	for _, raw := range []string{
		"", "a\nb\nc", `{"name":"x","n":1}`, `[{"name":"x"},{"name":"y"}]`,
		"{\"rows\":[{\"a\":1}]}", "a,b,c\n1,2,3", "x\ty\tz", "true\nfalse\n7",
		`{"n": 1e999}`, "1\n2\n3\n", `{"a":{"b":{"c":1}}}`, "\x00\x01\x02",
	} {
		f.Add(raw, "json", "", ",", false, "value", "string")
		f.Add(raw, "text", "", ",", false, "value", "string")
	}
	f.Fuzz(func(t *testing.T, raw, format, rowPath, delim string, headers bool, fieldName, fieldType string) {
		if len(raw) > MaxBytes || len(delim) == 0 {
			return
		}
		o := proto.SensorOutput{Format: format, RowPath: rowPath, Delimiter: delim, Headers: headers}
		// One declared field, plus the default-field path (nil fields).
		for _, fields := range [][]proto.SensorField{
			nil,
			{{Name: "value", Type: fieldType}},
			{{Name: fieldName, Type: fieldType}},
			{{Name: "a", Type: "string"}, {Name: "b", Type: "number"}, {Name: "c", Type: "bool"}},
		} {
			rows, err := Parse(raw, o, fields)
			if err != nil {
				continue
			}
			if len(rows) > MaxRows {
				t.Fatalf("Parse returned %d rows, over MaxRows %d", len(rows), MaxRows)
			}
			want := Fields(fields)
			for _, row := range rows {
				for _, fld := range want {
					if _, ok := row[fld.Name]; !ok {
						t.Fatalf("row missing declared field %q: %#v (fmt=%q)", fld.Name, row, format)
					}
				}
			}
		}
	})
}
