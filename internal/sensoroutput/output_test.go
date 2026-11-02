package sensoroutput

import (
	"github.com/mustra-dev/mustra/internal/proto"
	"reflect"
	"strings"
	"testing"
)

func TestOutputFormats(t *testing.T) {
	fields := []proto.SensorField{{Name: "name", Type: "string"}, {Name: "size", Type: "number"}}
	tests := []struct {
		name, raw string
		o         proto.SensorOutput
		fields    []proto.SensorField
		want      []map[string]any
	}{
		{"legacy CRLF", "a\r\nb\n", proto.SensorOutput{}, nil, []map[string]any{{"value": "a"}, {"value": "b"}}},
		{"empty success", "", proto.SensorOutput{}, nil, []map[string]any{}},
		{"nested JSON", `{"data":[{"name":"a","memory":{"mb":2}}]}`, proto.SensorOutput{Format: "json", RowPath: "data", Paths: map[string]string{"size": "memory.mb"}}, fields, []map[string]any{{"name": "a", "size": float64(2)}}},
		{"JSON pointer", `[{"a.b":"x","size":3}]`, proto.SensorOutput{Format: "json", Paths: map[string]string{"name": "/a.b"}}, fields, []map[string]any{{"name": "x", "size": float64(3)}}},
		{"scalar array", `{"items":["a","b"]}`, proto.SensorOutput{Format: "json", RowPath: "items"}, nil, []map[string]any{{"value": "a"}, {"value": "b"}}},
		{"JSON lines", "{\"name\":\"x\",\"size\":1}\n{\"name\":\"y\",\"size\":null}\n", proto.SensorOutput{Format: "jsonl"}, fields, []map[string]any{{"name": "x", "size": float64(1)}, {"name": "y", "size": nil}}},
		{"quoted pipe and embedded newline", "name|size\n\"a|b\nline\"|2\n", proto.SensorOutput{Format: "delimited", Delimiter: "|", Headers: true}, fields, []map[string]any{{"name": "a|b\nline", "size": float64(2)}}},
		{"list", "a~\"b~c\"", proto.SensorOutput{Format: "list", Delimiter: "~"}, nil, []map[string]any{{"value": "a"}, {"value": "b~c"}}},
		{"empty JSON array", "[]", proto.SensorOutput{Format: "json"}, fields, []map[string]any{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.raw, tt.o, tt.fields)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v want %#v", got, tt.want)
			}
		})
	}
}
func TestInvalidOutputNeverReturnsPartialRows(t *testing.T) {
	for _, raw := range []string{"{\"value\":1}\n{broken", "{\"value\":1}\n{\"value\":\"wrong type\"}"} {
		rows, err := Parse(raw, proto.SensorOutput{Format: "jsonl"}, []proto.SensorField{{Name: "value", Type: "number"}})
		if err == nil || rows != nil {
			t.Fatalf("partial success: %v %v", rows, err)
		}
	}
	for _, raw := range []string{strings.Repeat("x", MaxBytes+1), strings.Repeat("x\n", MaxRows+1)} {
		if rows, err := Parse(raw, proto.SensorOutput{}, nil); err == nil || rows != nil {
			t.Fatal("unbounded output accepted")
		}
	}
	for _, raw := range []string{`{} {}`, `{"value":[1,2]}`, `null`} {
		if rows, err := Parse(raw, proto.SensorOutput{Format: "json"}, nil); err == nil || rows != nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestValidateOutput(t *testing.T) {
	for _, delimiter := range []string{"", "ab", "\n", "\""} {
		if Validate(nil, map[string]proto.SensorPlatform{"linux": {Output: proto.SensorOutput{Format: "list", Delimiter: delimiter}}}) == nil {
			t.Fatalf("accepted delimiter %q", delimiter)
		}
	}
	if Validate(nil, map[string]proto.SensorPlatform{"linux": {Language: "batch"}}) == nil {
		t.Fatal("batch accepted on Linux")
	}
}
