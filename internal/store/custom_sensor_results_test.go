package store

import (
	"github.com/mustra-dev/mustra/internal/proto"
	"testing"
)

func TestLegacyCustomSensorCompatibility(t *testing.T) {
	c := CustomSensor{Commands: map[string]string{"linux": "echo value"}}
	if !c.LegacyCompatible("linux") {
		t.Fatal("legacy sensor rejected")
	}
	c.Fields = []proto.SensorField{{Name: "value", Type: "string"}}
	c.Platforms = map[string]proto.SensorPlatform{"linux": {Language: "shell", Output: proto.SensorOutput{Format: "text"}}}
	if !c.LegacyCompatible("linux") {
		t.Fatal("materialized defaults rejected")
	}
	c.Platforms["linux"] = proto.SensorPlatform{Language: "python"}
	if c.LegacyCompatible("linux") {
		t.Fatal("Python sent to old shell agent")
	}
	res := NormalizeCustomResult(c, "linux", proto.CustomSensorResult{Lines: []string{"value"}})
	if res.Error == "" || res.Rows != nil {
		t.Fatal("legacy result accepted for Python")
	}
}

func TestHistorySurvivesScriptEditsButNotTypeChanges(t *testing.T) {
	c := CustomSensor{Fields: []proto.SensorField{{Name: "value", Type: "string"}}}
	old := proto.CustomSensorResult{Revision: "previous-script", Fields: c.Fields, Rows: []map[string]any{{"value": "old"}}}
	rows, ok := HistoricalCustomRows(c, old)
	if !ok || rows[0]["value"] != "old" {
		t.Fatal("lost historical values")
	}
	c.Fields = []proto.SensorField{{Name: "value", Type: "number"}}
	if _, ok = HistoricalCustomRows(c, old); ok {
		t.Fatal("incompatible history projected")
	}
}
