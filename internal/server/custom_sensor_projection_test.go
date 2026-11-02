package server

import (
	"encoding/json"
	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
	"testing"
	"time"
)

func TestCustomResultStates(t *testing.T) {
	now := time.Now()
	def := store.CustomSensor{ID: "csn-test", Enabled: true, Commands: map[string]string{"linux": "echo hi"}, IntervalSeconds: 60, TimeoutSeconds: 30}
	raw := "hello\n"
	data, _ := json.Marshal(proto.CustomSensorResult{Raw: &raw, Revision: def.Revision("linux")})
	row := &store.AgentSensorRow{Data: data, CollectedAt: now}
	if res, state := customStatus(def, "linux", row, 1, now); state != "success" || len(res.Rows) != 1 {
		t.Fatalf("%s %#v", state, res)
	}
	if _, state := customStatus(def, "linux", row, 1, now.Add(151*time.Second)); state != "stale" {
		t.Fatal(state)
	}
	if _, state := customStatus(def, "linux", nil, 1, now); state != "never_reported" {
		t.Fatal(state)
	}
	def.Platforms = map[string]proto.SensorPlatform{"linux": {Language: "python"}}
	if _, state := customStatus(def, "linux", row, 0, now); state != "unsupported" {
		t.Fatal(state)
	}
	if _, state := customStatus(def, "linux", row, 1, now); state != "failed" {
		t.Fatal("old revision used", state)
	}
}
func TestRecordViewPreservesRelationships(t *testing.T) {
	d := groups.Device{AgentID: "a", Sensors: map[string][]map[string]any{"custom_csn-test": {{"name": "a", "running": false}, {"name": "b", "running": true}}}}
	req := questionRequest{Get: []string{"custom_csn-test.name", "custom_csn-test.running"}, RecordSensor: "custom_csn-test"}
	result := answerQuestion([]groups.Device{d}, req)
	if len(result.Rows) != 2 || result.Rows[0].Values[1] != "false" || result.Rows[1].Values[0] != "b" {
		t.Fatalf("%#v", result.Rows)
	}
}
func TestWQLScope(t *testing.T) {
	if err := validateWQL("SELECT Name FROM Win32_Process", `root\cimv2`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"Get-Process", "SELECT * FROM __InstanceCreationEvent WITHIN 1"} {
		if validateWQL(q, `root\cimv2`) == nil {
			t.Fatalf("accepted %s", q)
		}
	}
	if validateWQL("SELECT * FROM Win32_Process", `\\remote\root\cimv2`) == nil {
		t.Fatal("remote namespace accepted")
	}
}
