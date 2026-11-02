package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/proto"
)

// Explicitly opt in with a disposable database: this test checks both the old
// schema upgrade and a fresh install, and resets public between those cases.
func TestCustomSensorsPostgres(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_SENSOR_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_SENSOR_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "upgrade"}[upgrade], func(t *testing.T) {
			db, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
				t.Fatal(err)
			}
			if upgrade {
				base := strings.Split(schemaSQL, "-- Custom collection configuration is additive")[0]
				if _, err = db.Exec(ctx, base); err != nil {
					t.Fatal(err)
				}
			}
			db.Close(ctx)
			s, err := Open(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			// Applying upgrades repeatedly must preserve data and work identically.
			again, err := Open(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			again.Close()
			c := CustomSensor{ID: "csn-test", Name: "Test", Commands: map[string]string{"linux": "print('[]')"}, Platforms: map[string]proto.SensorPlatform{"linux": {Language: "python", Output: proto.SensorOutput{Format: "json"}}}, Fields: []proto.SensorField{{Name: "name", Type: "string"}}, Enabled: true, IntervalSeconds: 60, TimeoutSeconds: 30}
			saved, err := s.UpsertCustomSensor(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			if saved.Platform("linux").Language != "python" {
				t.Fatal("lost configuration")
			}
			if err = s.UpsertOnRegister(ctx, "agent-test", proto.AgentInfo{OS: "linux", Hostname: "test"}); err != nil {
				t.Fatal(err)
			}
			if err = s.RecordCustomCapability(ctx, "agent-test", 1); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			raw := `[{"name":"test"}]`
			data, _ := json.Marshal(proto.CustomSensorResult{Raw: &raw, Revision: c.Revision("linux")})
			snap := proto.SensorSnapshot{AgentID: "agent-test", Sensor: proto.SensorKind(c.SensorKind()), Timestamp: now, Data: data}
			if err = s.RecordCustomSensor(ctx, snap); err != nil {
				t.Fatal(err)
			}
			last, err := s.LastCustomSuccess(ctx, "agent-test", c.SensorKind())
			if err != nil || last == nil {
				t.Fatal("missing last success", err)
			}
			snap.Timestamp = now.Add(time.Second)
			snap.Data = []byte(`{"error":"failed","exit_code":1}`)
			if err = s.RecordCustomSensor(ctx, snap); err != nil {
				t.Fatal(err)
			}
			current, _ := s.GetSensorData(ctx, "agent-test", c.SensorKind())
			if !strings.Contains(string(current.Data), "failed") {
				t.Fatal("failure not persisted")
			}
			last, _ = s.LastCustomSuccess(ctx, "agent-test", c.SensorKind())
			if !strings.Contains(string(last.Data), `"name": "test"`) && !strings.Contains(string(last.Data), `"name":"test"`) {
				t.Fatal("last success lost", string(last.Data))
			}
			g := ComputerGroup{ID: "cg-test", Name: "Test group", Kind: "dynamic", MatchMode: "all", Rules: []groups.Rule{{Field: c.SensorKind() + ".name", Op: "equals", Value: "test"}}}
			if _, err = s.UpsertComputerGroup(ctx, g); err != nil {
				t.Fatal(err)
			}
			c.Fields[0].Type = "number"
			if _, err = s.UpsertCustomSensor(ctx, c); err == nil {
				t.Fatal("referenced field retyped")
			}
			if err = s.DeleteCustomSensor(ctx, c.ID); err == nil {
				t.Fatal("referenced sensor deleted")
			}
			c.Fields[0].Type = "string"
			c.Fields = append(c.Fields, proto.SensorField{Name: "extra", Type: "number"})
			if _, err = s.UpsertCustomSensor(ctx, c); err != nil {
				t.Fatal("additive change rejected", err)
			}
			q := SavedQuestion{ID: "sq-test", Name: "Records", Get: []string{c.SensorKind() + ".name"}, RecordSensor: c.SensorKind(), MatchAll: true}
			if _, err = s.UpsertSavedQuestion(ctx, q); err != nil {
				t.Fatal(err)
			}
			fetched, err := s.GetSavedQuestion(ctx, q.ID)
			if err != nil || fetched.RecordSensor != q.RecordSensor {
				t.Fatal("record view lost", err)
			}
			if _, _, err = s.DeleteComputerGroupAndOrphans(ctx, g.ID); err != nil {
				t.Fatal(err)
			}
			if err = s.DeleteCustomSensor(ctx, c.ID); err == nil {
				t.Fatal("question reference ignored")
			}
			if err = s.DeleteSavedQuestion(ctx, q.ID); err != nil {
				t.Fatal(err)
			}
			if err = s.DeleteCustomSensor(ctx, c.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
