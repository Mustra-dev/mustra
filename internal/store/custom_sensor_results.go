package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
)

func NormalizeCustomResult(def CustomSensor, os string, result proto.CustomSensorResult) proto.CustomSensorResult {
	result.Rows = nil
	result.Fields = nil
	if result.Error != "" || result.TimedOut || result.ExitCode != 0 || result.Truncated {
		if result.Error == "" {
			result.Error = "collection failed or output was truncated"
		}
		return result
	}
	if result.Revision != "" && result.Revision != def.Revision(os) {
		result.Error = "definition changed; awaiting a new collection"
		return result
	}
	p := def.Platform(os)
	if result.Revision == "" && !def.LegacyCompatible(os) {
		result.Error = "agent upgrade required for this definition"
		return result
	}
	raw := strings.Join(result.Lines, "\n")
	if result.Raw != nil {
		raw = *result.Raw
	}
	rows, err := sensoroutput.Parse(raw, p.Output, def.Fields)
	if err != nil {
		result.Error = "output parsing: " + err.Error()
		return result
	}
	result.Rows = rows
	result.Fields = sensoroutput.Fields(def.Fields)
	return result
}

// Persist latest attempt and last success atomically so redelivery cannot turn a
// failed collection into a successful empty answer or overwrite newer evidence.
func (s *Store) RecordCustomSensor(ctx context.Context, snap proto.SensorSnapshot) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	def, err := scanCustomSensor(tx.QueryRow(ctx, `SELECT `+customSensorColumns+` FROM custom_sensors WHERE id=$1 FOR SHARE`, strings.TrimPrefix(string(snap.Sensor), "custom_")))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	var os string
	if err = tx.QueryRow(ctx, `SELECT os FROM agents WHERE agent_id=$1`, snap.AgentID).Scan(&os); err != nil {
		return err
	}
	var result proto.CustomSensorResult
	if err = json.Unmarshal(snap.Data, &result); err != nil {
		return fmt.Errorf("decode custom result: %w", err)
	}
	result = NormalizeCustomResult(*def, os, result)
	data, _ := json.Marshal(result)
	if _, err = tx.Exec(ctx, `INSERT INTO agent_sensor_data(agent_id,sensor,collected_at,data) VALUES($1,$2,$3,$4) ON CONFLICT(agent_id,sensor) DO UPDATE SET collected_at=EXCLUDED.collected_at,data=EXCLUDED.data WHERE agent_sensor_data.collected_at<=EXCLUDED.collected_at`, snap.AgentID, snap.Sensor, snap.Timestamp, data); err != nil {
		return err
	}
	if result.Error == "" {
		if _, err = tx.Exec(ctx, `INSERT INTO custom_sensor_success(agent_id,sensor,collected_at,data) VALUES($1,$2,$3,$4) ON CONFLICT(agent_id,sensor) DO UPDATE SET collected_at=EXCLUDED.collected_at,data=EXCLUDED.data WHERE custom_sensor_success.collected_at<=EXCLUDED.collected_at`, snap.AgentID, snap.Sensor, snap.Timestamp, data); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) RecordCustomCapability(ctx context.Context, id string, version int) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO custom_sensor_capabilities(agent_id,version) VALUES($1,$2) ON CONFLICT(agent_id) DO UPDATE SET version=EXCLUDED.version`, id, version)
	return err
}
func (s *Store) CustomCapabilities(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id,version FROM custom_sensor_capabilities`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var v int
		if err = rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, rows.Err()
}
func (s *Store) LastCustomSuccess(ctx context.Context, id, sensor string) (*SensorRecord, error) {
	var r SensorRecord
	r.AgentID = id
	r.Sensor = sensor
	err := s.pool.QueryRow(ctx, `SELECT collected_at,data FROM custom_sensor_success WHERE agent_id=$1 AND sensor=$2`, id, sensor).Scan(&r.CollectedAt, &r.Data)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListCustomSuccess(ctx context.Context, sensor string) (map[string]SensorRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id,collected_at,data FROM custom_sensor_success WHERE sensor=$1`, sensor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SensorRecord{}
	for rows.Next() {
		var r SensorRecord
		r.Sensor = sensor
		if err = rows.Scan(&r.AgentID, &r.CollectedAt, &r.Data); err != nil {
			return nil, err
		}
		out[r.AgentID] = r
	}
	return out, rows.Err()
}

// Historical records are already normalized. Script revisions may change while
// their schema remains compatible; only current results can enter targeting.
func HistoricalCustomRows(def CustomSensor, result proto.CustomSensorResult) ([]map[string]any, bool) {
	types := map[string]string{}
	for _, f := range sensoroutput.Fields(result.Fields) {
		types[f.Name] = f.Type
	}
	for _, f := range sensoroutput.Fields(def.Fields) {
		if old, ok := types[f.Name]; ok && old != f.Type {
			return nil, false
		}
	}
	out := make([]map[string]any, 0, len(result.Rows))
	for _, row := range result.Rows {
		projected := map[string]any{}
		for _, f := range sensoroutput.Fields(def.Fields) {
			projected[f.Name] = row[f.Name]
		}
		out = append(out, projected)
	}
	return out, true
}
