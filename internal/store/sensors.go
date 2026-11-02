package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// UpsertSensorData records the latest snapshot for one (agent, sensor)
// pair, overwriting whatever was cached before.
func (s *Store) UpsertSensorData(ctx context.Context, agentID, sensor string, collectedAt time.Time, data []byte) error {
	const q = `
INSERT INTO agent_sensor_data (agent_id, sensor, collected_at, data)
VALUES ($1, $2, $3, $4)
ON CONFLICT (agent_id, sensor) DO UPDATE SET
    collected_at = EXCLUDED.collected_at,
    data = EXCLUDED.data`
	if _, err := s.pool.Exec(ctx, q, agentID, sensor, collectedAt, data); err != nil {
		return fmt.Errorf("upsert sensor data: %w", err)
	}
	return nil
}

// SensorRecord is the cached snapshot for one (agent, sensor) pair.
type SensorRecord struct {
	AgentID     string
	Sensor      string
	CollectedAt time.Time
	Data        []byte // raw JSON, shape depends on Sensor
}

// GetSensorData returns the cached snapshot for one agent's sensor, or nil
// if nothing has been collected yet.
func (s *Store) GetSensorData(ctx context.Context, agentID, sensor string) (*SensorRecord, error) {
	row := s.pool.QueryRow(ctx, `SELECT agent_id, sensor, collected_at, data FROM agent_sensor_data WHERE agent_id = $1 AND sensor = $2`, agentID, sensor)
	var r SensorRecord
	if err := row.Scan(&r.AgentID, &r.Sensor, &r.CollectedAt, &r.Data); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get sensor data: %w", err)
	}
	return &r, nil
}

// AgentSensorRow is one agent's cached snapshot for a sensor, joined with
// enough inventory context (hostname/OS/platform/site) to render a
// fleet-wide summary — what the Patches tab's "which devices are missing
// which patches" view needs, and what the vulnerability scanner needs
// Platform for (OS is runtime.GOOS — "linux" — not specific enough to map
// to an OSV ecosystem; Platform is the actual distro, "debian"/"ubuntu").
type AgentSensorRow struct {
	AgentID         string
	Hostname        string
	OS              string
	Platform        string
	PlatformVersion string
	Site            string
	CollectedAt     time.Time
	Data            []byte
}

// ListSensorDataForSensor returns every agent's latest cached snapshot for
// one sensor kind, across the whole fleet — used to build the Patches
// tab's per-OS/per-patch aggregate view and the vulnerability scanner's
// per-ecosystem package matching, without a live query.
func (s *Store) ListSensorDataForSensor(ctx context.Context, sensor string) ([]AgentSensorRow, error) {
	const q = `
SELECT a.agent_id, a.hostname, a.os, a.platform, coalesce(a.platform_version, ''), a.site, d.collected_at, d.data
FROM agent_sensor_data d JOIN agents a ON a.agent_id = d.agent_id
WHERE d.sensor = $1
ORDER BY a.hostname`
	rows, err := s.pool.Query(ctx, q, sensor)
	if err != nil {
		return nil, fmt.Errorf("list sensor data for sensor: %w", err)
	}
	defer rows.Close()
	var out []AgentSensorRow
	for rows.Next() {
		var r AgentSensorRow
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.OS, &r.Platform, &r.PlatformVersion, &r.Site, &r.CollectedAt, &r.Data); err != nil {
			return nil, fmt.Errorf("scan agent sensor row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SensorCoverageRow summarises one sensor across the whole fleet.
type SensorCoverageRow struct {
	Sensor string `json:"sensor"`
	// Agents is how many endpoints have ever reported this sensor.
	Agents int `json:"agents"`
	// Newest and Oldest bracket the freshness of what is cached. Oldest is
	// the interesting one: a sensor whose newest collection is seconds ago
	// can still be badly stale on half the fleet, and an average would hide
	// exactly that.
	Newest *time.Time `json:"newest,omitempty"`
	Oldest *time.Time `json:"oldest,omitempty"`
	// Stale counts endpoints whose last collection is older than the cutoff.
	Stale int `json:"stale"`
	// ByOS counts the endpoints reporting it per operating system (linux,
	// windows, darwin, and haos for Home Assistant OS), so a sensor broken
	// on one platform shows as a gap rather than hiding in a fleet total.
	ByOS map[string]int `json:"by_os,omitempty"`
}

// SensorCoverage reports, per sensor, how much of the fleet is actually
// reporting it and how fresh that is. A sensor can be perfectly documented
// and still be silently broken on one platform — this is what makes that
// visible instead of requiring someone to notice a number looks old.
func (s *Store) SensorCoverage(ctx context.Context) ([]SensorCoverageRow, error) {
	const staleAfter = time.Hour
	const q = `
SELECT sensor,
       count(*)                                        AS agents,
       max(collected_at)                               AS newest,
       min(collected_at)                               AS oldest,
       count(*) FILTER (WHERE collected_at < now() - $1::interval) AS stale
FROM agent_sensor_data
GROUP BY sensor
ORDER BY sensor`
	rows, err := s.pool.Query(ctx, q, staleAfter)
	if err != nil {
		return nil, fmt.Errorf("sensor coverage: %w", err)
	}
	defer rows.Close()

	var out []SensorCoverageRow
	for rows.Next() {
		var r SensorCoverageRow
		if err := rows.Scan(&r.Sensor, &r.Agents, &r.Newest, &r.Oldest, &r.Stale); err != nil {
			return nil, fmt.Errorf("scan sensor coverage: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	osRows, err := s.pool.Query(ctx, `SELECT d.sensor, CASE WHEN a.platform = 'haos' THEN 'haos' ELSE a.os END, count(*)
FROM agent_sensor_data d JOIN agents a ON a.agent_id = d.agent_id GROUP BY 1, 2`)
	if err != nil {
		return nil, fmt.Errorf("sensor coverage by os: %w", err)
	}
	defer osRows.Close()
	idx := map[string]int{}
	for i, r := range out {
		idx[r.Sensor] = i
	}
	for osRows.Next() {
		var sensor, os string
		var n int
		if err := osRows.Scan(&sensor, &os, &n); err != nil {
			return nil, fmt.Errorf("scan sensor coverage by os: %w", err)
		}
		if i, ok := idx[sensor]; ok {
			if out[i].ByOS == nil {
				out[i].ByOS = map[string]int{}
			}
			out[i].ByOS[os] = n
		}
	}
	return out, osRows.Err()
}

// AgentCountsByOS counts endpoints per operating system, Home Assistant OS
// apart, for coverage's "N of M" per platform.
func (s *Store) AgentCountsByOS(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT CASE WHEN platform = 'haos' THEN 'haos' ELSE os END, count(*) FROM agents GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var os string
		var n int
		if err := rows.Scan(&os, &n); err != nil {
			return nil, err
		}
		out[os] = n
	}
	return out, rows.Err()
}

// ListSensorTimes returns when each agent last published each sensor,
// which is what a client-health view needs and all it needs: the payloads
// stay on disk.
func (s *Store) ListSensorTimes(ctx context.Context) (map[string]map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, sensor, collected_at FROM agent_sensor_data`)
	if err != nil {
		return nil, fmt.Errorf("list sensor times: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]time.Time{}
	for rows.Next() {
		var agent, sensor string
		var at time.Time
		if err := rows.Scan(&agent, &sensor, &at); err != nil {
			return nil, fmt.Errorf("scan sensor time: %w", err)
		}
		if out[agent] == nil {
			out[agent] = map[string]time.Time{}
		}
		out[agent][sensor] = at
	}
	return out, rows.Err()
}
