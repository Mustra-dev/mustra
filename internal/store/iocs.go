package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Indicators of compromise, and where they have been seen.
//
// The hunt runs over cached sensor data rather than sweeping the fleet: the
// whole point of the sensor model is that the estate's state is already
// here, so "is this hash anywhere" should be a database question answered in
// milliseconds, not thirty-nine machines woken up to grep their own disks.

const (
	IOCFileHash    = "file_hash"
	IOCFilePath    = "file_path"
	IOCProcessName = "process_name"
	IOCIPAddress   = "ip"
	IOCAppName     = "app_name"
)

type IOC struct {
	ID          string    `json:"id"`
	Name        string    `json:"name" api:"required"`
	Kind        string    `json:"kind" api:"required"`
	Value       string    `json:"value" api:"required"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at" api:"readonly"`
	CreatedBy   string    `json:"created_by" api:"readonly"`
}

// IOCFinding is one indicator seen on one endpoint.
type IOCFinding struct {
	ID           string    `json:"id"`
	IOCID        string    `json:"ioc_id"`
	AgentID      string    `json:"agent_id"`
	Hostname     string    `json:"hostname,omitempty"`
	MatchedValue string    `json:"matched_value"`
	Context      string    `json:"context"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Acknowledged bool      `json:"acknowledged"`
	// Denormalised from the indicator so the findings list can be read
	// without joining every row back to what it means.
	IOCName     string `json:"ioc_name,omitempty"`
	IOCKind     string `json:"ioc_kind,omitempty"`
	IOCSeverity string `json:"ioc_severity,omitempty"`
}

const iocColumns = `id, name, kind, value, severity, description, source, enabled, created_at, created_by`

func scanIOC(row pgx.Row) (*IOC, error) {
	var i IOC
	if err := row.Scan(&i.ID, &i.Name, &i.Kind, &i.Value, &i.Severity,
		&i.Description, &i.Source, &i.Enabled, &i.CreatedAt, &i.CreatedBy); err != nil {
		return nil, err
	}
	return &i, nil
}

func (s *Store) ListIOCs(ctx context.Context) ([]IOC, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+iocColumns+` FROM iocs ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list indicators: %w", err)
	}
	defer rows.Close()
	var out []IOC
	for rows.Next() {
		i, err := scanIOC(rows)
		if err != nil {
			return nil, fmt.Errorf("scan indicator: %w", err)
		}
		out = append(out, *i)
	}
	return out, rows.Err()
}

func (s *Store) UpsertIOC(ctx context.Context, i IOC) (*IOC, error) {
	const q = `
INSERT INTO iocs (id, name, kind, value, severity, description, source, enabled, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, kind = EXCLUDED.kind, value = EXCLUDED.value,
  severity = EXCLUDED.severity, description = EXCLUDED.description,
  source = EXCLUDED.source, enabled = EXCLUDED.enabled
RETURNING ` + iocColumns
	out, err := scanIOC(s.pool.QueryRow(ctx, q, i.ID, i.Name, i.Kind, i.Value,
		i.Severity, i.Description, i.Source, i.Enabled, i.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("upsert indicator: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteIOC(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM iocs WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete indicator: %w", err)
	}
	return nil
}

// RecordIOCFinding upserts a sighting. Returns true when this is the first
// time this indicator has been seen on this endpoint — which is the only
// moment worth raising a notification, since a hunt runs on a timer and
// re-reporting the same finding every fifteen minutes trains people to
// ignore it.
func (s *Store) RecordIOCFinding(ctx context.Context, f IOCFinding) (bool, error) {
	const q = `
INSERT INTO ioc_findings (id, ioc_id, agent_id, matched_value, context)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (ioc_id, agent_id, matched_value) DO UPDATE SET
  last_seen = now(), context = EXCLUDED.context
RETURNING (xmax = 0) AS inserted`
	var inserted bool
	if err := s.pool.QueryRow(ctx, q, f.ID, f.IOCID, f.AgentID,
		f.MatchedValue, f.Context).Scan(&inserted); err != nil {
		return false, fmt.Errorf("record indicator finding: %w", err)
	}
	return inserted, nil
}

func (s *Store) ListIOCFindings(ctx context.Context, limit int) ([]IOCFinding, error) {
	if limit <= 0 {
		limit = 500
	}
	const q = `
SELECT f.id, f.ioc_id, f.agent_id, coalesce(a.hostname, ''), f.matched_value, f.context,
       f.first_seen, f.last_seen, f.acknowledged, i.name, i.kind, i.severity
FROM ioc_findings f
JOIN iocs i ON i.id = f.ioc_id
LEFT JOIN agents a ON a.agent_id = f.agent_id
ORDER BY f.acknowledged, f.last_seen DESC
LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("list indicator findings: %w", err)
	}
	defer rows.Close()
	var out []IOCFinding
	for rows.Next() {
		var f IOCFinding
		if err := rows.Scan(&f.ID, &f.IOCID, &f.AgentID, &f.Hostname, &f.MatchedValue,
			&f.Context, &f.FirstSeen, &f.LastSeen, &f.Acknowledged,
			&f.IOCName, &f.IOCKind, &f.IOCSeverity); err != nil {
			return nil, fmt.Errorf("scan indicator finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// AcknowledgeIOCFinding marks a sighting handled. It is not deleted: losing
// the record that something was once there is exactly the wrong outcome for
// the one table where history is the point.
func (s *Store) AcknowledgeIOCFinding(ctx context.Context, id string, ack bool) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE ioc_findings SET acknowledged = $2 WHERE id = $1`, id, ack); err != nil {
		return fmt.Errorf("acknowledge indicator finding: %w", err)
	}
	return nil
}
