package store

import (
	"context"
	"fmt"
	"time"
)

// IntegrityChange is one detected difference between consecutive snapshots
// of a watched file. Expected marks change that mustra itself caused —
// kept rather than hidden, so the record is complete and the list is still
// readable.
type IntegrityChange struct {
	ID             string     `json:"id"`
	AgentID        string     `json:"agent_id"`
	Hostname       string     `json:"hostname"`
	Path           string     `json:"path"`
	Kind           string     `json:"kind"`
	What           string     `json:"what"`
	Was            string     `json:"was"`
	Now            string     `json:"now"`
	Expected       bool       `json:"expected"`
	Because        string     `json:"because"`
	Labels         []string   `json:"labels"`
	DetectedAt     time.Time  `json:"detected_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
}

func (s *Store) RecordIntegrityChanges(ctx context.Context, changes []IntegrityChange) error {
	if len(changes) == 0 {
		return nil
	}
	batch := make([][]any, 0, len(changes))
	for _, c := range changes {
		labels := c.Labels
		if labels == nil {
			labels = []string{}
		}
		batch = append(batch, []any{c.AgentID, c.Path, c.Kind, c.What, c.Was, c.Now, c.Expected, c.Because, labels})
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin integrity changes: %w", err)
	}
	defer tx.Rollback(ctx)
	for _, args := range batch {
		if _, err := tx.Exec(ctx, `
INSERT INTO integrity_changes (agent_id, path, kind, what, was, now_value, expected, because, labels)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, args...); err != nil {
			return fmt.Errorf("insert integrity change: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ListIntegrityChanges(ctx context.Context, limit int) ([]IntegrityChange, error) {
	rows, err := s.pool.Query(ctx, `
SELECT c.id, c.agent_id, coalesce(a.hostname, ''), c.path, c.kind, c.what,
       c.was, c.now_value, c.expected, c.because, c.labels, c.detected_at, c.acknowledged_at, c.acknowledged_by
FROM integrity_changes c
LEFT JOIN agents a ON a.agent_id = c.agent_id
ORDER BY c.detected_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list integrity changes: %w", err)
	}
	defer rows.Close()
	var out []IntegrityChange
	for rows.Next() {
		var c IntegrityChange
		if err := rows.Scan(&c.ID, &c.AgentID, &c.Hostname, &c.Path, &c.Kind, &c.What,
			&c.Was, &c.Now, &c.Expected, &c.Because, &c.Labels, &c.DetectedAt, &c.AcknowledgedAt, &c.AcknowledgedBy); err != nil {
			return nil, fmt.Errorf("scan integrity change: %w", err)
		}
		if c.Labels == nil {
			c.Labels = []string{}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Criticality is how much an endpoint matters. It scales that endpoint's
// risk score, because the same vulnerability on a domain controller and on
// a spare laptop are not the same finding.
func (s *Store) ListCriticality(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, level FROM agent_criticality`)
	if err != nil {
		return nil, fmt.Errorf("list criticality: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, level string
		if err := rows.Scan(&id, &level); err != nil {
			return nil, fmt.Errorf("scan criticality: %w", err)
		}
		out[id] = level
	}
	return out, rows.Err()
}

// SetCriticality returns ErrUnknownAgent when no endpoint has agentID.
// The insert selects from agents rather than leaving the check to the
// foreign key, so a mistyped ID is told apart from a failed write.
func (s *Store) SetCriticality(ctx context.Context, agentID, level string) error {
	tag, err := s.pool.Exec(ctx, `
INSERT INTO agent_criticality (agent_id, level)
SELECT agent_id, $2::text FROM agents WHERE agent_id = $1
ON CONFLICT (agent_id) DO UPDATE SET level = EXCLUDED.level, updated_at = now()`, agentID, level)
	if err != nil {
		return fmt.Errorf("set criticality: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("set criticality for %q: %w", agentID, ErrUnknownAgent)
	}
	return nil
}
