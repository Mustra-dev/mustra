package store

import (
	"context"
	"fmt"
	"time"
)

// AuditEvent is one recorded action. Deliberately flat and uniform: the
// module tables carry the structure specific to each kind of work, this
// carries the one shape everything can be read and exported in.
type AuditEvent struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Action   string    `json:"action"`
	Actor    string    `json:"actor"`
	Target   string    `json:"target"`
	AgentID  string    `json:"agent_id,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	Outcome  string    `json:"outcome"`
	Severity string    `json:"severity"`
	Detail   string    `json:"detail,omitempty"`
}

func (s *Store) RecordAuditEvent(ctx context.Context, e AuditEvent) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO audit_events (action, actor, target, agent_id, outcome, severity, detail)
VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7)`,
		e.Action, e.Actor, e.Target, e.AgentID, e.Outcome, e.Severity, e.Detail)
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

// ListAuditEvents returns the most recent events, optionally filtered.
// `since` supports incremental export without re-sending history.
func (s *Store) ListAuditEvents(ctx context.Context, action, actor, since string, limit int) ([]AuditEvent, error) {
	rows, err := s.pool.Query(ctx, `
SELECT e.id, e.at, e.action, e.actor, e.target, coalesce(e.agent_id,''),
       coalesce(a.hostname,''), e.outcome, e.severity, e.detail
FROM audit_events e
LEFT JOIN agents a ON a.agent_id = e.agent_id
WHERE ($1 = '' OR e.action LIKE $1 || '%')
  AND ($2 = '' OR e.actor = $2)
  AND ($3 = '' OR e.at > $3::timestamptz)
ORDER BY e.at DESC, e.id DESC
LIMIT $4`, action, actor, since, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Action, &e.Actor, &e.Target,
			&e.AgentID, &e.Hostname, &e.Outcome, &e.Severity, &e.Detail); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditActionCounts powers the summary — which kinds of thing happen, and
// how often.
func (s *Store) AuditActionCounts(ctx context.Context, days int) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
SELECT action, count(*) FROM audit_events
WHERE at > now() - make_interval(days => $1) GROUP BY action ORDER BY count(*) DESC`, days)
	if err != nil {
		return nil, fmt.Errorf("audit action counts: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var a string
		var n int
		if err := rows.Scan(&a, &n); err != nil {
			return nil, err
		}
		out[a] = n
	}
	return out, rows.Err()
}
