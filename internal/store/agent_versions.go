package store

import (
	"context"
	"fmt"
	"time"
)

// AgentVersionChange is one recorded transition — see schema.sql's
// agent_version_history table.
type AgentVersionChange struct {
	AgentID   string    `json:"agent_id"`
	Version   string    `json:"version"`
	FirstSeen time.Time `json:"first_seen"`
}

// RecordAgentVersion appends a row only when the version differs from the
// one most recently recorded for that agent. Called on every registration,
// so it has to be cheap and idempotent: an agent that reports the same
// version forever writes exactly one row.
func (s *Store) RecordAgentVersion(ctx context.Context, agentID, version string) error {
	if version == "" {
		return nil
	}
	const q = `
INSERT INTO agent_version_history (agent_id, version)
SELECT $1, $2
WHERE NOT EXISTS (
    SELECT 1 FROM agent_version_history
    WHERE agent_id = $1
    ORDER BY first_seen DESC
    LIMIT 1
) OR (
    SELECT version FROM agent_version_history
    WHERE agent_id = $1
    ORDER BY first_seen DESC
    LIMIT 1
) IS DISTINCT FROM $2`
	if _, err := s.pool.Exec(ctx, q, agentID, version); err != nil {
		return fmt.Errorf("record agent version: %w", err)
	}
	return nil
}

// AgentVersionHistory returns one agent's version transitions, newest first.
func (s *Store) AgentVersionHistory(ctx context.Context, agentID string) ([]AgentVersionChange, error) {
	rows, err := s.pool.Query(ctx, `
SELECT agent_id, version, first_seen FROM agent_version_history
WHERE agent_id = $1 ORDER BY first_seen DESC`, agentID)
	if err != nil {
		return nil, fmt.Errorf("agent version history: %w", err)
	}
	defer rows.Close()
	var out []AgentVersionChange
	for rows.Next() {
		var c AgentVersionChange
		if err := rows.Scan(&c.AgentID, &c.Version, &c.FirstSeen); err != nil {
			return nil, fmt.Errorf("scan agent version change: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RecentAgentVersionChanges is the fleet-wide upgrade feed: who moved to
// what, most recent first. This is what makes a rollout observable while
// it's happening.
func (s *Store) RecentAgentVersionChanges(ctx context.Context, limit int) ([]AgentVersionChange, error) {
	rows, err := s.pool.Query(ctx, `
SELECT h.agent_id, h.version, h.first_seen FROM agent_version_history h
ORDER BY h.first_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("recent agent version changes: %w", err)
	}
	defer rows.Close()
	var out []AgentVersionChange
	for rows.Next() {
		var c AgentVersionChange
		if err := rows.Scan(&c.AgentID, &c.Version, &c.FirstSeen); err != nil {
			return nil, fmt.Errorf("scan agent version change: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
