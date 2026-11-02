package store

import (
	"context"
	"fmt"
	"time"
)

// RootTrust is one endpoint's state for one pushed root certificate.
type RootTrust struct {
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Fingerprint string    `json:"fingerprint"`
	State       string    `json:"state"`
	Via         string    `json:"via"`
	Detail      string    `json:"detail"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (s *Store) SetRootTrust(ctx context.Context, agentID, fingerprint, state, via, detail string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO root_trust (agent_id, fingerprint, state, via, detail, updated_at)
		VALUES ($1,$2,$3,$4,$5, now())
		ON CONFLICT (agent_id, fingerprint) DO UPDATE SET state = $3, via = $4, detail = $5, updated_at = now()`,
		agentID, fingerprint, state, via, detail)
	if err != nil {
		return fmt.Errorf("set root trust: %w", err)
	}
	return nil
}

// ListRootTrust returns every endpoint's state for one root, endpoints
// without a row included with an empty state.
func (s *Store) ListRootTrust(ctx context.Context, fingerprint string) ([]RootTrust, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.agent_id, a.hostname, a.os, COALESCE(t.state, ''), COALESCE(t.via, ''), COALESCE(t.detail, ''),
			COALESCE(t.updated_at, 'epoch'::timestamptz)
		FROM agents a LEFT JOIN root_trust t ON t.agent_id = a.agent_id AND t.fingerprint = $1
		ORDER BY lower(a.hostname)`, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("list root trust: %w", err)
	}
	defer rows.Close()
	out := []RootTrust{}
	for rows.Next() {
		r := RootTrust{Fingerprint: fingerprint}
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.OS, &r.State, &r.Via, &r.Detail, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan root trust: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
