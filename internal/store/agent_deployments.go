package store

import (
	"context"
	"fmt"
	"time"
)

// AgentDeployment is one attempt to push the agent onto a host — see
// schema.sql's agent_deployments table.
type AgentDeployment struct {
	ID         string     `json:"id"`
	Target     string     `json:"target"`
	Hostname   string     `json:"hostname"`
	Site       string     `json:"site"`
	Credential string     `json:"credential"`
	Status     string     `json:"status"` // "running" | "succeeded" | "failed"
	Error      string     `json:"error"`
	Output     string     `json:"output"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	StartedBy  string     `json:"started_by"`
}

func (s *Store) StartAgentDeployment(ctx context.Context, d AgentDeployment) error {
	const q = `
INSERT INTO agent_deployments (id, target, hostname, site, credential, status, started_by)
VALUES ($1, $2, $3, $4, $5, 'running', $6)`
	if _, err := s.pool.Exec(ctx, q, d.ID, d.Target, d.Hostname, d.Site, d.Credential, d.StartedBy); err != nil {
		return fmt.Errorf("start agent deployment: %w", err)
	}
	return nil
}

// FinishAgentDeployment records the outcome. Output is truncated by the
// caller — a full install transcript can be long, and this table is a
// history view, not a log store.
func (s *Store) FinishAgentDeployment(ctx context.Context, id, status, errMsg, output string) error {
	const q = `UPDATE agent_deployments SET status = $2, error = $3, output = $4, finished_at = now() WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id, status, errMsg, output); err != nil {
		return fmt.Errorf("finish agent deployment: %w", err)
	}
	return nil
}

func (s *Store) ListAgentDeployments(ctx context.Context, limit int) ([]AgentDeployment, error) {
	const q = `
SELECT id, target, hostname, site, credential, status, error, output, started_at, finished_at, started_by
FROM agent_deployments ORDER BY started_at DESC LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("list agent deployments: %w", err)
	}
	defer rows.Close()
	var out []AgentDeployment
	for rows.Next() {
		var d AgentDeployment
		if err := rows.Scan(&d.ID, &d.Target, &d.Hostname, &d.Site, &d.Credential, &d.Status,
			&d.Error, &d.Output, &d.StartedAt, &d.FinishedAt, &d.StartedBy); err != nil {
			return nil, fmt.Errorf("scan agent deployment: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
