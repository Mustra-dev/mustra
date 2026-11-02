package store

import (
	"context"
	"fmt"
)

// IDNumbers maps every endpoint, deployment and package text ID to its
// short number (see the num columns in schema.sql).
func (s *Store) IDNumbers(ctx context.Context) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
SELECT agent_id, num FROM agents WHERE num IS NOT NULL
UNION ALL SELECT id, num FROM patch_job_runs WHERE num IS NOT NULL
UNION ALL SELECT id, num FROM software_packages WHERE num IS NOT NULL
UNION ALL SELECT id, num FROM reveal_rules WHERE num IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("id numbers: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("id numbers: %w", err)
		}
		out[id] = n
	}
	return out, rows.Err()
}

// IDForNumber is the text ID behind a short number of one kind:
// "agent", "run" or "package". Empty when there is none.
func (s *Store) IDForNumber(ctx context.Context, kind string, n int64) (string, error) {
	q := map[string]string{
		"agent":   `SELECT agent_id FROM agents WHERE num = $1`,
		"run":     `SELECT id FROM patch_job_runs WHERE num = $1`,
		"package": `SELECT id FROM software_packages WHERE num = $1`,
		"rule":    `SELECT id FROM reveal_rules WHERE num = $1`,
	}[kind]
	if q == "" {
		return "", fmt.Errorf("unknown id kind %q", kind)
	}
	var id string
	if err := s.pool.QueryRow(ctx, q, n).Scan(&id); err != nil {
		return "", nil
	}
	return id, nil
}
