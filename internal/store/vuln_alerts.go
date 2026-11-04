package store

import (
	"context"
	"fmt"
	"time"
)

// VulnAlertKey is one finding on one endpoint.
type VulnAlertKey struct {
	AgentID string
	VulnID  string
}

// ListVulnAlerts returns the highest tier each finding has been announced at.
func (s *Store) ListVulnAlerts(ctx context.Context) (map[VulnAlertKey]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, vuln_id, tier_rank FROM vuln_alerts`)
	if err != nil {
		return nil, fmt.Errorf("list vuln alerts: %w", err)
	}
	defer rows.Close()
	out := map[VulnAlertKey]int{}
	for rows.Next() {
		var k VulnAlertKey
		var rank int
		if err := rows.Scan(&k.AgentID, &k.VulnID, &rank); err != nil {
			return nil, fmt.Errorf("scan vuln alert: %w", err)
		}
		out[k] = rank
	}
	return out, rows.Err()
}

// RecordVulnAlerts marks findings as present now and announced at a tier. A
// tier never goes down: a finding that fell and rose again is not news.
func (s *Store) RecordVulnAlerts(ctx context.Context, marks map[VulnAlertKey]int) error {
	if len(marks) == 0 {
		return nil
	}
	agents, vulns, ranks := make([]string, 0, len(marks)), make([]string, 0, len(marks)), make([]int32, 0, len(marks))
	for k, rank := range marks {
		agents, vulns, ranks = append(agents, k.AgentID), append(vulns, k.VulnID), append(ranks, int32(rank))
	}
	const q = `
INSERT INTO vuln_alerts (agent_id, vuln_id, tier_rank, last_seen)
SELECT agent_id, vuln_id, tier_rank, now() FROM unnest($1::text[], $2::text[], $3::int[]) AS m(agent_id, vuln_id, tier_rank)
ON CONFLICT (agent_id, vuln_id) DO UPDATE
   SET tier_rank = GREATEST(vuln_alerts.tier_rank, EXCLUDED.tier_rank), last_seen = now()`
	if _, err := s.pool.Exec(ctx, q, agents, vulns, ranks); err != nil {
		return fmt.Errorf("record vuln alerts: %w", err)
	}
	return nil
}

// PruneVulnAlerts forgets findings not seen since before.
func (s *Store) PruneVulnAlerts(ctx context.Context, before time.Time) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM vuln_alerts WHERE last_seen < $1`, before); err != nil {
		return fmt.Errorf("prune vuln alerts: %w", err)
	}
	return nil
}
