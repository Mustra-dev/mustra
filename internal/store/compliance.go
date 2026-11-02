package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Compliance results, one row per (endpoint, check).
//
// Stored as results rather than as a score: a score is derivable from
// results and results are not derivable from a score, and the question
// people actually ask is "which machines fail this check", not "what is
// our number".

type ComplianceResult struct {
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	PolicyID  string    `json:"policy_id"`
	CheckID   string    `json:"check_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	State     string    `json:"state"` // pass | fail | unknown
	Detail    string    `json:"detail"`
	CheckedAt time.Time `json:"checked_at"`
}

// ReplaceComplianceResults overwrites one endpoint's results for one
// policy. Replacing rather than appending is what makes a fixed check stop
// being reported, instead of lingering from an older run.
func (s *Store) ReplaceComplianceResults(ctx context.Context, agentID, policyID string, rows []ComplianceResult) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace compliance results: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`DELETE FROM compliance_results WHERE agent_id = $1 AND policy_id = $2`, agentID, policyID); err != nil {
		return fmt.Errorf("clear compliance results: %w", err)
	}
	for _, r := range rows {
		if _, err := tx.Exec(ctx, `
INSERT INTO compliance_results (agent_id, policy_id, check_id, title, severity, state, detail, checked_at)
VALUES ($1,$2,$3,$4,$5,$6,$7, now())`,
			agentID, policyID, r.CheckID, r.Title, r.Severity, r.State, r.Detail); err != nil {
			return fmt.Errorf("insert compliance result: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ListComplianceResults(ctx context.Context) ([]ComplianceResult, error) {
	rows, err := s.pool.Query(ctx, `
SELECT c.agent_id, coalesce(a.hostname,''), c.policy_id, c.check_id, c.title,
       c.severity, c.state, c.detail, c.checked_at
FROM compliance_results c LEFT JOIN agents a ON a.agent_id = c.agent_id
ORDER BY c.state, c.severity, c.check_id`)
	if err != nil {
		return nil, fmt.Errorf("list compliance results: %w", err)
	}
	defer rows.Close()
	var out []ComplianceResult
	for rows.Next() {
		var r ComplianceResult
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.PolicyID, &r.CheckID, &r.Title,
			&r.Severity, &r.State, &r.Detail, &r.CheckedAt); err != nil {
			return nil, fmt.Errorf("scan compliance result: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CompliancePolicy is a named set of checks. Imported policies keep their
// source so it is always clear where a check came from.
type CompliancePolicy struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	OS     string `json:"os"`
	Source string `json:"source"` // builtin | imported
	// Checks is omitted when empty, which is how the list endpoint drops
	// it: the policies list shows a name, a platform and a count, and
	// shipping every CIS rule of every policy to draw that was 2.6 MB per
	// page load.
	Checks     json.RawMessage `json:"checks,omitempty"`
	CheckCount int             `json:"check_count"`
	CreatedAt  time.Time       `json:"created_at"`
	CreatedBy  string          `json:"created_by"`
}

func (s *Store) ListCompliancePolicies(ctx context.Context) ([]CompliancePolicy, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, name, os, source, checks, created_at, created_by
FROM compliance_policies ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list compliance policies: %w", err)
	}
	defer rows.Close()
	var out []CompliancePolicy
	for rows.Next() {
		var p CompliancePolicy
		var checks []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.OS, &p.Source, &checks, &p.CreatedAt, &p.CreatedBy); err != nil {
			return nil, fmt.Errorf("scan compliance policy: %w", err)
		}
		var parsed []map[string]any
		_ = json.Unmarshal(checks, &parsed)
		p.CheckCount = len(parsed)
		// Deliberately not p.Checks: a listing wants the count, and the
		// rules themselves are fetched with the policy when something
		// actually needs to run or edit them.
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetCompliancePolicy(ctx context.Context, id string) (*CompliancePolicy, error) {
	var p CompliancePolicy
	var checks []byte
	err := s.pool.QueryRow(ctx, `
SELECT id, name, os, source, checks, created_at, created_by FROM compliance_policies WHERE id = $1`, id).
		Scan(&p.ID, &p.Name, &p.OS, &p.Source, &checks, &p.CreatedAt, &p.CreatedBy)
	if err != nil {
		return nil, nil
	}
	p.Checks = checks
	return &p, nil
}

func (s *Store) UpsertCompliancePolicy(ctx context.Context, p CompliancePolicy) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO compliance_policies (id, name, os, source, checks, created_by) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, os = EXCLUDED.os,
  source = EXCLUDED.source, checks = EXCLUDED.checks`,
		p.ID, p.Name, p.OS, p.Source, []byte(p.Checks), p.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert compliance policy: %w", err)
	}
	return nil
}

func (s *Store) DeleteCompliancePolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM compliance_policies WHERE id = $1`, id)
	return err
}

// ComplianceScore is one endpoint's hardening score against one policy on
// one day.
type ComplianceScore struct {
	AgentID  string    `json:"agent_id"`
	PolicyID string    `json:"policy_id"`
	Day      time.Time `json:"day"`
	Score    float64   `json:"score"`
	Pass     int       `json:"pass"`
	Fail     int       `json:"fail"`
	Unknown  int       `json:"unknown"`
}

func (s *Store) RecordComplianceScore(ctx context.Context, c ComplianceScore) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO compliance_scores (agent_id, policy_id, day, score, pass, fail, unknown)
		VALUES ($1,$2,current_date,$3,$4,$5,$6)
		ON CONFLICT (agent_id, policy_id, day) DO UPDATE SET score = $3, pass = $4, fail = $5, unknown = $6`,
		c.AgentID, c.PolicyID, c.Score, c.Pass, c.Fail, c.Unknown)
	if err != nil {
		return fmt.Errorf("record compliance score: %w", err)
	}
	return nil
}

// ComplianceScoreHistory returns the last days of scores, oldest first.
func (s *Store) ComplianceScoreHistory(ctx context.Context, days int) ([]ComplianceScore, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, policy_id, day, score, pass, fail, unknown FROM compliance_scores
		WHERE day > current_date - $1::int ORDER BY day`, days)
	if err != nil {
		return nil, fmt.Errorf("compliance score history: %w", err)
	}
	defer rows.Close()
	var out []ComplianceScore
	for rows.Next() {
		var c ComplianceScore
		if err := rows.Scan(&c.AgentID, &c.PolicyID, &c.Day, &c.Score, &c.Pass, &c.Fail, &c.Unknown); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ComplianceResultsFor returns one endpoint's results, optionally for one
// policy, worst first.
func (s *Store) ComplianceResultsFor(ctx context.Context, agentID, policyID string) ([]ComplianceResult, error) {
	rows, err := s.pool.Query(ctx, `
SELECT c.agent_id, coalesce(a.hostname,''), c.policy_id, c.check_id, c.title, c.severity, c.state, c.detail, c.checked_at
FROM compliance_results c LEFT JOIN agents a ON a.agent_id = c.agent_id
WHERE c.agent_id = $1 AND ($2 = '' OR c.policy_id = $2)
ORDER BY CASE c.state WHEN 'fail' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END,
         CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, c.check_id`, agentID, policyID)
	if err != nil {
		return nil, fmt.Errorf("compliance results for endpoint: %w", err)
	}
	defer rows.Close()
	var out []ComplianceResult
	for rows.Next() {
		var r ComplianceResult
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.PolicyID, &r.CheckID, &r.Title, &r.Severity, &r.State, &r.Detail, &r.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
