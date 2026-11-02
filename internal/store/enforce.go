package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Enforce policies and their standing per endpoint.
//
// The interesting logic here is the failure counter. Everything else is
// ordinary CRUD; the counter is what stops a broken remediation from
// becoming a permanent background load on the fleet.

// MaxRemediationAttempts is how many times in a row one setting may fail to
// remediate on one endpoint before mustra stops trying it there.
//
// Three, because the failures worth retrying are transient — a package
// manager lock, a service mid-restart, a reboot in progress — and those
// clear inside three passes. Anything still failing on the fourth is
// wrong in a way that retrying will not fix: the command is broken, the
// platform is different from what the author assumed, or something else on
// the machine is putting the setting back. All three need a person, and
// none of them is helped by running the same command every half hour
// forever.
const MaxRemediationAttempts = 3

type EnforcePolicy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OS          string `json:"os"`
	GroupID     string `json:"group_id"`
	GroupName   string `json:"group_name,omitempty"`
	// GroupDeleted means this policy was targeted at a group that no longer
	// exists. It targets nothing until somebody chooses again — see
	// schema.sql. Without it a blank group_id would read as "everything".
	GroupDeleted bool   `json:"group_deleted"`
	Mode         string `json:"mode"` // report | enforce
	Enabled      bool   `json:"enabled"`
	// Kind is '' for a hand-written policy or an internal/enforcekinds
	// kind; Config is that kind's form, from which Settings was compiled.
	Kind         string          `json:"kind"`
	Config       json.RawMessage `json:"config"`
	Settings     json.RawMessage `json:"settings"`
	SettingCount int             `json:"setting_count"`
	CreatedAt    time.Time       `json:"created_at"`
	CreatedBy    string          `json:"created_by"`
	UpdatedAt    time.Time       `json:"updated_at"`
	UpdatedBy    string          `json:"updated_by"`
	LastRunAt    *time.Time      `json:"last_run_at,omitempty"`
}

type EnforceResult struct {
	AgentID             string     `json:"agent_id"`
	Hostname            string     `json:"hostname"`
	PolicyID            string     `json:"policy_id"`
	SettingID           string     `json:"setting_id"`
	Name                string     `json:"name"`
	Severity            string     `json:"severity"`
	State               string     `json:"state"`
	Detail              string     `json:"detail"`
	Output              string     `json:"output,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	RemediationCount    int        `json:"remediation_count"`
	CheckedAt           time.Time  `json:"checked_at"`
	LastRemediatedAt    *time.Time `json:"last_remediated_at,omitempty"`
}

const enforcePolicyColumns = `p.id, p.name, p.description, p.os, coalesce(p.group_id,''),
       coalesce(g.name,''), p.group_deleted, p.mode, p.enabled, p.settings, p.created_at, p.created_by,
       p.updated_at, p.updated_by, p.last_run_at, p.kind, p.config`

func scanEnforcePolicy(scan func(dest ...any) error) (EnforcePolicy, error) {
	var p EnforcePolicy
	var settings, config []byte
	err := scan(&p.ID, &p.Name, &p.Description, &p.OS, &p.GroupID, &p.GroupName,
		&p.GroupDeleted, &p.Mode, &p.Enabled, &settings, &p.CreatedAt, &p.CreatedBy,
		&p.UpdatedAt, &p.UpdatedBy, &p.LastRunAt, &p.Kind, &config)
	if len(config) == 0 {
		config = []byte("{}")
	}
	p.Config = json.RawMessage(config)
	if err != nil {
		return p, err
	}
	p.Settings = settings
	var parsed []map[string]any
	_ = json.Unmarshal(settings, &parsed)
	p.SettingCount = len(parsed)
	return p, nil
}

func (s *Store) ListEnforcePolicies(ctx context.Context) ([]EnforcePolicy, error) {
	rows, err := s.pool.Query(ctx, `
SELECT `+enforcePolicyColumns+`
FROM enforce_policies p LEFT JOIN computer_groups g ON g.id = p.group_id
ORDER BY lower(p.name)`)
	if err != nil {
		return nil, fmt.Errorf("list enforce policies: %w", err)
	}
	defer rows.Close()
	out := []EnforcePolicy{}
	for rows.Next() {
		p, err := scanEnforcePolicy(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan enforce policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetEnforcePolicy(ctx context.Context, id string) (*EnforcePolicy, error) {
	row := s.pool.QueryRow(ctx, `
SELECT `+enforcePolicyColumns+`
FROM enforce_policies p LEFT JOIN computer_groups g ON g.id = p.group_id
WHERE p.id = $1`, id)
	p, err := scanEnforcePolicy(row.Scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		// Distinguished from "not found" deliberately: a connection reset
		// read as absence made a save audit itself as a create, and made a
		// playbook step report "no such enforce policy" for what was a database
		// problem.
		return nil, fmt.Errorf("get enforce policy: %w", err)
	}
	return &p, nil
}

func (s *Store) UpsertEnforcePolicy(ctx context.Context, p EnforcePolicy) error {
	var group *string
	if p.GroupID != "" {
		group = &p.GroupID
	}
	config := []byte(p.Config)
	if len(config) == 0 {
		config = []byte("{}")
	}
	settings := []byte(p.Settings)
	if len(settings) == 0 {
		settings = []byte("[]")
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO enforce_policies (id, name, description, os, group_id, mode, enabled, settings, created_by, updated_by, kind, config)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, os = EXCLUDED.os,
  group_id = EXCLUDED.group_id, mode = EXCLUDED.mode, enabled = EXCLUDED.enabled,
  settings = EXCLUDED.settings, updated_at = now(), updated_by = EXCLUDED.updated_by,
  kind = EXCLUDED.kind, config = EXCLUDED.config,
  -- Saving targeting is a person choosing it, which is the only thing that
  -- may clear the orphan flag.
  group_deleted = false`,
		p.ID, p.Name, p.Description, p.OS, group, p.Mode, p.Enabled, settings, p.UpdatedBy, p.Kind, config)
	if err != nil {
		return fmt.Errorf("upsert enforce policy: %w", err)
	}
	return nil
}

func (s *Store) DeleteEnforcePolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM enforce_policies WHERE id = $1`, id)
	return err
}

func (s *Store) MarkEnforcePolicyRun(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE enforce_policies SET last_run_at = now() WHERE id = $1`, id)
	return err
}

// RecordEnforceResult writes one setting's outcome and maintains the
// failure counter.
//
// The counter is kept here rather than computed by the caller so that the
// increment and the write are one statement: two servers, or one server and
// a manual "run now", cannot interleave into a count that never reaches the
// ceiling. It returns the row as stored, so the caller can see the count it
// landed on without reading back.
func (s *Store) RecordEnforceResult(ctx context.Context, r EnforceResult) (EnforceResult, error) {
	// Only 'failed' advances the counter, because only 'failed' is an
	// attempt. 'drifted' means nothing was tried (report mode), and
	// 'failing' means nothing was tried any more — counting either would
	// report "seven failures" for three attempts and four passes spent
	// deliberately not touching the machine.
	row := s.pool.QueryRow(ctx, `
INSERT INTO enforce_results (agent_id, policy_id, setting_id, name, severity, state, detail, output,
                             consecutive_failures, remediation_count, checked_at, last_remediated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,
        CASE WHEN $6 = 'failed' THEN 1 ELSE 0 END,
        CASE WHEN $6 = 'remediated' THEN 1 ELSE 0 END,
        now(),
        CASE WHEN $6 = 'remediated' THEN now() ELSE NULL END)
ON CONFLICT (agent_id, policy_id, setting_id) DO UPDATE SET
  name = EXCLUDED.name, severity = EXCLUDED.severity, state = EXCLUDED.state,
  detail = EXCLUDED.detail, output = EXCLUDED.output, checked_at = now(),
  consecutive_failures = CASE
     WHEN EXCLUDED.state = 'failed' THEN enforce_results.consecutive_failures + 1
     WHEN EXCLUDED.state IN ('compliant','remediated') THEN 0
     ELSE enforce_results.consecutive_failures END,
  remediation_count = enforce_results.remediation_count +
     CASE WHEN EXCLUDED.state = 'remediated' THEN 1 ELSE 0 END,
  last_remediated_at = CASE WHEN EXCLUDED.state = 'remediated' THEN now()
                            ELSE enforce_results.last_remediated_at END
RETURNING consecutive_failures, remediation_count`,
		r.AgentID, r.PolicyID, r.SettingID, r.Name, r.Severity, r.State, r.Detail, r.Output)
	if err := row.Scan(&r.ConsecutiveFailures, &r.RemediationCount); err != nil {
		return r, fmt.Errorf("record enforce result: %w", err)
	}
	return r, nil
}

// EnforceFailureCounts is what the dispatcher reads before sending: for one
// policy, how many times each setting has failed in a row on each endpoint.
// Keyed agent -> setting -> count.
func (s *Store) EnforceFailureCounts(ctx context.Context, policyID string) (map[string]map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
SELECT agent_id, setting_id, consecutive_failures
FROM enforce_results WHERE policy_id = $1 AND consecutive_failures > 0`, policyID)
	if err != nil {
		return nil, fmt.Errorf("read enforce failure counts: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var agent, setting string
		var count int
		if err := rows.Scan(&agent, &setting, &count); err != nil {
			return nil, fmt.Errorf("scan enforce failure count: %w", err)
		}
		if out[agent] == nil {
			out[agent] = map[string]int{}
		}
		out[agent][setting] = count
	}
	return out, rows.Err()
}

// ListEnforceResults returns every endpoint's standing, optionally for one
// policy. Ordered worst-first, because a compliance page sorted
// alphabetically buries the only rows anybody opened it to see.
func (s *Store) ListEnforceResults(ctx context.Context, policyID string) ([]EnforceResult, error) {
	rows, err := s.pool.Query(ctx, `
SELECT r.agent_id, coalesce(a.hostname,''), r.policy_id, r.setting_id, r.name, r.severity,
       r.state, r.detail, r.output, r.consecutive_failures, r.remediation_count,
       r.checked_at, r.last_remediated_at
FROM enforce_results r LEFT JOIN agents a ON a.agent_id = r.agent_id
WHERE ($1 = '' OR r.policy_id = $1)
ORDER BY CASE r.state WHEN 'failing' THEN 0 WHEN 'failed' THEN 1 WHEN 'drifted' THEN 2
                      WHEN 'unknown' THEN 3 WHEN 'remediated' THEN 4 ELSE 5 END,
         lower(coalesce(a.hostname,'')), r.name`, policyID)
	if err != nil {
		return nil, fmt.Errorf("list enforce results: %w", err)
	}
	defer rows.Close()
	out := []EnforceResult{}
	for rows.Next() {
		var r EnforceResult
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.PolicyID, &r.SettingID, &r.Name,
			&r.Severity, &r.State, &r.Detail, &r.Output, &r.ConsecutiveFailures,
			&r.RemediationCount, &r.CheckedAt, &r.LastRemediatedAt); err != nil {
			return nil, fmt.Errorf("scan enforce result: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ClearEnforceResultsForPolicy drops a policy's history. Called when its
// settings are edited: a result whose setting no longer exists, or whose
// rules have changed underneath it, is a claim about something that is no
// longer being checked.
func (s *Store) ClearEnforceResultsForPolicy(ctx context.Context, policyID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM enforce_results WHERE policy_id = $1`, policyID)
	return err
}
