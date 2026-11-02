package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Playbooks, their runs, and the per-endpoint per-step results a run
// produces. See schema.sql for why steps are JSON and why a run copies
// them rather than referencing the playbook.

type Playbook struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OS          string `json:"os"`
	GroupID     string `json:"group_id"`
	GroupName   string `json:"group_name,omitempty"`
	// See EnforcePolicy.GroupDeleted: a playbook that lost its group targets
	// nothing rather than everything.
	GroupDeleted bool            `json:"group_deleted"`
	Steps        json.RawMessage `json:"steps"`
	StepCount    int             `json:"step_count"`
	Enabled      bool            `json:"enabled"`

	ScheduleKind string     `json:"schedule_kind"`
	TimeOfDay    string     `json:"time_of_day"`
	Weekday      *int       `json:"weekday,omitempty"`
	NextRunAt    *time.Time `json:"next_run_at,omitempty"`
	LastRunAt    *time.Time `json:"last_run_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

type PlaybookRun struct {
	ID          string          `json:"id"`
	PlaybookID  string          `json:"playbook_id"`
	Name        string          `json:"name"`
	Steps       json.RawMessage `json:"steps"`
	TargetDesc  string          `json:"target_desc"`
	AgentCount  int             `json:"agent_count"`
	Status      string          `json:"status"`
	TriggeredBy string          `json:"triggered_by"`
	StartedAt   time.Time       `json:"started_at"`
	FinishedAt  *time.Time      `json:"finished_at"`
}

type PlaybookStepResult struct {
	RunID      string     `json:"run_id"`
	AgentID    string     `json:"agent_id"`
	Hostname   string     `json:"hostname"`
	StepIndex  int        `json:"step_index"`
	StepName   string     `json:"step_name"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	Detail     string     `json:"detail"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

const playbookColumns = `p.id, p.name, p.description, p.os, coalesce(p.group_id,''), coalesce(g.name,''),
       p.group_deleted, p.steps, p.enabled, p.schedule_kind, p.time_of_day, p.weekday, p.next_run_at, p.last_run_at,
       p.created_at, p.created_by, p.updated_at, p.updated_by`

func scanPlaybook(scan func(dest ...any) error) (Playbook, error) {
	var p Playbook
	var steps []byte
	err := scan(&p.ID, &p.Name, &p.Description, &p.OS, &p.GroupID, &p.GroupName,
		&p.GroupDeleted, &steps, &p.Enabled, &p.ScheduleKind, &p.TimeOfDay, &p.Weekday, &p.NextRunAt, &p.LastRunAt,
		&p.CreatedAt, &p.CreatedBy, &p.UpdatedAt, &p.UpdatedBy)
	if err != nil {
		return p, err
	}
	p.Steps = steps
	var parsed []map[string]any
	_ = json.Unmarshal(steps, &parsed)
	p.StepCount = len(parsed)
	return p, nil
}

func (s *Store) ListPlaybooks(ctx context.Context) ([]Playbook, error) {
	rows, err := s.pool.Query(ctx, `
SELECT `+playbookColumns+`
FROM playbooks p LEFT JOIN computer_groups g ON g.id = p.group_id
ORDER BY lower(p.name)`)
	if err != nil {
		return nil, fmt.Errorf("list playbooks: %w", err)
	}
	defer rows.Close()
	out := []Playbook{}
	for rows.Next() {
		p, err := scanPlaybook(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan playbook: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPlaybook(ctx context.Context, id string) (*Playbook, error) {
	row := s.pool.QueryRow(ctx, `
SELECT `+playbookColumns+`
FROM playbooks p LEFT JOIN computer_groups g ON g.id = p.group_id WHERE p.id = $1`, id)
	p, err := scanPlaybook(row.Scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		// Distinguished from "not found" deliberately: a connection reset
		// read as absence made a save audit itself as a create, and made a
		// playbook step report "no such playbook" for what was a database
		// problem.
		return nil, fmt.Errorf("get playbook: %w", err)
	}
	return &p, nil
}

func (s *Store) UpsertPlaybook(ctx context.Context, p Playbook, nextRun *time.Time) error {
	var group *string
	if p.GroupID != "" {
		group = &p.GroupID
	}
	steps := []byte(p.Steps)
	if len(steps) == 0 {
		steps = []byte("[]")
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO playbooks (id, name, description, os, group_id, steps, enabled,
                       schedule_kind, time_of_day, weekday, next_run_at, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, os = EXCLUDED.os,
  group_id = EXCLUDED.group_id, steps = EXCLUDED.steps, enabled = EXCLUDED.enabled,
  schedule_kind = EXCLUDED.schedule_kind, time_of_day = EXCLUDED.time_of_day,
  weekday = EXCLUDED.weekday, next_run_at = EXCLUDED.next_run_at,
  updated_at = now(), updated_by = EXCLUDED.updated_by,
  group_deleted = false`,
		p.ID, p.Name, p.Description, p.OS, group, steps, p.Enabled,
		p.ScheduleKind, p.TimeOfDay, p.Weekday, nextRun, p.UpdatedBy)
	if err != nil {
		return fmt.Errorf("upsert playbook: %w", err)
	}
	return nil
}

func (s *Store) DeletePlaybook(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM playbooks WHERE id = $1`, id)
	return err
}

// DuePlaybooks returns the enabled playbooks whose next run has arrived.
func (s *Store) DuePlaybooks(ctx context.Context, now time.Time) ([]Playbook, error) {
	rows, err := s.pool.Query(ctx, `
SELECT `+playbookColumns+`
FROM playbooks p LEFT JOIN computer_groups g ON g.id = p.group_id
WHERE p.enabled AND p.next_run_at IS NOT NULL AND p.next_run_at <= $1`, now)
	if err != nil {
		return nil, fmt.Errorf("list due playbooks: %w", err)
	}
	defer rows.Close()
	out := []Playbook{}
	for rows.Next() {
		p, err := scanPlaybook(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan due playbook: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) MarkPlaybookRun(ctx context.Context, id string, ranAt time.Time, next *time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE playbooks SET last_run_at = $2, next_run_at = $3 WHERE id = $1`, id, ranAt, next)
	return err
}

func (s *Store) StartPlaybookRun(ctx context.Context, r PlaybookRun) error {
	steps := []byte(r.Steps)
	if len(steps) == 0 {
		steps = []byte("[]")
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO playbook_runs (id, playbook_id, name, steps, target_desc, agent_count, triggered_by)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		r.ID, nullable(r.PlaybookID), r.Name, steps, r.TargetDesc, r.AgentCount, r.TriggeredBy)
	if err != nil {
		return fmt.Errorf("start playbook run: %w", err)
	}
	return nil
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *Store) FinishPlaybookRun(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE playbook_runs SET status = $2, finished_at = now() WHERE id = $1`, id, status)
	return err
}

// SetPlaybookRunStatus changes a run's status without closing it. A run
// parked at an approval gate is not finished — writing finished_at would
// make it look like one, and every count of "what is still going" would be
// wrong from then on.
func (s *Store) SetPlaybookRunStatus(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE playbook_runs SET status = $2 WHERE id = $1`, id, status)
	return err
}

func (s *Store) ListPlaybookRuns(ctx context.Context, limit int) ([]PlaybookRun, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
SELECT id, coalesce(playbook_id,''), name, steps, target_desc, agent_count, status,
       triggered_by, started_at, finished_at
FROM playbook_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list playbook runs: %w", err)
	}
	defer rows.Close()
	out := []PlaybookRun{}
	for rows.Next() {
		var r PlaybookRun
		var steps []byte
		if err := rows.Scan(&r.ID, &r.PlaybookID, &r.Name, &steps, &r.TargetDesc,
			&r.AgentCount, &r.Status, &r.TriggeredBy, &r.StartedAt, &r.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan playbook run: %w", err)
		}
		r.Steps = steps
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetPlaybookRun(ctx context.Context, id string) (*PlaybookRun, error) {
	var r PlaybookRun
	var steps []byte
	err := s.pool.QueryRow(ctx, `
SELECT id, coalesce(playbook_id,''), name, steps, target_desc, agent_count, status,
       triggered_by, started_at, finished_at
FROM playbook_runs WHERE id = $1`, id).
		Scan(&r.ID, &r.PlaybookID, &r.Name, &steps, &r.TargetDesc,
			&r.AgentCount, &r.Status, &r.TriggeredBy, &r.StartedAt, &r.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		// Distinguished from "not found" deliberately: a connection reset
		// read as absence made a save audit itself as a create, and made a
		// playbook step report "no such playbook run" for what was a database
		// problem.
		return nil, fmt.Errorf("get playbook run: %w", err)
	}
	r.Steps = steps
	return &r, nil
}

// StartPlaybookStep records a step as running. Upsert rather than insert:
// a step re-entered after a server restart should overwrite its own stale
// "running" row rather than collide with it.
func (s *Store) StartPlaybookStep(ctx context.Context, r PlaybookStepResult) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO playbook_step_results (run_id, agent_id, hostname, step_index, step_name, kind, status, started_at)
VALUES ($1,$2,$3,$4,$5,$6,'running', now())
ON CONFLICT (run_id, agent_id, step_index) DO UPDATE SET
  step_name = EXCLUDED.step_name, kind = EXCLUDED.kind, status = 'running',
  detail = '', started_at = now(), finished_at = NULL`,
		r.RunID, r.AgentID, r.Hostname, r.StepIndex, r.StepName, r.Kind)
	if err != nil {
		return fmt.Errorf("start playbook step: %w", err)
	}
	return nil
}

func (s *Store) FinishPlaybookStep(ctx context.Context, runID, agentID string, index int, status, detail string) error {
	if len(detail) > 8000 {
		// Rune boundary: invalid UTF-8 is rejected by Postgres, and the
		// caller only logs the error — leaving the step "running" for ever
		// in the live view of a run that actually finished.
		cut := detail[:8000]
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
		detail = cut + "\n… (truncated)"
	}
	_, err := s.pool.Exec(ctx, `
UPDATE playbook_step_results SET status = $4, detail = $5, finished_at = now()
WHERE run_id = $1 AND agent_id = $2 AND step_index = $3`, runID, agentID, index, status, detail)
	return err
}

// RecordSkippedPlaybookStep writes a step that never ran, with the reason.
// A skipped step has to be visible: "why did nobody get the reboot" is
// answered by the row saying the check before it failed, and not at all by
// its absence.
func (s *Store) RecordSkippedPlaybookStep(ctx context.Context, r PlaybookStepResult, reason string) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO playbook_step_results (run_id, agent_id, hostname, step_index, step_name, kind, status, detail, finished_at)
VALUES ($1,$2,$3,$4,$5,$6,'skipped',$7, now())
ON CONFLICT (run_id, agent_id, step_index) DO UPDATE SET
  status = 'skipped', detail = EXCLUDED.detail, finished_at = now()`,
		r.RunID, r.AgentID, r.Hostname, r.StepIndex, r.StepName, r.Kind, reason)
	return err
}

func (s *Store) ListPlaybookStepResults(ctx context.Context, runID string) ([]PlaybookStepResult, error) {
	rows, err := s.pool.Query(ctx, `
SELECT run_id, agent_id, hostname, step_index, step_name, kind, status, detail, started_at, finished_at
FROM playbook_step_results WHERE run_id = $1 ORDER BY lower(hostname), step_index`, runID)
	if err != nil {
		return nil, fmt.Errorf("list playbook step results: %w", err)
	}
	defer rows.Close()
	out := []PlaybookStepResult{}
	for rows.Next() {
		var r PlaybookStepResult
		if err := rows.Scan(&r.RunID, &r.AgentID, &r.Hostname, &r.StepIndex, &r.StepName,
			&r.Kind, &r.Status, &r.Detail, &r.StartedAt, &r.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan playbook step result: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
