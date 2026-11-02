package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// PatchSchedule is one scheduled or recurring patch-deployment job — see
// schema.sql for the field semantics.
type PatchSchedule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TargetOS    string `json:"target_os"`
	TargetSite  string `json:"target_site"`
	TargetAgent string `json:"target_agent"`
	// TargetVulnID, when set, means this schedule came from a Risk &
	// Compliance CVE's "Schedule" button — resolved at fire time to
	// whichever online agents currently carry this vuln_id, instead of a
	// frozen host list. Mutually exclusive with TargetOS/TargetSite/
	// TargetAgent in practice (the UI only ever sets one kind of target).
	TargetVulnID string `json:"target_vuln_id"`
	// TargetAgents freezes the schedule to a named set of endpoints
	// ("Specific endpoints" in the console). Like every other target it is
	// resolved at fire time against the online fleet, so a machine that is
	// off that night is skipped rather than failing the run. Empty means
	// the fields above decide.
	TargetAgents []string   `json:"target_agents"`
	Kind         string     `json:"kind"` // "once" | "daily" | "weekly"
	RunAt        *time.Time `json:"run_at"`
	TimeOfDay    string     `json:"time_of_day"` // "HH:MM" UTC
	Weekday      *int       `json:"weekday"`     // 0 (Sunday) - 6
	Enabled      bool       `json:"enabled"`
	LastRunAt    *time.Time `json:"last_run_at"`
	NextRunAt    *time.Time `json:"next_run_at"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    string     `json:"created_by"`
}

const patchScheduleColumns = `id, name, target_os, target_site, target_agent, target_agents, target_vuln_id, kind, run_at, time_of_day, weekday, enabled, last_run_at, next_run_at, created_at, created_by`

func scanPatchSchedule(row pgx.Row) (*PatchSchedule, error) {
	var s PatchSchedule
	if err := row.Scan(&s.ID, &s.Name, &s.TargetOS, &s.TargetSite, &s.TargetAgent, &s.TargetAgents, &s.TargetVulnID, &s.Kind, &s.RunAt, &s.TimeOfDay, &s.Weekday, &s.Enabled, &s.LastRunAt, &s.NextRunAt, &s.CreatedAt, &s.CreatedBy); err != nil {
		return nil, err
	}
	if s.TargetAgents == nil {
		s.TargetAgents = []string{}
	}
	return &s, nil
}

// CreatePatchSchedule inserts a schedule. nextRunAt should already be
// computed by the caller (see server/patch_scheduler.go's computeNextRun)
// so the store layer doesn't need to know timezone/cadence rules.
func (s *Store) CreatePatchSchedule(ctx context.Context, sched PatchSchedule) (*PatchSchedule, error) {
	// target_agents is NOT NULL: a nil slice would be encoded as NULL.
	if sched.TargetAgents == nil {
		sched.TargetAgents = []string{}
	}
	const q = `
INSERT INTO patch_schedules (id, name, target_os, target_site, target_agent, target_agents, target_vuln_id, kind, run_at, time_of_day, weekday, enabled, next_run_at, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING ` + patchScheduleColumns
	row := s.pool.QueryRow(ctx, q, sched.ID, sched.Name, sched.TargetOS, sched.TargetSite, sched.TargetAgent,
		sched.TargetAgents, sched.TargetVulnID,
		sched.Kind, sched.RunAt, sched.TimeOfDay, sched.Weekday, sched.Enabled, sched.NextRunAt, sched.CreatedBy)
	out, err := scanPatchSchedule(row)
	if err != nil {
		return nil, fmt.Errorf("create patch schedule: %w", err)
	}
	return out, nil
}

func (s *Store) ListPatchSchedules(ctx context.Context) ([]PatchSchedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+patchScheduleColumns+` FROM patch_schedules ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list patch schedules: %w", err)
	}
	defer rows.Close()
	out := []PatchSchedule{}
	for rows.Next() {
		sc, err := scanPatchSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan patch schedule: %w", err)
		}
		out = append(out, *sc)
	}
	return out, rows.Err()
}

// DuePatchSchedules returns every enabled schedule whose next_run_at has
// arrived — what the scheduler loop polls for, once a minute.
func (s *Store) DuePatchSchedules(ctx context.Context, now time.Time) ([]PatchSchedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+patchScheduleColumns+` FROM patch_schedules WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1`, now)
	if err != nil {
		return nil, fmt.Errorf("due patch schedules: %w", err)
	}
	defer rows.Close()
	var out []PatchSchedule
	for rows.Next() {
		sc, err := scanPatchSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan patch schedule: %w", err)
		}
		out = append(out, *sc)
	}
	return out, rows.Err()
}

// GetPatchSchedule reads one schedule, or (nil, nil) when there is no such
// row — a genuine database error is returned rather than folded into "not
// found", which is a distinction the enable path depends on.
func (s *Store) GetPatchSchedule(ctx context.Context, id string) (*PatchSchedule, error) {
	all, err := s.ListPatchSchedules(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, nil
}

// SetPatchScheduleEnabled flips the flag and sets the next fire time with
// it.
//
// Enabling used to touch nothing else, and next_run_at is what the
// scheduler selects on: `enabled AND next_run_at <= now`. So a daily 03:00
// schedule paused on Monday for a change freeze kept Tuesday 03:00 in that
// column, and re-enabling it on Friday afternoon fired apply_patches at
// every matching endpoint within the minute — mid-workday, with nobody
// having asked for it.
//
// The inverse was just as bad: a fired "once" schedule has next_run_at
// NULL, so re-enabling it showed an enabled schedule in the console that
// the scheduler's IS NOT NULL clause could never select. It looked armed
// and was inert.
//
// nextRunAt nil means "leave it unset", which is correct when disabling and
// when a "once" schedule has already run.
func (s *Store) SetPatchScheduleEnabled(ctx context.Context, id string, enabled bool, nextRunAt *time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE patch_schedules SET enabled = $2, next_run_at = $3 WHERE id = $1`,
		id, enabled, nextRunAt)
	if err != nil {
		return fmt.Errorf("set patch schedule enabled: %w", err)
	}
	return nil
}

func (s *Store) DeletePatchSchedule(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM patch_schedules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete patch schedule: %w", err)
	}
	return nil
}

// MarkPatchScheduleRun records that a schedule just fired: last_run_at is
// set to now, next_run_at advances to the caller-computed next occurrence
// (nil for a 'once' schedule, which also gets disabled — it has nothing
// left to do).
func (s *Store) MarkPatchScheduleRun(ctx context.Context, id string, ranAt time.Time, nextRunAt *time.Time) error {
	const q = `UPDATE patch_schedules SET last_run_at = $2, next_run_at = $3, enabled = (enabled AND $3 IS NOT NULL) WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id, ranAt, nextRunAt); err != nil {
		return fmt.Errorf("mark patch schedule run: %w", err)
	}
	return nil
}

// PatchJobRun is one deployment, scheduled or ad hoc: a single identified
// event that targeted some set of devices. Every way of applying patches —
// a schedule firing, a bulk deploy, a one-off apply to a single device, a
// Self Service install — creates one, so the Deployments view and the
// Patches tab's history can show them all with an ID that leads to who ran
// it and what happened per device.
type PatchJobRun struct {
	ID           string    `json:"id"`
	ScheduleID   string    `json:"schedule_id,omitempty"`
	ScheduleName string    `json:"schedule_name"`
	TargetDesc   string    `json:"target_desc"`
	AgentCount   int       `json:"agent_count"`
	TriggeredBy  string    `json:"triggered_by"`
	StartedAt    time.Time `json:"started_at"`
	// NotifyOnFinish asks for one console notification when the run's last
	// job reaches a final state (ClaimFinishedRun).
	NotifyOnFinish bool `json:"notify_on_finish,omitempty"`
}

// GetPatchJobRun loads one deployment by ID. Returns nil when there is no
// such run.
func (s *Store) GetPatchJobRun(ctx context.Context, id string) (*PatchJobRun, error) {
	var r PatchJobRun
	err := s.pool.QueryRow(ctx, `
SELECT id, coalesce(schedule_id, ''), schedule_name, target_desc, agent_count, triggered_by, started_at
FROM patch_job_runs WHERE id = $1`, id).Scan(&r.ID, &r.ScheduleID, &r.ScheduleName,
		&r.TargetDesc, &r.AgentCount, &r.TriggeredBy, &r.StartedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get patch job run: %w", err)
	}
	return &r, nil
}

func (s *Store) RecordPatchJobRun(ctx context.Context, run PatchJobRun) error {
	const q = `
INSERT INTO patch_job_runs (id, schedule_id, schedule_name, target_desc, agent_count, triggered_by)
VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6)`
	if _, err := s.pool.Exec(ctx, q, run.ID, run.ScheduleID, run.ScheduleName, run.TargetDesc, run.AgentCount, run.TriggeredBy); err != nil {
		return fmt.Errorf("record patch job run: %w", err)
	}
	return nil
}

func (s *Store) ListPatchJobRuns(ctx context.Context, limit int) ([]PatchJobRun, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, coalesce(schedule_id, ''), schedule_name, target_desc, agent_count, triggered_by, started_at
FROM patch_job_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list patch job runs: %w", err)
	}
	defer rows.Close()
	var out []PatchJobRun
	for rows.Next() {
		var r PatchJobRun
		if err := rows.Scan(&r.ID, &r.ScheduleID, &r.ScheduleName, &r.TargetDesc, &r.AgentCount, &r.TriggeredBy, &r.StartedAt); err != nil {
			return nil, fmt.Errorf("scan patch job run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
