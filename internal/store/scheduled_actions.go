package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// A scheduled action runs a package on a cadence.
//
// Deliberately a schedule over a package rather than over a raw command:
// the package already carries per-OS commands, applicability, a timeout, an
// expiry and its parameters. A schedule that took a command string instead
// would be a second, worse way to define the same thing — and the one
// nobody audits.
type ScheduledAction struct {
	RevisionID   string            `json:"revision_id,omitempty"`
	FollowLatest bool              `json:"follow_latest"`
	ID           string            `json:"id"`
	Name         string            `json:"name" api:"required"`
	PackageID    string            `json:"package_id" api:"required"`
	Operation    string            `json:"operation"`
	Parameters   map[string]string `json:"parameters"`

	TargetOS    string `json:"target_os"`
	TargetSite  string `json:"target_site"`
	TargetAgent string `json:"target_agent"`
	// Hand-picked endpoints and computer groups. Groups are resolved each
	// time the schedule fires, so a machine that joins later is included.
	// Either one set means only these; both empty falls back to the
	// OS/site/agent filters above.
	AgentIDs []string `json:"agent_ids"`
	GroupIDs []string `json:"group_ids"`

	// The options a deployment from the Deploy window carries.
	AllowReboot     bool `json:"allow_reboot"`
	ForceRemove     bool `json:"force_remove"`
	ExpireSeconds   int  `json:"expire_seconds"`
	OverrideWindows bool `json:"override_windows"`
	// NotifyMessageID is an end-user notification shown on each target as
	// the run starts; NotifyOnFinish raises a console notification when
	// the run's last job finishes.
	NotifyMessageID string `json:"notify_message_id"`
	NotifyOnFinish  bool   `json:"notify_on_finish"`

	Kind      string     `json:"kind"` // once | daily | weekly
	RunAt     *time.Time `json:"run_at,omitempty"`
	TimeOfDay string     `json:"time_of_day"`
	Weekday   *int       `json:"weekday,omitempty"`

	Enabled   bool       `json:"enabled"`
	LastRunAt *time.Time `json:"last_run_at,omitempty" api:"readonly"`
	NextRunAt *time.Time `json:"next_run_at,omitempty" api:"readonly"`
	CreatedAt time.Time  `json:"created_at" api:"readonly"`
	CreatedBy string     `json:"created_by" api:"readonly"`
}

const scheduledActionColumns = `id, name, package_id, operation, parameters,
       target_os, target_site, target_agent, kind, run_at, time_of_day, weekday,
       enabled, last_run_at, next_run_at, created_at, created_by, revision_id, follow_latest,
       agent_ids, group_ids, allow_reboot, force_remove, expire_seconds, override_windows,
       notify_message_id, notify_on_finish`

func scanScheduledAction(row pgx.Row) (*ScheduledAction, error) {
	var a ScheduledAction
	var params []byte
	if err := row.Scan(&a.ID, &a.Name, &a.PackageID, &a.Operation, &params,
		&a.TargetOS, &a.TargetSite, &a.TargetAgent, &a.Kind, &a.RunAt,
		&a.TimeOfDay, &a.Weekday, &a.Enabled, &a.LastRunAt, &a.NextRunAt,
		&a.CreatedAt, &a.CreatedBy, &a.RevisionID, &a.FollowLatest,
		&a.AgentIDs, &a.GroupIDs, &a.AllowReboot, &a.ForceRemove, &a.ExpireSeconds,
		&a.OverrideWindows, &a.NotifyMessageID, &a.NotifyOnFinish); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(params, &a.Parameters)
	if a.Parameters == nil {
		a.Parameters = map[string]string{}
	}
	return &a, nil
}

func (s *Store) ListScheduledActions(ctx context.Context) ([]ScheduledAction, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scheduledActionColumns+` FROM scheduled_actions ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list scheduled actions: %w", err)
	}
	defer rows.Close()
	var out []ScheduledAction
	for rows.Next() {
		a, err := scanScheduledAction(rows)
		if err != nil {
			return nil, fmt.Errorf("scan scheduled action: %w", err)
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) GetScheduledAction(ctx context.Context, id string) (*ScheduledAction, error) {
	a, err := scanScheduledAction(s.pool.QueryRow(ctx,
		`SELECT `+scheduledActionColumns+` FROM scheduled_actions WHERE id = $1`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get scheduled action: %w", err)
	}
	return a, nil
}

func (s *Store) UpsertScheduledAction(ctx context.Context, a ScheduledAction) (*ScheduledAction, error) {
	params, err := json.Marshal(a.Parameters)
	if err != nil {
		return nil, fmt.Errorf("encode scheduled action parameters: %w", err)
	}
	const q = `
INSERT INTO scheduled_actions (id, name, package_id, operation, parameters,
                               target_os, target_site, target_agent, kind, run_at,
                               time_of_day, weekday, enabled, next_run_at, created_by, revision_id, follow_latest,
                               agent_ids, group_ids, allow_reboot, force_remove, expire_seconds,
                               override_windows, notify_message_id, notify_on_finish)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, package_id = EXCLUDED.package_id,
  operation = EXCLUDED.operation, parameters = EXCLUDED.parameters,
  target_os = EXCLUDED.target_os, target_site = EXCLUDED.target_site,
  target_agent = EXCLUDED.target_agent, kind = EXCLUDED.kind,
  run_at = EXCLUDED.run_at, time_of_day = EXCLUDED.time_of_day,
  weekday = EXCLUDED.weekday, enabled = EXCLUDED.enabled,
  next_run_at = EXCLUDED.next_run_at, revision_id=EXCLUDED.revision_id, follow_latest=EXCLUDED.follow_latest,
  agent_ids = EXCLUDED.agent_ids, group_ids = EXCLUDED.group_ids,
  allow_reboot = EXCLUDED.allow_reboot, force_remove = EXCLUDED.force_remove,
  expire_seconds = EXCLUDED.expire_seconds, override_windows = EXCLUDED.override_windows,
  notify_message_id = EXCLUDED.notify_message_id, notify_on_finish = EXCLUDED.notify_on_finish
RETURNING ` + scheduledActionColumns
	out, err := scanScheduledAction(s.pool.QueryRow(ctx, q,
		a.ID, a.Name, a.PackageID, a.Operation, params,
		a.TargetOS, a.TargetSite, a.TargetAgent, a.Kind, a.RunAt,
		a.TimeOfDay, a.Weekday, a.Enabled, a.NextRunAt, a.CreatedBy, a.RevisionID, a.FollowLatest,
		nonNilStrings(a.AgentIDs), nonNilStrings(a.GroupIDs), a.AllowReboot, a.ForceRemove, a.ExpireSeconds,
		a.OverrideWindows, a.NotifyMessageID, a.NotifyOnFinish))
	if err != nil {
		return nil, fmt.Errorf("upsert scheduled action: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteScheduledAction(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM scheduled_actions WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete scheduled action: %w", err)
	}
	return nil
}

// DueScheduledActions returns enabled schedules whose next run has arrived.
func (s *Store) DueScheduledActions(ctx context.Context, now time.Time) ([]ScheduledAction, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduledActionColumns+`
FROM scheduled_actions
WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1
ORDER BY next_run_at`, now)
	if err != nil {
		return nil, fmt.Errorf("due scheduled actions: %w", err)
	}
	defer rows.Close()
	var out []ScheduledAction
	for rows.Next() {
		a, err := scanScheduledAction(rows)
		if err != nil {
			return nil, fmt.Errorf("scan due scheduled action: %w", err)
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// MarkScheduledActionRun records a firing and sets the next one. A "once"
// schedule gets a nil next run and is disabled, so it cannot fire twice if
// the server restarts between the deployment and this write.
func (s *Store) MarkScheduledActionRun(ctx context.Context, id string, ranAt time.Time, next *time.Time) error {
	const q = `
UPDATE scheduled_actions
SET last_run_at = $2, next_run_at = $3, enabled = CASE WHEN $3 IS NULL THEN false ELSE enabled END
WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id, ranAt, next); err != nil {
		return fmt.Errorf("mark scheduled action run: %w", err)
	}
	return nil
}

// nonNilStrings keeps a NOT NULL TEXT[] column from receiving SQL NULL for
// an unset slice.
func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
