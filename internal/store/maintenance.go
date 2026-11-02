package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type MaintenanceWindow struct {
	ID string `json:"id" api:"readonly"`
	// Number is a short sequential ID for lists and conversation ("window 16").
	Number          int64    `json:"number" api:"readonly"`
	Name            string   `json:"name" api:"required"`
	Description     string   `json:"description"`
	Enabled         bool     `json:"enabled"`
	GroupIDs        []string `json:"group_ids"`
	Weekdays        []int    `json:"weekdays"`
	StartTime       string   `json:"start_time" api:"required"`
	DurationMinutes int      `json:"duration_minutes" api:"required"`
	Timezone        string   `json:"timezone"`
	AppliesTo       []string `json:"applies_to"` // deploy | patch
	// Platform restricts the window to endpoints of one OS (windows,
	// darwin, linux); "" is every platform.
	Platform string `json:"platform"`
	// Recurrence is once, daily, weekly or monthly ("" is the original
	// weekdays-every-week form); see internal/maintenance.
	Recurrence   string `json:"recurrence"`
	Interval     int    `json:"interval"`
	StartDate    string `json:"start_date"` // YYYY-MM-DD, the effective date
	MonthDay     int    `json:"month_day"`
	MonthWeek    int    `json:"month_week"` // 1-4, 5 = last; 0 = use month_day
	MonthWeekday int    `json:"month_weekday"`
	// TimeBase "endpoint" reads the window in each endpoint's own time
	// zone (falling back to Timezone for one that has not reported it);
	// "zone" reads it in Timezone for everyone.
	TimeBase   string    `json:"time_base"`
	ObserveDST bool      `json:"observe_dst"`
	CreatedBy  string    `json:"created_by" api:"readonly"`
	UpdatedBy  string    `json:"updated_by" api:"readonly"`
	CreatedAt  time.Time `json:"created_at" api:"readonly"`
	UpdatedAt  time.Time `json:"updated_at" api:"readonly"`
}

const maintenanceColumns = `id, name, description, enabled, group_ids, weekdays, start_time, duration_minutes, timezone, applies_to, created_by, created_at, updated_at,
	number, platform, recurrence, interval_n, coalesce(to_char(start_date, 'YYYY-MM-DD'), ''), month_day, month_week, month_weekday, time_base, observe_dst, updated_by`

func scanMaintenanceWindow(row interface{ Scan(...any) error }) (MaintenanceWindow, error) {
	var w MaintenanceWindow
	var weekdays []int32
	err := row.Scan(&w.ID, &w.Name, &w.Description, &w.Enabled, &w.GroupIDs, &weekdays, &w.StartTime, &w.DurationMinutes, &w.Timezone, &w.AppliesTo, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt,
		&w.Number, &w.Platform, &w.Recurrence, &w.Interval, &w.StartDate, &w.MonthDay, &w.MonthWeek, &w.MonthWeekday, &w.TimeBase, &w.ObserveDST, &w.UpdatedBy)
	if err != nil {
		return w, err
	}
	w.Weekdays = make([]int, 0, len(weekdays))
	for _, d := range weekdays {
		w.Weekdays = append(w.Weekdays, int(d))
	}
	if w.GroupIDs == nil {
		w.GroupIDs = []string{}
	}
	if w.AppliesTo == nil {
		w.AppliesTo = []string{}
	}
	return w, nil
}

func (s *Store) ListMaintenanceWindows(ctx context.Context) ([]MaintenanceWindow, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+maintenanceColumns+` FROM maintenance_windows ORDER BY number`)
	if err != nil {
		return nil, fmt.Errorf("list maintenance windows: %w", err)
	}
	defer rows.Close()
	out := []MaintenanceWindow{}
	for rows.Next() {
		w, err := scanMaintenanceWindow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan maintenance window: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) GetMaintenanceWindow(ctx context.Context, id string) (*MaintenanceWindow, error) {
	w, err := scanMaintenanceWindow(s.pool.QueryRow(ctx, `SELECT `+maintenanceColumns+` FROM maintenance_windows WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get maintenance window: %w", err)
	}
	return &w, nil
}

// UpsertMaintenanceWindow saves a window. created_by is kept from the first
// save; updated_by records who saved it last.
func (s *Store) UpsertMaintenanceWindow(ctx context.Context, w MaintenanceWindow) error {
	weekdays := make([]int32, 0, len(w.Weekdays))
	for _, d := range w.Weekdays {
		weekdays = append(weekdays, int32(d))
	}
	var startDate any
	if w.StartDate != "" {
		startDate = w.StartDate
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO maintenance_windows (id, name, description, enabled, group_ids, weekdays, start_time, duration_minutes, timezone, applies_to, created_by, created_at, updated_at,
		platform, recurrence, interval_n, start_date, month_day, month_week, month_weekday, time_base, observe_dst, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now(),now(),$12,$13,$14,$15::date,$16,$17,$18,$19,$20,$11)
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, enabled=EXCLUDED.enabled, group_ids=EXCLUDED.group_ids,
		weekdays=EXCLUDED.weekdays, start_time=EXCLUDED.start_time, duration_minutes=EXCLUDED.duration_minutes, timezone=EXCLUDED.timezone,
		applies_to=EXCLUDED.applies_to, platform=EXCLUDED.platform, recurrence=EXCLUDED.recurrence, interval_n=EXCLUDED.interval_n,
		start_date=EXCLUDED.start_date, month_day=EXCLUDED.month_day, month_week=EXCLUDED.month_week, month_weekday=EXCLUDED.month_weekday,
		time_base=EXCLUDED.time_base, observe_dst=EXCLUDED.observe_dst, updated_by=EXCLUDED.updated_by, updated_at=now()`,
		w.ID, w.Name, w.Description, w.Enabled, w.GroupIDs, weekdays, w.StartTime, w.DurationMinutes, w.Timezone, w.AppliesTo, w.CreatedBy,
		w.Platform, w.Recurrence, w.Interval, startDate, w.MonthDay, w.MonthWeek, w.MonthWeekday, w.TimeBase, w.ObserveDST)
	if err != nil {
		return fmt.Errorf("upsert maintenance window: %w", err)
	}
	return nil
}

func (s *Store) DeleteMaintenanceWindow(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM maintenance_windows WHERE id = $1`, id)
	return err
}

// DeploymentTemplate remembers a deployment form.
type DeploymentTemplate struct {
	ID              string            `json:"id" api:"readonly"`
	Name            string            `json:"name" api:"required"`
	Description     string            `json:"description"`
	IsDefault       bool              `json:"is_default"`
	PackageID       string            `json:"package_id"`
	Operation       string            `json:"operation"`
	PlanID          string            `json:"plan_id"`
	Parameters      map[string]string `json:"parameters"`
	AllowReboot     bool              `json:"allow_reboot"`
	ForceRemove     bool              `json:"force_remove"`
	ExpireSeconds   int               `json:"expire_seconds"`
	OverrideWindows bool              `json:"override_windows"`
	CreatedBy       string            `json:"created_by" api:"readonly"`
	CreatedAt       time.Time         `json:"created_at" api:"readonly"`
	UpdatedAt       time.Time         `json:"updated_at" api:"readonly"`
}

const templateColumns = `id, name, description, is_default, package_id, operation, plan_id, parameters, allow_reboot, force_remove, expire_seconds, override_windows, created_by, created_at, updated_at`

func scanTemplate(row interface{ Scan(...any) error }) (DeploymentTemplate, error) {
	var t DeploymentTemplate
	var params []byte
	err := row.Scan(&t.ID, &t.Name, &t.Description, &t.IsDefault, &t.PackageID, &t.Operation, &t.PlanID, &params, &t.AllowReboot, &t.ForceRemove, &t.ExpireSeconds, &t.OverrideWindows, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return t, err
	}
	_ = json.Unmarshal(params, &t.Parameters)
	if t.Parameters == nil {
		t.Parameters = map[string]string{}
	}
	return t, nil
}

func (s *Store) ListDeploymentTemplates(ctx context.Context) ([]DeploymentTemplate, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+templateColumns+` FROM deployment_templates ORDER BY is_default DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("list deployment templates: %w", err)
	}
	defer rows.Close()
	out := []DeploymentTemplate{}
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan deployment template: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetDeploymentTemplate answers the template with this ID, or nil if there is none.
func (s *Store) GetDeploymentTemplate(ctx context.Context, id string) (*DeploymentTemplate, error) {
	t, err := scanTemplate(s.pool.QueryRow(ctx, `SELECT `+templateColumns+` FROM deployment_templates WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get deployment template: %w", err)
	}
	return &t, nil
}

// UpsertDeploymentTemplate saves a template; marking one default clears
// the flag on the others, since "the default" is singular.
func (s *Store) UpsertDeploymentTemplate(ctx context.Context, t DeploymentTemplate) error {
	params, _ := json.Marshal(t.Parameters)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if t.IsDefault {
		if _, err := tx.Exec(ctx, `UPDATE deployment_templates SET is_default = false WHERE id <> $1`, t.ID); err != nil {
			return fmt.Errorf("clear default template: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO deployment_templates (`+templateColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, is_default=EXCLUDED.is_default, package_id=EXCLUDED.package_id,
		operation=EXCLUDED.operation, plan_id=EXCLUDED.plan_id, parameters=EXCLUDED.parameters, allow_reboot=EXCLUDED.allow_reboot, force_remove=EXCLUDED.force_remove,
		expire_seconds=EXCLUDED.expire_seconds, override_windows=EXCLUDED.override_windows, updated_at=now()`,
		t.ID, t.Name, t.Description, t.IsDefault, t.PackageID, t.Operation, t.PlanID, params, t.AllowReboot, t.ForceRemove, t.ExpireSeconds, t.OverrideWindows, t.CreatedBy); err != nil {
		return fmt.Errorf("upsert deployment template: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteDeploymentTemplate(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM deployment_templates WHERE id = $1`, id)
	return err
}
