package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Dashboard is a user-authored arrangement of panels. Panels are kept as
// JSON: their shape belongs to the server package that evaluates them,
// and the store only needs to carry it.
type Dashboard struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Panels      json.RawMessage `json:"panels"`
	PanelCount  int             `json:"panel_count"`
	Shared      bool            `json:"shared"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

const dashboardColumns = `id, name, description, panels, jsonb_array_length(panels), shared, created_by, created_at, updated_at`

func scanDashboard(row interface{ Scan(...any) error }) (Dashboard, error) {
	var d Dashboard
	var panels []byte
	if err := row.Scan(&d.ID, &d.Name, &d.Description, &panels, &d.PanelCount, &d.Shared, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return d, err
	}
	d.Panels = json.RawMessage(panels)
	if len(d.Panels) == 0 {
		d.Panels = json.RawMessage("[]")
	}
	return d, nil
}

func (s *Store) ListDashboards(ctx context.Context) ([]Dashboard, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+dashboardColumns+` FROM dashboards ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list dashboards: %w", err)
	}
	defer rows.Close()
	out := []Dashboard{}
	for rows.Next() {
		d, err := scanDashboard(rows)
		if err != nil {
			return nil, fmt.Errorf("scan dashboard: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) GetDashboard(ctx context.Context, id string) (*Dashboard, error) {
	d, err := scanDashboard(s.pool.QueryRow(ctx, `SELECT `+dashboardColumns+` FROM dashboards WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get dashboard: %w", err)
	}
	return &d, nil
}

func (s *Store) UpsertDashboard(ctx context.Context, d Dashboard) error {
	if len(d.Panels) == 0 {
		d.Panels = json.RawMessage("[]")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO dashboards (id, name, description, panels, shared, created_by, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, panels=EXCLUDED.panels, shared=EXCLUDED.shared, updated_at=now()`,
		d.ID, d.Name, d.Description, []byte(d.Panels), d.Shared, d.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert dashboard: %w", err)
	}
	return nil
}

func (s *Store) DeleteDashboard(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM dashboards WHERE id = $1`, id)
	return err
}

func (s *Store) CountDashboards(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM dashboards`).Scan(&n)
	return n, err
}

// PanelSample is one panel's value at one sampling.
type PanelSample struct {
	At     time.Time       `json:"at"`
	Value  float64         `json:"value"`
	Series json.RawMessage `json:"series,omitempty"`
}

func (s *Store) RecordPanelSample(ctx context.Context, dashboardID, panelID string, at time.Time, value float64, series []byte) error {
	if len(series) == 0 {
		series = []byte("[]")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO panel_samples (dashboard_id, panel_id, at, value, series) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (dashboard_id, panel_id, at) DO UPDATE SET value = EXCLUDED.value, series = EXCLUDED.series`,
		dashboardID, panelID, at, value, series)
	if err != nil {
		return fmt.Errorf("record panel sample: %w", err)
	}
	return nil
}

// ListPanelSamples returns a panel's samples inside the window, oldest first.
func (s *Store) ListPanelSamples(ctx context.Context, dashboardID, panelID string, since time.Time) ([]PanelSample, error) {
	rows, err := s.pool.Query(ctx, `SELECT at, value, series FROM panel_samples WHERE dashboard_id = $1 AND panel_id = $2 AND at >= $3 ORDER BY at`, dashboardID, panelID, since)
	if err != nil {
		return nil, fmt.Errorf("list panel samples: %w", err)
	}
	defer rows.Close()
	out := []PanelSample{}
	for rows.Next() {
		var p PanelSample
		var series []byte
		if err := rows.Scan(&p.At, &p.Value, &series); err != nil {
			return nil, fmt.Errorf("scan panel sample: %w", err)
		}
		p.Series = json.RawMessage(series)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) PrunePanelSamples(ctx context.Context, keep time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM panel_samples WHERE at < $1`, time.Now().Add(-keep))
	if err != nil {
		return 0, fmt.Errorf("prune panel samples: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DashboardAlert is a threshold on one panel.
type DashboardAlert struct {
	ID            string          `json:"id"`
	Name          string          `json:"name" api:"required"`
	DashboardID   string          `json:"dashboard_id" api:"required"`
	PanelID       string          `json:"panel_id" api:"required"`
	Condition     json.RawMessage `json:"condition" api:"required"`
	Severity      string          `json:"severity"`
	Enabled       bool            `json:"enabled"`
	LastValue     *float64        `json:"last_value,omitempty" api:"readonly"`
	LastState     string          `json:"last_state" api:"readonly"`
	LastDetail    string          `json:"last_detail" api:"readonly"`
	LastEvaluated *time.Time      `json:"last_evaluated,omitempty" api:"readonly"`
	CreatedBy     string          `json:"created_by" api:"readonly"`
	CreatedAt     time.Time       `json:"created_at" api:"readonly"`
	UpdatedAt     time.Time       `json:"updated_at" api:"readonly"`
}

const alertColumns = `id, name, dashboard_id, panel_id, condition, severity, enabled, last_value, last_state, last_detail, last_evaluated, created_by, created_at, updated_at`

func scanAlert(row interface{ Scan(...any) error }) (DashboardAlert, error) {
	var a DashboardAlert
	var cond []byte
	if err := row.Scan(&a.ID, &a.Name, &a.DashboardID, &a.PanelID, &cond, &a.Severity, &a.Enabled, &a.LastValue, &a.LastState, &a.LastDetail, &a.LastEvaluated, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return a, err
	}
	a.Condition = json.RawMessage(cond)
	if len(a.Condition) == 0 {
		a.Condition = json.RawMessage("{}")
	}
	return a, nil
}

func (s *Store) ListDashboardAlerts(ctx context.Context) ([]DashboardAlert, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+alertColumns+` FROM dashboard_alerts ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list dashboard alerts: %w", err)
	}
	defer rows.Close()
	out := []DashboardAlert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, fmt.Errorf("scan dashboard alert: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetDashboardAlert(ctx context.Context, id string) (*DashboardAlert, error) {
	a, err := scanAlert(s.pool.QueryRow(ctx, `SELECT `+alertColumns+` FROM dashboard_alerts WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get dashboard alert: %w", err)
	}
	return &a, nil
}

func (s *Store) UpsertDashboardAlert(ctx context.Context, a DashboardAlert) error {
	if len(a.Condition) == 0 {
		a.Condition = json.RawMessage("{}")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO dashboard_alerts (id, name, dashboard_id, panel_id, condition, severity, enabled, created_by, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, dashboard_id=EXCLUDED.dashboard_id, panel_id=EXCLUDED.panel_id, condition=EXCLUDED.condition, severity=EXCLUDED.severity, enabled=EXCLUDED.enabled, updated_at=now()`,
		a.ID, a.Name, a.DashboardID, a.PanelID, []byte(a.Condition), a.Severity, a.Enabled, a.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert dashboard alert: %w", err)
	}
	return nil
}

// SetAlertState records the outcome of one evaluation.
func (s *Store) SetAlertState(ctx context.Context, id string, value *float64, state, detail string) error {
	_, err := s.pool.Exec(ctx, `UPDATE dashboard_alerts SET last_value = $2, last_state = $3, last_detail = $4, last_evaluated = now() WHERE id = $1`, id, value, state, detail)
	return err
}

func (s *Store) DeleteDashboardAlert(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM dashboard_alerts WHERE id = $1`, id)
	return err
}
