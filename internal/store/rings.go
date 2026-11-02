package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// A deployment plan rolls a change out in stages instead of all at once,
// and stops if a stage goes badly.
//
// Two kinds, because they answer different questions. A *custom* plan's
// rings are computer groups — use it when *which* endpoints go first
// matters, so ring 1 is the machines you can afford to break. A *dynamic*
// plan's rings are random percentages, re-drawn on every deployment — use
// it when a representative sample matters more than a specific one, which
// is what catches a problem that only shows up on some hardware.

type Ring struct {
	Name string `json:"name"`
	// GroupID targets a computer group (custom plans).
	GroupID string `json:"group_id,omitempty"`
	// Percent takes a random share of the whole target set (dynamic plans).
	Percent int `json:"percent,omitempty"`
	// MinSuccess is how many endpoints must succeed before the next ring
	// starts; SuccessRate is the same thing as a percentage. Whichever is
	// set gates progression — a plan with neither runs straight through,
	// which is a staged rollout with no brakes and worth doing knowingly.
	MinSuccess  int `json:"min_success,omitempty"`
	SuccessRate int `json:"success_rate,omitempty"`
	// WaitMinutes holds the rollout open after a ring completes, so a
	// problem that takes time to show up has time to show up.
	WaitMinutes int `json:"wait_minutes,omitempty"`
}

type DeploymentPlan struct {
	ID        string    `json:"id" api:"readonly"`
	Name      string    `json:"name" api:"required"`
	Kind      string    `json:"kind"` // custom | dynamic
	Rings     []Ring    `json:"rings" api:"required"`
	CreatedAt time.Time `json:"created_at" api:"readonly"`
	CreatedBy string    `json:"created_by" api:"readonly"`
}

func scanPlan(row pgx.Row) (*DeploymentPlan, error) {
	var p DeploymentPlan
	var rings []byte
	if err := row.Scan(&p.ID, &p.Name, &p.Kind, &rings, &p.CreatedAt, &p.CreatedBy); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rings, &p.Rings)
	if p.Rings == nil {
		p.Rings = []Ring{}
	}
	return &p, nil
}

func (s *Store) ListDeploymentPlans(ctx context.Context) ([]DeploymentPlan, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, name, kind, rings, created_at, created_by FROM deployment_plans ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list deployment plans: %w", err)
	}
	defer rows.Close()
	var out []DeploymentPlan
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan deployment plan: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) GetDeploymentPlan(ctx context.Context, id string) (*DeploymentPlan, error) {
	p, err := scanPlan(s.pool.QueryRow(ctx,
		`SELECT id, name, kind, rings, created_at, created_by FROM deployment_plans WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get deployment plan: %w", err)
	}
	return p, nil
}

func (s *Store) UpsertDeploymentPlan(ctx context.Context, p DeploymentPlan) (*DeploymentPlan, error) {
	rings, err := json.Marshal(p.Rings)
	if err != nil {
		return nil, fmt.Errorf("encode rings: %w", err)
	}
	out, err := scanPlan(s.pool.QueryRow(ctx, `
INSERT INTO deployment_plans (id, name, kind, rings, created_by) VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, kind = EXCLUDED.kind, rings = EXCLUDED.rings
RETURNING id, name, kind, rings, created_at, created_by`, p.ID, p.Name, p.Kind, rings, p.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("upsert deployment plan: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteDeploymentPlan(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM deployment_plans WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete deployment plan: %w", err)
	}
	return nil
}
