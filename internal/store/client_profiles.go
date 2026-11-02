package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mustra-dev/mustra/internal/proto"
)

// ClientProfile is a set of runtime settings and an upgrade ring for the
// agents in some groups. UpgradeRing 0 is the deferral ring: those agents
// are never upgraded by a fleet roll unless the operator says so.
type ClientProfile struct {
	ID          string              `json:"id" api:"readonly"`
	Name        string              `json:"name" api:"required"`
	Description string              `json:"description"`
	Priority    int                 `json:"priority"`
	GroupIDs    []string            `json:"group_ids"`
	Settings    proto.AgentSettings `json:"settings"`
	UpgradeRing int                 `json:"upgrade_ring"`
	Enabled     bool                `json:"enabled"`
	CreatedBy   string              `json:"created_by" api:"readonly"`
	CreatedAt   time.Time           `json:"created_at" api:"readonly"`
	UpdatedAt   time.Time           `json:"updated_at" api:"readonly"`
}

const clientProfileColumns = `id, name, description, priority, group_ids, settings, upgrade_ring, enabled, created_by, created_at, updated_at`

func scanClientProfile(row interface{ Scan(...any) error }) (ClientProfile, error) {
	var p ClientProfile
	var settings []byte
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Priority, &p.GroupIDs, &settings, &p.UpgradeRing, &p.Enabled, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	_ = json.Unmarshal(settings, &p.Settings)
	if p.GroupIDs == nil {
		p.GroupIDs = []string{}
	}
	return p, nil
}

func (s *Store) ListClientProfiles(ctx context.Context) ([]ClientProfile, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+clientProfileColumns+` FROM client_profiles ORDER BY priority DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("list client profiles: %w", err)
	}
	defer rows.Close()
	out := []ClientProfile{}
	for rows.Next() {
		p, err := scanClientProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan client profile: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetClientProfile(ctx context.Context, id string) (*ClientProfile, error) {
	p, err := scanClientProfile(s.pool.QueryRow(ctx, `SELECT `+clientProfileColumns+` FROM client_profiles WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get client profile: %w", err)
	}
	return &p, nil
}

func (s *Store) UpsertClientProfile(ctx context.Context, p ClientProfile) error {
	settings, _ := json.Marshal(p.Settings)
	_, err := s.pool.Exec(ctx, `INSERT INTO client_profiles (`+clientProfileColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, priority=EXCLUDED.priority, group_ids=EXCLUDED.group_ids,
		settings=EXCLUDED.settings, upgrade_ring=EXCLUDED.upgrade_ring, enabled=EXCLUDED.enabled, updated_at=now()`,
		p.ID, p.Name, p.Description, p.Priority, p.GroupIDs, settings, p.UpgradeRing, p.Enabled, p.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert client profile: %w", err)
	}
	return nil
}

func (s *Store) DeleteClientProfile(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM client_profiles WHERE id = $1`, id)
	return err
}
