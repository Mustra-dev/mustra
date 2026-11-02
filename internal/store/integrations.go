package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Integration is one outside system Mustra sends events to, or that reads
// from it (Prometheus).
type Integration struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind" api:"required"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config"`
	Secret      string            `json:"-"`
	SecretSet   bool              `json:"secret_set" api:"readonly"`
	Events      []string          `json:"events"`
	MinSeverity string            `json:"min_severity"`
	LastOKAt    *time.Time        `json:"last_ok_at,omitempty" api:"readonly"`
	LastError   string            `json:"last_error,omitempty" api:"readonly"`
	LastErrorAt *time.Time        `json:"last_error_at,omitempty" api:"readonly"`
	Sent        int64             `json:"sent" api:"readonly"`
	CreatedBy   string            `json:"created_by" api:"readonly"`
	CreatedAt   time.Time         `json:"created_at" api:"readonly"`
}

func (s *Store) ListIntegrations(ctx context.Context) ([]Integration, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, name, enabled, config, secret, events, min_severity,
  last_ok_at, last_error, last_error_at, sent, created_by, created_at FROM integrations ORDER BY kind, name`)
	if err != nil {
		return nil, fmt.Errorf("list integrations: %w", err)
	}
	defer rows.Close()
	out := []Integration{}
	for rows.Next() {
		var in Integration
		var cfg []byte
		if err := rows.Scan(&in.ID, &in.Kind, &in.Name, &in.Enabled, &cfg, &in.Secret, &in.Events, &in.MinSeverity,
			&in.LastOKAt, &in.LastError, &in.LastErrorAt, &in.Sent, &in.CreatedBy, &in.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan integration: %w", err)
		}
		_ = json.Unmarshal(cfg, &in.Config)
		if in.Config == nil {
			in.Config = map[string]string{}
		}
		in.SecretSet = in.Secret != ""
		out = append(out, in)
	}
	return out, rows.Err()
}

// SaveIntegration creates or updates one. A nil secret keeps the stored one.
func (s *Store) SaveIntegration(ctx context.Context, in Integration, secret *string) error {
	cfg, _ := json.Marshal(in.Config)
	_, err := s.pool.Exec(ctx, `INSERT INTO integrations (id, kind, name, enabled, config, secret, events, min_severity, created_by)
VALUES ($1,$2,$3,$4,$5,coalesce($6,''),$7,$8,$9)
ON CONFLICT (id) DO UPDATE SET kind=EXCLUDED.kind, name=EXCLUDED.name, enabled=EXCLUDED.enabled, config=EXCLUDED.config,
  secret=CASE WHEN $6::text IS NULL THEN integrations.secret ELSE EXCLUDED.secret END,
  events=EXCLUDED.events, min_severity=EXCLUDED.min_severity, updated_at=now()`,
		in.ID, in.Kind, in.Name, in.Enabled, cfg, secret, in.Events, in.MinSeverity, in.CreatedBy)
	if err != nil {
		return fmt.Errorf("save integration: %w", err)
	}
	return nil
}

func (s *Store) DeleteIntegration(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM integrations WHERE id = $1`, id)
	return err
}

// RecordIntegrationResult notes a delivery's outcome.
func (s *Store) RecordIntegrationResult(ctx context.Context, id string, deliveryErr error) error {
	if deliveryErr == nil {
		_, err := s.pool.Exec(ctx, `UPDATE integrations SET last_ok_at = now(), sent = sent + 1 WHERE id = $1`, id)
		return err
	}
	msg := deliveryErr.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := s.pool.Exec(ctx, `UPDATE integrations SET last_error = $2, last_error_at = now() WHERE id = $1`, id, msg)
	return err
}
