package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AppCredConnection is an API login to one identity provider.
type AppCredConnection struct {
	ID        string            `json:"id" api:"readonly"`
	Kind      string            `json:"kind"` // entra, authentik, okta, gcp
	Name      string            `json:"name"`
	Config    map[string]string `json:"config"`
	Secret    string            `json:"-"` // vault-sealed
	HasSecret bool              `json:"has_secret" api:"readonly"`
	LastOKAt  *time.Time        `json:"last_ok_at,omitempty" api:"readonly"`
	LastError string            `json:"last_error" api:"readonly"`
	CreatedBy string            `json:"created_by" api:"readonly"`
	CreatedAt time.Time         `json:"created_at" api:"readonly"`
}

// AppCredential is one tracked secret or certificate.
type AppCredential struct {
	ID                 string     `json:"id" api:"readonly"`
	ConnectionID       string     `json:"connection_id"`
	Kind               string     `json:"kind"` // provider kind, or "manual"
	AppID              string     `json:"app_id"`
	AppName            string     `json:"app_name"`
	CredType           string     `json:"cred_type"` // client_secret, client_certificate, saml_signing, service_account_key, certificate
	ExternalID         string     `json:"external_id"`
	DisplayName        string     `json:"display_name"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	RotateDays         int        `json:"rotate_days"`
	RenewDays          int        `json:"renew_days" api:"required"`
	Mode               string     `json:"mode" api:"required"` // remind, download, push
	PushAgentID        string     `json:"push_agent_id"`
	PushPath           string     `json:"push_path"`
	PushKey            string     `json:"push_key"`
	PushReload         string     `json:"push_reload"`
	GraceDays          int        `json:"grace_days"`
	State              string     `json:"state" api:"readonly"` // idle, rotating, failed
	LastDetail         string     `json:"last_detail" api:"readonly"`
	LastRotatedAt      *time.Time `json:"last_rotated_at,omitempty" api:"readonly"`
	PreviousExternalID string     `json:"previous_external_id,omitempty"`
	RetireAfter        *time.Time `json:"retire_after,omitempty"`
	Material           string     `json:"-"` // vault-sealed, for one-time download
	MaterialUntil      *time.Time `json:"material_until,omitempty"`
	NotifiedAt         *time.Time `json:"notified_at,omitempty" api:"readonly"`
	CreatedBy          string     `json:"created_by" api:"readonly"`
	CreatedAt          time.Time  `json:"created_at" api:"readonly"`
}

func (s *Store) ListAppCredConnections(ctx context.Context) ([]AppCredConnection, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, name, config, secret, last_ok_at, last_error, created_by, created_at
FROM app_cred_connections ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list app credential connections: %w", err)
	}
	defer rows.Close()
	out := []AppCredConnection{}
	for rows.Next() {
		var c AppCredConnection
		var cfg []byte
		if err := rows.Scan(&c.ID, &c.Kind, &c.Name, &cfg, &c.Secret, &c.LastOKAt, &c.LastError, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cfg, &c.Config)
		c.HasSecret = c.Secret != ""
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetAppCredConnection(ctx context.Context, id string) (*AppCredConnection, error) {
	list, err := s.ListAppCredConnections(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range list {
		if c.ID == id {
			return &c, nil
		}
	}
	return nil, nil
}

// SaveAppCredConnection inserts or updates; an empty Secret keeps the
// stored one.
func (s *Store) SaveAppCredConnection(ctx context.Context, c AppCredConnection) error {
	cfg, _ := json.Marshal(c.Config)
	_, err := s.pool.Exec(ctx, `INSERT INTO app_cred_connections (id, kind, name, config, secret, created_by)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, config = EXCLUDED.config,
  secret = CASE WHEN EXCLUDED.secret = '' THEN app_cred_connections.secret ELSE EXCLUDED.secret END`,
		c.ID, c.Kind, c.Name, cfg, c.Secret, c.CreatedBy)
	if err != nil {
		return fmt.Errorf("save app credential connection: %w", err)
	}
	return nil
}

func (s *Store) SetAppCredConnectionStatus(ctx context.Context, id, errText string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_cred_connections SET last_error = $2,
  last_ok_at = CASE WHEN $2 = '' THEN now() ELSE last_ok_at END WHERE id = $1`, id, errText)
	return err
}

func (s *Store) DeleteAppCredConnection(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM app_cred_connections WHERE id = $1`, id)
	return err
}

const appCredCols = `id, connection_id, kind, app_id, app_name, cred_type, external_id, display_name, expires_at, rotate_days,
  renew_days, mode, push_agent_id, push_path, push_key, push_reload, grace_days, state, last_detail, last_rotated_at,
  previous_external_id, retire_after, material, material_until, notified_at, created_by, created_at`

func scanAppCred(row pgx.Row) (AppCredential, error) {
	var c AppCredential
	err := row.Scan(&c.ID, &c.ConnectionID, &c.Kind, &c.AppID, &c.AppName, &c.CredType, &c.ExternalID, &c.DisplayName,
		&c.ExpiresAt, &c.RotateDays, &c.RenewDays, &c.Mode, &c.PushAgentID, &c.PushPath, &c.PushKey, &c.PushReload,
		&c.GraceDays, &c.State, &c.LastDetail, &c.LastRotatedAt, &c.PreviousExternalID, &c.RetireAfter, &c.Material,
		&c.MaterialUntil, &c.NotifiedAt, &c.CreatedBy, &c.CreatedAt)
	return c, err
}

func (s *Store) ListAppCredentials(ctx context.Context) ([]AppCredential, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+appCredCols+` FROM app_credentials ORDER BY expires_at NULLS LAST, app_name`)
	if err != nil {
		return nil, fmt.Errorf("list app credentials: %w", err)
	}
	defer rows.Close()
	out := []AppCredential{}
	for rows.Next() {
		c, err := scanAppCred(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetAppCredential(ctx context.Context, id string) (*AppCredential, error) {
	c, err := scanAppCred(s.pool.QueryRow(ctx, `SELECT `+appCredCols+` FROM app_credentials WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get app credential: %w", err)
	}
	return &c, nil
}

// SaveAppCredential inserts or updates the tracked credential and its
// settings; rotation state is written by SetAppCredRotation.
func (s *Store) SaveAppCredential(ctx context.Context, c AppCredential) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO app_credentials (id, connection_id, kind, app_id, app_name, cred_type, external_id,
  display_name, expires_at, rotate_days, renew_days, mode, push_agent_id, push_path, push_key, push_reload, grace_days, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name, expires_at = EXCLUDED.expires_at,
  rotate_days = EXCLUDED.rotate_days, renew_days = EXCLUDED.renew_days, mode = EXCLUDED.mode,
  push_agent_id = EXCLUDED.push_agent_id, push_path = EXCLUDED.push_path, push_key = EXCLUDED.push_key,
  push_reload = EXCLUDED.push_reload, grace_days = EXCLUDED.grace_days`,
		c.ID, c.ConnectionID, c.Kind, c.AppID, c.AppName, c.CredType, c.ExternalID, c.DisplayName, c.ExpiresAt,
		c.RotateDays, c.RenewDays, c.Mode, c.PushAgentID, c.PushPath, c.PushKey, c.PushReload, c.GraceDays, c.CreatedBy)
	if err != nil {
		return fmt.Errorf("save app credential: %w", err)
	}
	return nil
}

func (s *Store) DeleteAppCredential(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM app_credentials WHERE id = $1`, id)
	return err
}

func (s *Store) SetAppCredState(ctx context.Context, id, state, detail string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_credentials SET state = $2, last_detail = $3 WHERE id = $1`, id, state, detail)
	return err
}

// SetAppCredRotation records a rotation: the new credential's id and
// expiry, the one it replaced (retired after retireAfter), and any material
// kept for download.
func (s *Store) SetAppCredRotation(ctx context.Context, id, newExternalID, previousExternalID string, expires, retireAfter *time.Time,
	material string, materialUntil *time.Time, detail string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_credentials SET external_id = $2, previous_external_id = $3, expires_at = $4,
  retire_after = $5, material = $6, material_until = $7, state = 'idle', last_detail = $8, last_rotated_at = now(), notified_at = NULL
WHERE id = $1`, id, newExternalID, previousExternalID, expires, retireAfter, material, materialUntil, detail)
	return err
}

// ClearAppCredRetired notes the replaced credential is gone.
func (s *Store) ClearAppCredRetired(ctx context.Context, id, detail string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_credentials SET previous_external_id = '', retire_after = NULL,
  last_detail = $2 || E'\n' || last_detail WHERE id = $1`, id, detail)
	return err
}

func (s *Store) ClearAppCredMaterial(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_credentials SET material = '', material_until = NULL WHERE id = $1`, id)
	return err
}

func (s *Store) SetAppCredNotified(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_credentials SET notified_at = now() WHERE id = $1`, id)
	return err
}
