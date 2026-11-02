package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// OIDCProviderRow is one configured identity provider — see schema.sql's
// oidc_providers table for the field semantics.
type OIDCProviderRow struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	Kind         string    `json:"kind"`
	IssuerURL    string    `json:"issuer_url"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	RedirectURL  string    `json:"redirect_url"`
	Enabled      bool      `json:"enabled"`
	SortOrder    int       `json:"sort_order"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
}

const oidcProviderColumns = `id, label, kind, issuer_url, client_id, client_secret, redirect_url, enabled, sort_order, created_at, created_by`

func scanOIDCProvider(row pgx.Row) (*OIDCProviderRow, error) {
	var p OIDCProviderRow
	if err := row.Scan(&p.ID, &p.Label, &p.Kind, &p.IssuerURL, &p.ClientID, &p.ClientSecret,
		&p.RedirectURL, &p.Enabled, &p.SortOrder, &p.CreatedAt, &p.CreatedBy); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListOIDCProviders(ctx context.Context) ([]OIDCProviderRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+oidcProviderColumns+` FROM oidc_providers ORDER BY sort_order, label`)
	if err != nil {
		return nil, fmt.Errorf("list oidc providers: %w", err)
	}
	defer rows.Close()
	var out []OIDCProviderRow
	for rows.Next() {
		p, err := scanOIDCProvider(rows)
		if err != nil {
			return nil, fmt.Errorf("scan oidc provider: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) GetOIDCProvider(ctx context.Context, id string) (*OIDCProviderRow, error) {
	p, err := scanOIDCProvider(s.pool.QueryRow(ctx, `SELECT `+oidcProviderColumns+` FROM oidc_providers WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get oidc provider: %w", err)
	}
	return p, nil
}

// UpsertOIDCProvider creates or replaces a provider. An empty client_secret
// on an update keeps the stored one, so the admin form can show a blank
// secret field ("leave blank to keep unchanged") the same way the backdoor
// password does.
func (s *Store) UpsertOIDCProvider(ctx context.Context, p OIDCProviderRow) (*OIDCProviderRow, error) {
	const q = `
INSERT INTO oidc_providers (id, label, kind, issuer_url, client_id, client_secret, redirect_url, enabled, sort_order, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
    label = EXCLUDED.label,
    kind = EXCLUDED.kind,
    issuer_url = EXCLUDED.issuer_url,
    client_id = EXCLUDED.client_id,
    client_secret = CASE WHEN EXCLUDED.client_secret = '' THEN oidc_providers.client_secret ELSE EXCLUDED.client_secret END,
    redirect_url = EXCLUDED.redirect_url,
    enabled = EXCLUDED.enabled,
    sort_order = EXCLUDED.sort_order
RETURNING ` + oidcProviderColumns
	out, err := scanOIDCProvider(s.pool.QueryRow(ctx, q, p.ID, p.Label, p.Kind, p.IssuerURL, p.ClientID,
		p.ClientSecret, p.RedirectURL, p.Enabled, p.SortOrder, p.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("upsert oidc provider: %w", err)
	}
	return out, nil
}

func (s *Store) SetOIDCProviderEnabled(ctx context.Context, id string, enabled bool) error {
	if _, err := s.pool.Exec(ctx, `UPDATE oidc_providers SET enabled = $2 WHERE id = $1`, id, enabled); err != nil {
		return fmt.Errorf("set oidc provider enabled: %w", err)
	}
	return nil
}

// DeleteOIDCProvider removes a provider. Users who signed in through it keep
// their accounts (they're keyed on the IdP subject claim, not the provider
// row) — they just can't sign in that way any more.
func (s *Store) DeleteOIDCProvider(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM oidc_providers WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete oidc provider: %w", err)
	}
	return nil
}

func (s *Store) CountOIDCProviders(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM oidc_providers`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count oidc providers: %w", err)
	}
	return n, nil
}

// SetOIDCProviderSecret replaces only a provider's stored client secret.
func (s *Store) SetOIDCProviderSecret(ctx context.Context, id, secret string) error {
	if _, err := s.pool.Exec(ctx, `UPDATE oidc_providers SET client_secret = $2 WHERE id = $1`, id, secret); err != nil {
		return fmt.Errorf("set oidc provider secret: %w", err)
	}
	return nil
}
