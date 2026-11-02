package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// OIDC identities link an IdP account to a console user by (issuer,
// subject). A subject is only unique within its issuer: two IdPs, or one
// that lets users choose their subject, can both produce "1234", and keying
// on the bare subject signed one into the other's account.

// GetUserByOIDCIdentity returns the user linked to (issuer, subject), or
// nil when there is none.
func (s *Store) GetUserByOIDCIdentity(ctx context.Context, issuer, subject string) (*User, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+userColumnsPrefixed("u")+`
FROM oidc_identities i JOIN users u ON u.id = i.user_id
WHERE i.issuer = $1 AND i.subject = $2`, issuer, subject)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by oidc identity: %w", err)
	}
	return u, nil
}

// LinkOIDCIdentity records that (issuer, subject) signs in as userID. An
// existing link for the pair is left as it is.
func (s *Store) LinkOIDCIdentity(ctx context.Context, issuer, subject, userID, providerID string) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO oidc_identities (issuer, subject, user_id, provider_id) VALUES ($1, $2, $3, $4)
ON CONFLICT (issuer, subject) DO NOTHING`, issuer, subject, userID, providerID)
	if err != nil {
		return fmt.Errorf("link oidc identity: %w", err)
	}
	return nil
}

// GetUserByExternalID returns the user whose external_id is id (a SCIM
// externalId or a pre-(issuer, subject) OIDC subject), or nil.
func (s *Store) GetUserByExternalID(ctx context.Context, id string) (*User, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE external_id = $1`, id)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by external id: %w", err)
	}
	return u, nil
}

// CreateOIDCUser creates the console account for a first OIDC sign-in.
// The username is chosen once, here; later sign-ins never rename it.
// Returns (nil, nil) when the username is already taken, so the caller can
// pick another rather than attach to somebody else's account.
func (s *Store) CreateOIDCUser(ctx context.Context, id, username, email, displayName string) (*User, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO users (id, username, email, display_name, source, active, updated_at)
VALUES ($1, $2, $3, $4, 'oidc', true, now())
ON CONFLICT (username) DO NOTHING
RETURNING `+userColumns, id, username, email, displayName)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("create oidc user: %w", err)
	}
	return u, nil
}

// RefreshOIDCProfile updates the descriptive fields an IdP owns. The
// username is deliberately not among them: approvals, dashboards and audit
// history refer to it, and a claim like preferred_username is whatever the
// IdP account's owner last typed.
func (s *Store) RefreshOIDCProfile(ctx context.Context, userID, email, displayName string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET email = $2, display_name = $3, updated_at = now() WHERE id = $1`,
		userID, email, displayName)
	if err != nil {
		return fmt.Errorf("refresh oidc profile: %w", err)
	}
	return nil
}
