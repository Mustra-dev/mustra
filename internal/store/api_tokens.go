package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// APIToken is one programmatic-access credential — see schema.sql's
// api_tokens table. The secret itself is never stored, only its hash, so
// nothing here can be used to reconstruct a working token.
type APIToken struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	Revoked     bool       `json:"revoked"`
	// CreatedByID is the creating user's id. A token acts within its
	// creator's current reach: permissions, management rights and content
	// sets are all intersected with the creator's at every use.
	CreatedByID string `json:"created_by_id"`
	// ApprovalExempt lets a token run operations an approval policy covers
	// without waiting (there is nobody to wait for). Only an administrator
	// may set it; otherwise a covered operation is refused.
	ApprovalExempt bool `json:"approval_exempt"`
	// ParentTokenID is the token that created this one, if a token did.
	// This one works only while that one (and its own parent, and so on)
	// is live, and never with more permissions than it.
	ParentTokenID string `json:"parent_token_id,omitempty"`
}

// apiTokenColumns deliberately omits token_hash: no code path outside
// VerifyAPIToken has any business reading it.
const apiTokenColumns = `id, name, prefix, permissions, created_at, created_by, expires_at, last_used_at, revoked, created_by_id, approval_exempt, parent_token_id`

func (s *Store) CreateAPIToken(ctx context.Context, t APIToken, tokenHash string) error {
	const q = `
INSERT INTO api_tokens (id, name, prefix, token_hash, permissions, created_by, expires_at, created_by_id, approval_exempt, parent_token_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	if _, err := s.pool.Exec(ctx, q, t.ID, t.Name, t.Prefix, tokenHash, t.Permissions, t.CreatedBy, t.ExpiresAt, t.CreatedByID, t.ApprovalExempt, t.ParentTokenID); err != nil {
		return fmt.Errorf("create api token: %w", err)
	}
	return nil
}

func (s *Store) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.Permissions, &t.CreatedAt,
			&t.CreatedBy, &t.ExpiresAt, &t.LastUsedAt, &t.Revoked, &t.CreatedByID, &t.ApprovalExempt, &t.ParentTokenID); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// APITokenCandidate is one stored token's hash plus what it may do — the
// authenticator compares a presented token against each candidate with the
// matching prefix.
type APITokenCandidate struct {
	ID             string
	Name           string
	Hash           string
	Permissions    []string
	CreatedByID    string
	ApprovalExempt bool
	ParentTokenID  string
}

// CandidatesForPrefix returns live (unrevoked, unexpired) tokens whose
// prefix matches. Narrowing by prefix keeps verification to a bcrypt
// compare or two rather than one per token in the table.
func (s *Store) CandidatesForPrefix(ctx context.Context, prefix string) ([]APITokenCandidate, error) {
	const q = `
SELECT id, name, token_hash, permissions, created_by_id, approval_exempt, parent_token_id FROM api_tokens
WHERE prefix = $1 AND NOT revoked AND (expires_at IS NULL OR expires_at > now())`
	rows, err := s.pool.Query(ctx, q, prefix)
	if err != nil {
		return nil, fmt.Errorf("lookup api token: %w", err)
	}
	defer rows.Close()
	var out []APITokenCandidate
	for rows.Next() {
		var c APITokenCandidate
		if err := rows.Scan(&c.ID, &c.Name, &c.Hash, &c.Permissions, &c.CreatedByID, &c.ApprovalExempt, &c.ParentTokenID); err != nil {
			return nil, fmt.Errorf("scan api token candidate: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TouchAPIToken records that a token was just used, for the "last used"
// column — best-effort, so a failure here never fails the request.
func (s *Store) TouchAPIToken(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, id)
	return err
}

// RevokeAPIToken keeps the row so the audit trail (who made it, when it was
// last used) survives — a deleted token is a token nobody can explain.
func (s *Store) RevokeAPIToken(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `UPDATE api_tokens SET revoked = true WHERE id = $1`, id); err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	return nil
}

// GetAPIToken returns one token's metadata, or nil.
func (s *Store) GetAPIToken(ctx context.Context, id string) (*APIToken, error) {
	var t APIToken
	err := s.pool.QueryRow(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens WHERE id = $1`, id).Scan(
		&t.ID, &t.Name, &t.Prefix, &t.Permissions, &t.CreatedAt,
		&t.CreatedBy, &t.ExpiresAt, &t.LastUsedAt, &t.Revoked, &t.CreatedByID, &t.ApprovalExempt, &t.ParentTokenID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get api token: %w", err)
	}
	return &t, nil
}

// UpdateAPIToken changes what a token is called and may do. The secret,
// its hash and prefix, its expiry and its creator are untouched, so the
// scripts holding the token keep working. A revoked token is not changed.
// It reports whether a token was updated.
func (s *Store) UpdateAPIToken(ctx context.Context, id, name string, permissions []string, approvalExempt bool) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE api_tokens SET name = $2, permissions = $3, approval_exempt = $4
WHERE id = $1 AND NOT revoked`, id, name, permissions, approvalExempt)
	if err != nil {
		return false, fmt.Errorf("update api token: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) DeleteAPIToken(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM api_tokens WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete api token: %w", err)
	}
	return nil
}
