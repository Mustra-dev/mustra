package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent identity: enrollment tokens and per-agent credentials. See the
// "Agent identity and enrollment" section of schema.sql.

// EnrollmentToken is one enrollment token as the console lists it. The
// token itself is never stored or returned after creation.
type EnrollmentToken struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Site       string     `json:"site"`
	MaxUses    int        `json:"max_uses"`
	Uses       int        `json:"uses"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Usable reports whether the token can still enroll an agent.
func (t EnrollmentToken) Usable(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt) && t.Uses < t.MaxUses
}

const enrollmentTokenColumns = `id, label, site, max_uses, uses, created_by, created_at, expires_at, revoked_at, last_used_at`

func scanEnrollmentToken(row pgx.Row) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := row.Scan(&t.ID, &t.Label, &t.Site, &t.MaxUses, &t.Uses, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt)
	return t, err
}

// ErrTokenUnusable is returned when a token is unknown, revoked, expired or
// used up. One error for all four, deliberately: the caller is an
// unauthenticated endpoint, which learns nothing from the difference.
var ErrTokenUnusable = errors.New("enrollment token is not valid")

// ErrIdentityEnrolled is returned when an enrolment asks to keep an
// identity that already has a credential.
var ErrIdentityEnrolled = errors.New("that agent identity is already enrolled")

func (s *Store) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken, tokenHash string) error {
	const q = `INSERT INTO enrollment_tokens (id, label, token_hash, site, max_uses, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := s.pool.Exec(ctx, q, t.ID, t.Label, tokenHash, t.Site, t.MaxUses, t.CreatedBy, t.ExpiresAt); err != nil {
		return fmt.Errorf("create enrollment token: %w", err)
	}
	return nil
}

func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+enrollmentTokenColumns+` FROM enrollment_tokens ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("list enrollment tokens: %w", err)
	}
	defer rows.Close()
	out := []EnrollmentToken{}
	for rows.Next() {
		t, err := scanEnrollmentToken(rows)
		if err != nil {
			return nil, fmt.Errorf("scan enrollment token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeEnrollmentToken reports whether a token was revoked by this call.
func (s *Store) RevokeEnrollmentToken(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return false, fmt.Errorf("revoke enrollment token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// LookupEnrollmentToken returns a usable token by hash without consuming it.
func (s *Store) LookupEnrollmentToken(ctx context.Context, tokenHash string) (EnrollmentToken, error) {
	t, err := scanEnrollmentToken(s.pool.QueryRow(ctx, `SELECT `+enrollmentTokenColumns+`
FROM enrollment_tokens WHERE token_hash = $1`, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollmentToken{}, ErrTokenUnusable
	}
	if err != nil {
		return EnrollmentToken{}, fmt.Errorf("look up enrollment token: %w", err)
	}
	if !t.Usable(time.Now()) {
		return EnrollmentToken{}, ErrTokenUnusable
	}
	return t, nil
}

// EnrollWithToken consumes one use of a token and issues a credential in
// one transaction, so a token cannot be spent without an identity coming
// out of it, nor an identity issued on a token that was already spent.
//
// A token always issues newID. priorID is accepted for signature stability
// and ignored: an agent ID is not a secret (shared-credential holders see
// them on beacon.cmd.*), and a multi-use token is meant to be handed out,
// so letting a token holder name the ID it wants would let it take over a
// not-yet-enrolled agent — its group memberships and its commands — and
// lock the real host out. Legacy agents keep their IDs through
// EnrollLegacy instead. It returns the identity that was issued.
func (s *Store) EnrollWithToken(ctx context.Context, tokenHash, priorID, newID, secretHash string) (string, EnrollmentToken, error) {
	_ = priorID
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", EnrollmentToken{}, err
	}
	defer tx.Rollback(ctx)
	t, err := scanEnrollmentToken(tx.QueryRow(ctx, `UPDATE enrollment_tokens SET uses = uses + 1, last_used_at = now()
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now() AND uses < max_uses
RETURNING `+enrollmentTokenColumns, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return "", EnrollmentToken{}, ErrTokenUnusable
	}
	if err != nil {
		return "", EnrollmentToken{}, fmt.Errorf("consume enrollment token: %w", err)
	}
	id := newID
	if _, err := tx.Exec(ctx, `INSERT INTO agent_credentials (agent_id, secret_hash, enrolled_via, token_id)
VALUES ($1, $2, 'token', $3)`, id, secretHash, t.ID); err != nil {
		return "", EnrollmentToken{}, fmt.Errorf("issue agent credential: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", EnrollmentToken{}, err
	}
	return id, t, nil
}

// EnrollLegacy issues a credential to an agent that authenticated with the
// legacy shared password. Its prior identity is kept only if it is a
// legacy-era identity this server already knows (an inventory row or a
// legacy registration) and has never had a credential — revoked included,
// since a revoked credential is kept as a tombstone. A legacy holder must
// never take over an identity that has enrolled, nor get back one that
// was revoked, nor mint an ID of its choosing; an unknown prior ID gets
// newID instead.
func (s *Store) EnrollLegacy(ctx context.Context, priorID, newID, secretHash string) (string, error) {
	id := newID
	if priorID != "" {
		var known bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE agent_id = $1)
    OR EXISTS (SELECT 1 FROM agent_legacy_seen WHERE agent_id = $1)
    OR EXISTS (SELECT 1 FROM agent_credentials WHERE agent_id = $1)`, priorID).Scan(&known); err != nil {
			return "", fmt.Errorf("look up prior identity: %w", err)
		}
		if known {
			id = priorID
		}
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO agent_credentials (agent_id, secret_hash, enrolled_via)
VALUES ($1, $2, 'legacy') ON CONFLICT (agent_id) DO NOTHING`, id, secretHash)
	if err != nil {
		return "", fmt.Errorf("issue agent credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", ErrIdentityEnrolled
	}
	return id, nil
}

// AgentCredentialHash returns the stored secret hash, or "" when the agent
// has no credential or it was revoked.
func (s *Store) AgentCredentialHash(ctx context.Context, agentID string) (string, error) {
	var h string
	err := s.pool.QueryRow(ctx, `SELECT secret_hash FROM agent_credentials WHERE agent_id = $1 AND revoked_at IS NULL`, agentID).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read agent credential: %w", err)
	}
	return h, nil
}

// AgentHasCredential reports whether an identity has ever enrolled,
// including one whose credential was since revoked. Every caller uses it to
// keep the legacy shared credential away from that identity, and a
// revoked one must stay out of legacy's reach too.
func (s *Store) AgentHasCredential(ctx context.Context, agentID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_credentials WHERE agent_id = $1)`, agentID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("read agent credential: %w", err)
	}
	return exists, nil
}

// TouchAgentAuth records a successful broker authentication.
func (s *Store) TouchAgentAuth(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_credentials SET last_auth_at = now() WHERE agent_id = $1 AND revoked_at IS NULL`, agentID)
	return err
}

// RevokeAgentCredential revokes an agent's credential, keeping the row as a
// tombstone so the ID can never be enrolled again. Its broker
// authorization lapses when its current connection's JWT expires.
func (s *Store) RevokeAgentCredential(ctx context.Context, agentID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_credentials SET revoked_at = now(), secret_hash = ''
WHERE agent_id = $1 AND revoked_at IS NULL`, agentID)
	if err != nil {
		return false, fmt.Errorf("revoke agent credential: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RecordLegacySeen notes an agent registering over the shared credential.
func (s *Store) RecordLegacySeen(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO agent_legacy_seen (agent_id, last_seen_at) VALUES ($1, now())
ON CONFLICT (agent_id) DO UPDATE SET last_seen_at = now()`, agentID)
	return err
}

// AgentIdentity is one managed endpoint's enrollment state.
type AgentIdentity struct {
	AgentID      string     `json:"agent_id"`
	Hostname     string     `json:"hostname"`
	Enrolled     bool       `json:"enrolled"`
	EnrolledVia  string     `json:"enrolled_via,omitempty"`
	EnrolledAt   *time.Time `json:"enrolled_at,omitempty"`
	LastAuthAt   *time.Time `json:"last_auth_at,omitempty"`
	LegacySeenAt *time.Time `json:"legacy_seen_at,omitempty"`
	// RevokedAt is set when the agent's credential was revoked; it is then
	// not Enrolled and must be re-enrolled with a token (under a new ID).
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// ListAgentIdentities covers every managed agent.
func (s *Store) ListAgentIdentities(ctx context.Context) ([]AgentIdentity, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.agent_id, a.hostname, c.agent_id IS NOT NULL AND c.revoked_at IS NULL, COALESCE(c.enrolled_via, ''),
       c.created_at, c.last_auth_at, l.last_seen_at, c.revoked_at
FROM agents a
LEFT JOIN agent_credentials c ON c.agent_id = a.agent_id
LEFT JOIN agent_legacy_seen l ON l.agent_id = a.agent_id
WHERE a.managed
ORDER BY a.hostname`)
	if err != nil {
		return nil, fmt.Errorf("list agent identities: %w", err)
	}
	defer rows.Close()
	out := []AgentIdentity{}
	for rows.Next() {
		var a AgentIdentity
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.Enrolled, &a.EnrolledVia, &a.EnrolledAt, &a.LastAuthAt, &a.LegacySeenAt, &a.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan agent identity: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountManagedAgents is how the legacy-credential default is chosen: an
// install that already has agents is an upgrade.
func (s *Store) CountManagedAgents(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM agents WHERE managed`).Scan(&n)
	return n, err
}

// ListCredentialAgentIDs returns every enrolled agent ID, revoked ones
// included, for the deny list a legacy shared-credential connection is
// issued with.
func (s *Store) ListCredentialAgentIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id FROM agent_credentials`)
	if err != nil {
		return nil, fmt.Errorf("list agent credentials: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
