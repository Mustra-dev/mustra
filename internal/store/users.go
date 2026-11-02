package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// User is a console account, regardless of how it got here: a local
// backdoor account, an OIDC login, or a SCIM-provisioned identity.
// "Source" and "ExternalID" record provenance; authentication and session
// handling treat all three identically once a User exists.
type User struct {
	ID           string
	Username     string
	Email        string
	DisplayName  string
	PasswordHash string // empty for SSO/SCIM-only users — never authenticate-able via the local form
	Source       string // "local" | "oidc" | "scim"
	ExternalID   string
	IsAdmin      bool
	Active       bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// LastSignIn is when this session began; PreviousSignIn is the one
	// before it, which is the one worth showing someone — "you last signed
	// in on Tuesday" is checkable against their own memory, and telling
	// them when this session started is not.
	LastSignIn     *time.Time
	PreviousSignIn *time.Time
}

const userColumns = `id, username, email, display_name, password_hash, source, external_id, is_admin, active, created_at, updated_at, last_sign_in, previous_sign_in`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	var passwordHash, externalID *string
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &passwordHash, &u.Source, &externalID, &u.IsAdmin, &u.Active, &u.CreatedAt, &u.UpdatedAt, &u.LastSignIn, &u.PreviousSignIn); err != nil {
		return nil, err
	}
	if passwordHash != nil {
		u.PasswordHash = *passwordHash
	}
	if externalID != nil {
		u.ExternalID = *externalID
	}
	return &u, nil
}

// UpsertLocalAdmin creates or updates the break-glass local admin account.
// Called on every server startup with whatever username/password-hash is
// currently configured, so the backdoor account always matches the
// operator's configuration — this is what makes it usable even when the
// OIDC provider is unreachable, since it never depends on anything but
// Postgres.
func (s *Store) UpsertLocalAdmin(ctx context.Context, username, passwordHash string) (*User, error) {
	const q = `
INSERT INTO users (id, username, display_name, password_hash, source, is_admin, active, updated_at)
VALUES ($1, $2, $2, $3, 'local', true, true, now())
ON CONFLICT (username) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    source = 'local',
    is_admin = true,
    active = true,
    updated_at = now()
RETURNING ` + userColumns
	row := s.pool.QueryRow(ctx, q, "usr-"+username, username, passwordHash)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("upsert local admin: %w", err)
	}
	return u, nil
}

// GetUserByUsername looks up a user for local-form login. Returns
// (nil, nil) if not found — not found is a normal outcome here, not an
// error.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE username = $1`, username)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	return u, nil
}

// ListAllUsers returns every user, for the admin Users tab. Slice 1's
// expected scale (one console, a handful of admins/viewers) doesn't
// need SCIM's pagination here — see ListUsers in scim.go for the paginated
// version SCIM clients get.
func (s *Store) ListAllUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list all users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user row: %w", err)
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// CreateLocalUser creates a non-admin local account (the admin Users tab's
// "add local user" action) — distinct from UpsertLocalAdmin, which is
// specifically the always-is_admin break-glass backdoor account.
func (s *Store) CreateLocalUser(ctx context.Context, id, username, passwordHash, displayName string) (*User, error) {
	const q = `
INSERT INTO users (id, username, display_name, password_hash, source, is_admin, active, updated_at)
VALUES ($1, $2, $3, $4, 'local', false, true, now())
RETURNING ` + userColumns
	row := s.pool.QueryRow(ctx, q, id, username, displayName, passwordHash)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("create local user: %w", err)
	}
	return u, nil
}

// GetUserByID looks up a user by ID, e.g. to resolve a session.
func (s *Store) GetUserByID(ctx context.Context, id string) (*User, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// --- Sessions ---

// Session is a server-side session record; the browser cookie carries only
// the token, and the database only its SHA-256 (TokenHash). A copy of the
// sessions table — a backup, a replica, a read-only SQL bug — is then not a
// set of live logins.
type Session struct {
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateSession inserts a new session valid for ttl. tokenHash is the
// hex SHA-256 of the cookie value; the plaintext never reaches the store.
func (s *Store) CreateSession(ctx context.Context, tokenHash, userID string, ttl time.Duration) (*Session, error) {
	now := time.Now().UTC()
	sess := &Session{TokenHash: tokenHash, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	const q = `INSERT INTO sessions (token, user_id, created_at, expires_at, last_seen_at, hashed) VALUES ($1, $2, $3, $4, $3, true)`
	if _, err := s.pool.Exec(ctx, q, sess.TokenHash, sess.UserID, sess.CreatedAt, sess.ExpiresAt); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return sess, nil
}

// GetSessionUser resolves a session token hash to its user, or (nil, nil)
// if the session is unknown, past its absolute expiry, or has been idle for
// longer than idle (0 disables the idle check). A successful lookup marks
// the session as used, which is what the idle timeout measures from.
func (s *Store) GetSessionUser(ctx context.Context, tokenHash string, idle time.Duration) (*User, error) {
	idleSeconds := int64(idle / time.Second)
	q := `
WITH s AS (
    UPDATE sessions SET last_seen_at = now()
    WHERE token = $1 AND hashed AND expires_at > now()
      AND ($2::bigint <= 0 OR last_seen_at > now() - make_interval(secs => $2::bigint))
    RETURNING user_id
)
SELECT ` + userColumnsPrefixed("u") + `
FROM s JOIN users u ON u.id = s.user_id
WHERE u.active`
	row := s.pool.QueryRow(ctx, q, tokenHash, idleSeconds)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get session user: %w", err)
	}
	return u, nil
}

// DeleteSession removes a session (logout), by token hash.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, tokenHash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteSessionsForUser signs a user out everywhere. Called when their
// password, admin flag, roles or active state change: a session minted
// under the old credentials or rights must not outlive them.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete sessions for user: %w", err)
	}
	return nil
}

// PruneExpiredSessions deletes expired session rows. Cheap enough to call
// on a slow periodic tick rather than needing a dedicated job scheduler.
func (s *Store) PruneExpiredSessions(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now() OR last_seen_at <= now() - interval '30 days'`)
	if err != nil {
		return fmt.Errorf("prune expired sessions: %w", err)
	}
	return nil
}

// userColumnsPrefixed is userColumns with a table alias on each column, for
// the queries that join users to something else.
//
// Derived from userColumns rather than repeating the list, because it was a
// second hand-maintained copy: adding a column to one and not the other
// compiles perfectly and then fails at runtime with "number of field
// descriptions must equal number of destinations", which takes down every
// session lookup at once. Ask me how I know.
func userColumnsPrefixed(alias string) string {
	cols := strings.Split(userColumns, ",")
	for i, c := range cols {
		cols[i] = alias + "." + strings.TrimSpace(c)
	}
	return strings.Join(cols, ", ")
}
