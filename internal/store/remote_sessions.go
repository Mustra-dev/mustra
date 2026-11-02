package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RemoteSession is a remote desktop session: one the server must end on
// time, log out when it goes idle, clear a temporary account after, or
// find the recording of.
type RemoteSession struct {
	ID        string     `json:"id"`
	AgentID   string     `json:"agent_id"`
	Hostname  string     `json:"hostname"`
	Username  string     `json:"username"`
	Protocol  string     `json:"protocol"`
	Provider  string     `json:"provider"`
	GrantID   string     `json:"grant_id"`
	Reason    string     `json:"reason,omitempty"`
	GuacToken string     `json:"-"`
	TokenHash string     `json:"-"`
	OpenedAt  time.Time  `json:"opened_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastSeen  time.Time  `json:"last_seen_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	EndReason string     `json:"end_reason,omitempty"`
	Recording string     `json:"recording,omitempty"`

	// JITUsername is the temporary account the session signed in with;
	// JITState is "active" until the endpoint confirms it removed it.
	JITUsername  string     `json:"jit_username,omitempty"`
	JITState     string     `json:"jit_state,omitempty"`
	JITAttempts  int        `json:"jit_attempts,omitempty"`
	JITError     string     `json:"jit_error,omitempty"`
	JITRemovedAt *time.Time `json:"jit_removed_at,omitempty"`
}

func (s *Store) CreateRemoteSession(ctx context.Context, r RemoteSession) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO remote_sessions (id, agent_id, hostname, username, protocol, provider, grant_id, guac_token, expires_at,
			token_hash, recording, reason, jit_username, jit_state, jit_next_try_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14, CASE WHEN $14 = 'active' THEN now() END)`,
		r.ID, r.AgentID, r.Hostname, r.Username, r.Protocol, r.Provider, r.GrantID, r.GuacToken, r.ExpiresAt,
		r.TokenHash, r.Recording, r.Reason, r.JITUsername, r.JITState)
	if err != nil {
		return fmt.Errorf("create remote session: %w", err)
	}
	return nil
}

// SetRemoteSessionToken attaches the Guacamole token once the ticket has
// been traded for one, which happens after the row (and so the temporary
// account it accounts for) already exists.
func (s *Store) SetRemoteSessionToken(ctx context.Context, id, sealed, hash string) error {
	_, err := s.pool.Exec(ctx, `UPDATE remote_sessions SET guac_token = $2, token_hash = $3, last_seen_at = now() WHERE id = $1 AND ended_at IS NULL`, id, sealed, hash)
	if err != nil {
		return fmt.Errorf("set remote session token: %w", err)
	}
	return nil
}

// RemoteSessionByTokenHash finds the open session a tunnel belongs to.
func (s *Store) RemoteSessionByTokenHash(ctx context.Context, hash string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `SELECT id FROM remote_sessions WHERE token_hash = $1 AND token_hash <> '' AND ended_at IS NULL`, hash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("remote session by token: %w", err)
	}
	return id, nil
}

// TouchRemoteSession records that the session's tunnel is still open.
func (s *Store) TouchRemoteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE remote_sessions SET last_seen_at = now() WHERE id = $1 AND ended_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("touch remote session: %w", err)
	}
	return nil
}

// RemoteSessionsToEnd lists open sessions whose window has passed, whose
// grant is no longer approved and live, or whose tunnel has been closed
// for longer than idle, with the reason for each. Like ActiveJumpGrant,
// "live" is the clock's answer, not the state column's.
func (s *Store) RemoteSessionsToEnd(ctx context.Context, idle time.Duration) ([]RemoteSession, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.id, r.agent_id, r.hostname, r.username, r.protocol, r.provider, r.grant_id, r.guac_token, r.opened_at, r.expires_at,
			r.jit_username,
			CASE WHEN r.expires_at IS NOT NULL AND r.expires_at <= now() THEN 'window ended'
			     WHEN r.grant_id <> '' AND g.state IS DISTINCT FROM 'approved' THEN 'grant ' || COALESCE(g.state, 'removed')
			     WHEN r.grant_id <> '' AND g.expires_at <= now() THEN 'grant window ended'
			     ELSE 'disconnected' END
		FROM remote_sessions r LEFT JOIN jump_grants g ON g.id = r.grant_id AND r.grant_id <> ''
		WHERE r.ended_at IS NULL AND (
			(r.expires_at IS NOT NULL AND r.expires_at <= now())
			OR (r.grant_id <> '' AND (g.state IS DISTINCT FROM 'approved' OR g.expires_at <= now()))
			OR r.last_seen_at <= now() - make_interval(secs => $1))`, idle.Seconds())
	if err != nil {
		return nil, fmt.Errorf("remote sessions to end: %w", err)
	}
	defer rows.Close()
	var out []RemoteSession
	for rows.Next() {
		var r RemoteSession
		if err := rows.Scan(&r.ID, &r.AgentID, &r.Hostname, &r.Username, &r.Protocol, &r.Provider, &r.GrantID, &r.GuacToken, &r.OpenedAt, &r.ExpiresAt,
			&r.JITUsername, &r.EndReason); err != nil {
			return nil, fmt.Errorf("scan remote session: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EndRemoteSession marks a session ended and drops its token, which is of
// no further use and should not outlive the session in the database.
func (s *Store) EndRemoteSession(ctx context.Context, id, reason string) error {
	_, err := s.pool.Exec(ctx, `UPDATE remote_sessions SET ended_at = now(), end_reason = $2, guac_token = '', token_hash = '' WHERE id = $1 AND ended_at IS NULL`, id, reason)
	if err != nil {
		return fmt.Errorf("end remote session: %w", err)
	}
	return nil
}

// RemoteJITToRemove lists ended sessions whose temporary account the
// endpoint has not yet confirmed removed and whose next attempt is due.
func (s *Store) RemoteJITToRemove(ctx context.Context) ([]RemoteSession, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, agent_id, hostname, username, protocol, jit_username, jit_attempts
		FROM remote_sessions
		WHERE jit_state = 'active' AND ended_at IS NOT NULL AND (jit_next_try_at IS NULL OR jit_next_try_at <= now())
		ORDER BY ended_at LIMIT 100`)
	if err != nil {
		return nil, fmt.Errorf("temporary accounts to remove: %w", err)
	}
	defer rows.Close()
	var out []RemoteSession
	for rows.Next() {
		var r RemoteSession
		if err := rows.Scan(&r.ID, &r.AgentID, &r.Hostname, &r.Username, &r.Protocol, &r.JITUsername, &r.JITAttempts); err != nil {
			return nil, fmt.Errorf("scan temporary account: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RemoteJITRemoved records the endpoint's confirmation.
func (s *Store) RemoteJITRemoved(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE remote_sessions SET jit_state = 'removed', jit_removed_at = now(), jit_error = '', jit_next_try_at = NULL WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("temporary account removed: %w", err)
	}
	return nil
}

// RemoteJITNotCreated clears a session's account when the endpoint said
// no to creating it, so nothing waits to remove an account that never was.
func (s *Store) RemoteJITNotCreated(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE remote_sessions SET jit_state = '', jit_next_try_at = NULL WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("temporary account not created: %w", err)
	}
	return nil
}

// RemoteJITFailed records a failed removal and when to try again; it
// returns the attempt count so far.
func (s *Store) RemoteJITFailed(ctx context.Context, id, msg string, retryIn time.Duration) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `UPDATE remote_sessions SET jit_attempts = jit_attempts + 1, jit_error = $2, jit_next_try_at = now() + make_interval(secs => $3)
		WHERE id = $1 RETURNING jit_attempts`, id, msg, retryIn.Seconds()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("temporary account removal failed: %w", err)
	}
	return n, nil
}

// ListRemoteSessions returns the most recent sessions, newest first.
func (s *Store) ListRemoteSessions(ctx context.Context, limit int) ([]RemoteSession, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+remoteSessionColumns+` FROM remote_sessions ORDER BY opened_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list remote sessions: %w", err)
	}
	defer rows.Close()
	var out []RemoteSession
	for rows.Next() {
		r, err := scanRemoteSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRemoteSession returns one session, or nil.
func (s *Store) GetRemoteSession(ctx context.Context, id string) (*RemoteSession, error) {
	r, err := scanRemoteSession(s.pool.QueryRow(ctx, `SELECT `+remoteSessionColumns+` FROM remote_sessions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

const remoteSessionColumns = `id, agent_id, hostname, username, protocol, provider, grant_id, reason, opened_at, expires_at, last_seen_at, ended_at, end_reason,
	recording, jit_username, jit_state, jit_attempts, jit_error, jit_removed_at`

func scanRemoteSession(row pgx.Row) (RemoteSession, error) {
	var r RemoteSession
	err := row.Scan(&r.ID, &r.AgentID, &r.Hostname, &r.Username, &r.Protocol, &r.Provider, &r.GrantID, &r.Reason, &r.OpenedAt, &r.ExpiresAt, &r.LastSeen, &r.EndedAt, &r.EndReason,
		&r.Recording, &r.JITUsername, &r.JITState, &r.JITAttempts, &r.JITError, &r.JITRemovedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return r, fmt.Errorf("scan remote session: %w", err)
	}
	return r, err
}
