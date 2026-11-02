package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// JumpPolicy says what reaching an endpoint costs: a reason, an approval,
// a time limit. The highest-priority enabled policy covering an endpoint
// wins; an endpoint no policy covers costs nothing beyond the permission
// and management rights that already applied.
type JumpPolicy struct {
	ID              string    `json:"id"`
	Name            string    `json:"name" api:"required"`
	GroupIDs        []string  `json:"group_ids"`
	RequireApproval bool      `json:"require_approval"`
	RequireReason   bool      `json:"require_reason"`
	MaxMinutes      int       `json:"max_minutes"`
	Priority        int       `json:"priority"`
	Enabled         bool      `json:"enabled"`
	CreatedBy       string    `json:"created_by" api:"readonly"`
	CreatedAt       time.Time `json:"created_at" api:"readonly"`
	UpdatedAt       time.Time `json:"updated_at" api:"readonly"`
}

const jumpPolicyColumns = `id, name, group_ids, require_approval, require_reason, max_minutes, priority, enabled, created_by, created_at, updated_at`

func (s *Store) ListJumpPolicies(ctx context.Context) ([]JumpPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+jumpPolicyColumns+` FROM jump_policies ORDER BY priority DESC, lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list jump policies: %w", err)
	}
	defer rows.Close()
	out := []JumpPolicy{}
	for rows.Next() {
		var p JumpPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.GroupIDs, &p.RequireApproval, &p.RequireReason, &p.MaxMinutes, &p.Priority, &p.Enabled, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan jump policy: %w", err)
		}
		if p.GroupIDs == nil {
			p.GroupIDs = []string{}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetJumpPolicy(ctx context.Context, id string) (*JumpPolicy, error) {
	list, err := s.ListJumpPolicies(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, nil
}

func (s *Store) UpsertJumpPolicy(ctx context.Context, p JumpPolicy) error {
	if p.GroupIDs == nil {
		p.GroupIDs = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO jump_policies (`+jumpPolicyColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, group_ids=EXCLUDED.group_ids, require_approval=EXCLUDED.require_approval,
		require_reason=EXCLUDED.require_reason, max_minutes=EXCLUDED.max_minutes, priority=EXCLUDED.priority,
		enabled=EXCLUDED.enabled, updated_at=now()`,
		p.ID, p.Name, p.GroupIDs, p.RequireApproval, p.RequireReason, p.MaxMinutes, p.Priority, p.Enabled, p.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert jump policy: %w", err)
	}
	return nil
}

func (s *Store) DeleteJumpPolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM jump_policies WHERE id = $1`, id)
	return err
}

// JumpGrant is one person's time-boxed permission to reach one endpoint.
type JumpGrant struct {
	ID           string     `json:"id"`
	AgentID      string     `json:"agent_id"`
	Hostname     string     `json:"hostname"`
	PolicyID     string     `json:"policy_id"`
	PolicyName   string     `json:"policy_name"`
	RequestedBy  string     `json:"requested_by"`
	Reason       string     `json:"reason"`
	MaxMinutes   int        `json:"max_minutes"`
	State        string     `json:"state"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`
	RequestedAt  time.Time  `json:"requested_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

const jumpGrantColumns = `id, agent_id, hostname, policy_id, policy_name, requested_by, reason, max_minutes,
	state, decided_by, decided_at, decision_note, requested_at, expires_at`

func scanJumpGrant(row interface{ Scan(...any) error }) (JumpGrant, error) {
	var g JumpGrant
	err := row.Scan(&g.ID, &g.AgentID, &g.Hostname, &g.PolicyID, &g.PolicyName, &g.RequestedBy, &g.Reason, &g.MaxMinutes,
		&g.State, &g.DecidedBy, &g.DecidedAt, &g.DecisionNote, &g.RequestedAt, &g.ExpiresAt)
	return g, err
}

// CreateJumpGrant returns the grant as stored, with the requested_at the
// database gave it.
func (s *Store) CreateJumpGrant(ctx context.Context, g JumpGrant) (JumpGrant, error) {
	stored, err := scanJumpGrant(s.pool.QueryRow(ctx, `INSERT INTO jump_grants (id, agent_id, hostname, policy_id, policy_name, requested_by, reason, max_minutes, state, requested_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
		RETURNING `+jumpGrantColumns,
		g.ID, g.AgentID, g.Hostname, g.PolicyID, g.PolicyName, g.RequestedBy, g.Reason, g.MaxMinutes, g.State))
	if err != nil {
		return JumpGrant{}, fmt.Errorf("create jump grant: %w", err)
	}
	return stored, nil
}

func (s *Store) ListJumpGrants(ctx context.Context, state string, limit int) ([]JumpGrant, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+jumpGrantColumns+` FROM jump_grants
		WHERE ($1 = '' OR state = $1) ORDER BY requested_at DESC LIMIT $2`, state, limit)
	if err != nil {
		return nil, fmt.Errorf("list jump grants: %w", err)
	}
	defer rows.Close()
	out := []JumpGrant{}
	for rows.Next() {
		g, err := scanJumpGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("scan jump grant: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GetJumpGrant(ctx context.Context, id string) (*JumpGrant, error) {
	g, err := scanJumpGrant(s.pool.QueryRow(ctx, `SELECT `+jumpGrantColumns+` FROM jump_grants WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get jump grant: %w", err)
	}
	return &g, nil
}

// ActiveJumpGrant finds this person's live approved grant for an endpoint.
// "Live" is the clock's answer, not a state column's: a grant whose window
// has passed is not access, whatever the row still says.
func (s *Store) ActiveJumpGrant(ctx context.Context, username, agentID string) (*JumpGrant, error) {
	g, err := scanJumpGrant(s.pool.QueryRow(ctx, `SELECT `+jumpGrantColumns+` FROM jump_grants
		WHERE requested_by = $1 AND agent_id = $2 AND state = 'approved' AND expires_at > now()
		ORDER BY expires_at DESC LIMIT 1`, username, agentID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("active jump grant: %w", err)
	}
	return &g, nil
}

// DecideJumpGrant moves a grant out of pending, only from pending, and
// starts its clock at the moment of approval rather than of the request:
// a window that began while nobody was looking is not just-in-time.
func (s *Store) DecideJumpGrant(ctx context.Context, id, state, who, note string, minutes int) (bool, error) {
	var expires any
	if state == "approved" {
		expires = time.Now().Add(time.Duration(minutes) * time.Minute)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE jump_grants SET state = $2, decided_by = $3, decided_at = now(), decision_note = $4, expires_at = $5
		WHERE id = $1 AND state = 'pending'`, id, state, who, note, expires)
	if err != nil {
		return false, fmt.Errorf("decide jump grant: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) RevokeJumpGrant(ctx context.Context, id, who string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE jump_grants SET state = 'revoked', decided_by = $2, decided_at = now()
		WHERE id = $1 AND state = 'approved'`, id, who)
	if err != nil {
		return false, fmt.Errorf("revoke jump grant: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ExpireJumpGrants retires windows that have closed.
func (s *Store) ExpireJumpGrants(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE jump_grants SET state = 'expired'
		WHERE state IN ('approved','pending') AND expires_at IS NOT NULL AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("expire jump grants: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SessionTranscript is a recorded Direct Connect session with everything
// an auditor needs to judge it: who, where, why, who agreed, and what ran.
type SessionTranscript struct {
	ID         string         `json:"id"`
	AgentID    string         `json:"agent_id"`
	Hostname   string         `json:"hostname"`
	OpenedBy   string         `json:"opened_by"`
	OpenedAt   time.Time      `json:"opened_at"`
	ClosedAt   *time.Time     `json:"closed_at,omitempty"`
	ExpiresAt  *time.Time     `json:"expires_at,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	GrantID    string         `json:"grant_id,omitempty"`
	ApprovedBy string         `json:"approved_by,omitempty"`
	Commands   []ShellCommand `json:"commands,omitempty"`
	CommandN   int            `json:"command_count"`
}

// ListSessionTranscripts summarises recorded sessions, newest first.
func (s *Store) ListSessionTranscripts(ctx context.Context, limit int) ([]SessionTranscript, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
SELECT ss.id, ss.agent_id, coalesce(a.hostname,''), ss.opened_by, ss.opened_at, ss.closed_at, ss.expires_at,
       ss.reason, ss.grant_id, coalesce(g.decided_by,''), count(sc.id)::int
FROM shell_sessions ss
LEFT JOIN agents a ON a.agent_id = ss.agent_id
LEFT JOIN jump_grants g ON g.id = ss.grant_id
LEFT JOIN shell_commands sc ON sc.session_id = ss.id
GROUP BY ss.id, a.hostname, g.decided_by
ORDER BY ss.opened_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list session transcripts: %w", err)
	}
	defer rows.Close()
	out := []SessionTranscript{}
	for rows.Next() {
		var t SessionTranscript
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Hostname, &t.OpenedBy, &t.OpenedAt, &t.ClosedAt, &t.ExpiresAt,
			&t.Reason, &t.GrantID, &t.ApprovedBy, &t.CommandN); err != nil {
			return nil, fmt.Errorf("scan session transcript: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetSessionTranscript returns one session with every command it ran.
func (s *Store) GetSessionTranscript(ctx context.Context, id string) (*SessionTranscript, error) {
	list, err := s.ListSessionTranscripts(ctx, 500)
	if err != nil {
		return nil, err
	}
	var found *SessionTranscript
	for i := range list {
		if list[i].ID == id {
			found = &list[i]
			break
		}
	}
	if found == nil {
		return nil, nil
	}
	cmds, err := s.ListShellCommands(ctx, id, 1000)
	if err != nil {
		return nil, err
	}
	found.Commands = cmds
	return found, nil
}

// SetSessionAccess records why a session exists and what allowed it.
func (s *Store) SetSessionAccess(ctx context.Context, sessionID, reason, grantID string, expires *time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE shell_sessions SET reason = $2, grant_id = $3, expires_at = $4 WHERE id = $1`,
		sessionID, reason, grantID, expires)
	return err
}

// CloseExpiredSessions shuts sessions whose window has passed.
func (s *Store) CloseExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE shell_sessions SET closed_at = now()
		WHERE closed_at IS NULL AND expires_at IS NOT NULL AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("close expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CloseSessionsForGrant ends any open session that a grant allowed.
func (s *Store) CloseSessionsForGrant(ctx context.Context, grantID string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE shell_sessions SET closed_at = now() WHERE grant_id = $1 AND closed_at IS NULL`, grantID)
	if err != nil {
		return 0, fmt.Errorf("close sessions for grant: %w", err)
	}
	return tag.RowsAffected(), nil
}
