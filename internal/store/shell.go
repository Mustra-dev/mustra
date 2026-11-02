package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Live shell sessions and their command log.
//
// The log is the point. A remote root shell across a fleet is a capability
// that has to be accountable to be defensible, so the record is written
// before the command runs, not after it returns — a command that hangs or
// crashes the agent is exactly the one you most want to find in the log.

type ShellSession struct {
	ID         string     `json:"id"`
	AgentID    string     `json:"agent_id"`
	Hostname   string     `json:"hostname"`
	OpenedBy   string     `json:"opened_by"`
	OpenedAt   time.Time  `json:"opened_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	Commands   int        `json:"commands"`
	WorkingDir string     `json:"working_dir"`
	// Reason, GrantID and ExpiresAt are the Jump Gate half: why this
	// session exists, what allowed it, and when it stops being allowed.
	Reason    string     `json:"reason,omitempty"`
	GrantID   string     `json:"grant_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// OpenedByID is the opener's stable identity (user id, or "tok:<id>"
	// for an API token). Only that principal may run commands in the
	// session; usernames can change and are not compared.
	OpenedByID string `json:"-"`
}

func (s *Store) CreateShellSession(ctx context.Context, sess ShellSession) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO shell_sessions (id, agent_id, opened_by, working_dir, opened_by_id) VALUES ($1,$2,$3,$4,$5)`,
		sess.ID, sess.AgentID, sess.OpenedBy, sess.WorkingDir, sess.OpenedByID)
	if err != nil {
		return fmt.Errorf("create shell session: %w", err)
	}
	return nil
}

// shellSessionSelect is what one session's read and the list both
// select, so the list cannot leave out what the read carries (the Jump
// Gate fields, which the console needs to hide an expired session).
const shellSessionSelect = `
SELECT s.id, s.agent_id, coalesce(a.hostname,''), s.opened_by, s.opened_at, s.closed_at,
       s.working_dir, (SELECT count(*) FROM shell_commands c WHERE c.session_id = s.id),
       s.reason, s.grant_id, s.expires_at, s.opened_by_id
FROM shell_sessions s LEFT JOIN agents a ON a.agent_id = s.agent_id`

func scanShellSession(row interface{ Scan(...any) error }) (ShellSession, error) {
	var sess ShellSession
	err := row.Scan(&sess.ID, &sess.AgentID, &sess.Hostname, &sess.OpenedBy,
		&sess.OpenedAt, &sess.ClosedAt, &sess.WorkingDir, &sess.Commands,
		&sess.Reason, &sess.GrantID, &sess.ExpiresAt, &sess.OpenedByID)
	return sess, err
}

func (s *Store) GetShellSession(ctx context.Context, id string) (*ShellSession, error) {
	sess, err := scanShellSession(s.pool.QueryRow(ctx, shellSessionSelect+`
WHERE s.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get shell session: %w", err)
	}
	return &sess, nil
}

func (s *Store) SetShellWorkingDir(ctx context.Context, id, dir string) error {
	_, err := s.pool.Exec(ctx, `UPDATE shell_sessions SET working_dir = $2 WHERE id = $1`, id, dir)
	return err
}

func (s *Store) CloseShellSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE shell_sessions SET closed_at = now() WHERE id = $1 AND closed_at IS NULL`, id)
	return err
}

func (s *Store) ListShellSessions(ctx context.Context, limit int) ([]ShellSession, error) {
	rows, err := s.pool.Query(ctx, shellSessionSelect+`
ORDER BY s.opened_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list shell sessions: %w", err)
	}
	defer rows.Close()
	var out []ShellSession
	for rows.Next() {
		sess, err := scanShellSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan shell session: %w", err)
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

type ShellCommand struct {
	ID        int64     `json:"id"`
	SessionID string    `json:"session_id"`
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	RanBy     string    `json:"ran_by"`
	Command   string    `json:"command"`
	Output    string    `json:"output"`
	ExitCode  int       `json:"exit_code"`
	RanAt     time.Time `json:"ran_at"`
}

// RecordShellCommand writes the command before it runs. The output is
// filled in afterwards by FinishShellCommand — so a command that never
// returns still leaves a record of having been issued, which is precisely
// the case worth being able to look up.
func (s *Store) RecordShellCommand(ctx context.Context, sessionID, agentID, ranBy, command string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
INSERT INTO shell_commands (session_id, agent_id, ran_by, command) VALUES ($1,$2,$3,$4) RETURNING id`,
		sessionID, agentID, ranBy, command).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("record shell command: %w", err)
	}
	return id, nil
}

func (s *Store) FinishShellCommand(ctx context.Context, id int64, output string, exitCode int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE shell_commands SET output = $2, exit_code = $3 WHERE id = $1`, id, output, exitCode)
	return err
}

func (s *Store) ListShellCommands(ctx context.Context, sessionID string, limit int) ([]ShellCommand, error) {
	rows, err := s.pool.Query(ctx, `
SELECT c.id, c.session_id, c.agent_id, coalesce(a.hostname,''), c.ran_by, c.command,
       c.output, c.exit_code, c.ran_at
FROM shell_commands c LEFT JOIN agents a ON a.agent_id = c.agent_id
WHERE ($1 = '' OR c.session_id = $1)
ORDER BY c.ran_at DESC LIMIT $2`, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("list shell commands: %w", err)
	}
	defer rows.Close()
	var out []ShellCommand
	for rows.Next() {
		var c ShellCommand
		if err := rows.Scan(&c.ID, &c.SessionID, &c.AgentID, &c.Hostname, &c.RanBy,
			&c.Command, &c.Output, &c.ExitCode, &c.RanAt); err != nil {
			return nil, fmt.Errorf("scan shell command: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
