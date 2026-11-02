package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mustra-dev/mustra/internal/proto"
)

// End-user notifications: what the person at the endpoint is told, as
// distinct from what the operator watching the console is told.
//
// The two kinds are not cosmetic. A notice informs; a restart negotiates.
// A restart has to offer a countdown, a deadline and a bounded set of
// postponements, because the alternative — rebooting someone's machine
// under them — is how a fleet-management tool teaches a company to
// uninstall it.

const (
	EUNNotice  = "notice"
	EUNRestart = "restart"
)

type EUNMessage struct {
	ID    string `json:"id" api:"readonly"`
	Kind  string `json:"kind"`
	Name  string `json:"name" api:"required"`
	Title string `json:"title" api:"required"`
	Body  string `json:"body"`
	// DeadlineAt is when the message stops being worth showing at all. A
	// notice about Tuesday's maintenance is noise on Wednesday.
	DeadlineAt *time.Time `json:"deadline_at,omitempty"`

	AllowPostpone    bool  `json:"allow_postpone"`
	CountdownMinutes int   `json:"countdown_minutes"`
	GentleMinutes    int   `json:"gentle_minutes"`
	PostponeMinutes  []int `json:"postpone_minutes"`

	// Buttons replaces the choices the Self Service window would otherwise
	// render. Empty means the defaults for this kind, which is what every
	// message saved before this column existed holds.
	Buttons []proto.EUNButton `json:"buttons"`

	CreatedAt time.Time `json:"created_at" api:"readonly"`
	UpdatedAt time.Time `json:"updated_at" api:"readonly"`
	CreatedBy string    `json:"created_by" api:"readonly"`
}

const eunColumns = `id, kind, name, title, body, deadline_at, allow_postpone,
       countdown_minutes, gentle_minutes, postpone_minutes, buttons, created_at, updated_at, created_by`

func scanEUN(row pgx.Row) (*EUNMessage, error) {
	var m EUNMessage
	if err := row.Scan(&m.ID, &m.Kind, &m.Name, &m.Title, &m.Body, &m.DeadlineAt,
		&m.AllowPostpone, &m.CountdownMinutes, &m.GentleMinutes, &m.PostponeMinutes,
		&m.Buttons, &m.CreatedAt, &m.UpdatedAt, &m.CreatedBy); err != nil {
		return nil, err
	}
	if m.PostponeMinutes == nil {
		m.PostponeMinutes = []int{}
	}
	if m.Buttons == nil {
		m.Buttons = []proto.EUNButton{}
	}
	return &m, nil
}

func (s *Store) ListEUNMessages(ctx context.Context) ([]EUNMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+eunColumns+` FROM eun_messages ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list end-user notifications: %w", err)
	}
	defer rows.Close()
	var out []EUNMessage
	for rows.Next() {
		m, err := scanEUN(rows)
		if err != nil {
			return nil, fmt.Errorf("scan end-user notification: %w", err)
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (s *Store) GetEUNMessage(ctx context.Context, id string) (*EUNMessage, error) {
	m, err := scanEUN(s.pool.QueryRow(ctx, `SELECT `+eunColumns+` FROM eun_messages WHERE id = $1`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get end-user notification: %w", err)
	}
	return m, nil
}

func (s *Store) UpsertEUNMessage(ctx context.Context, m EUNMessage) (*EUNMessage, error) {
	const q = `
INSERT INTO eun_messages (id, kind, name, title, body, deadline_at, allow_postpone,
                          countdown_minutes, gentle_minutes, postpone_minutes, buttons, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (id) DO UPDATE SET
  kind = EXCLUDED.kind, name = EXCLUDED.name, title = EXCLUDED.title,
  body = EXCLUDED.body, deadline_at = EXCLUDED.deadline_at,
  allow_postpone = EXCLUDED.allow_postpone,
  countdown_minutes = EXCLUDED.countdown_minutes,
  gentle_minutes = EXCLUDED.gentle_minutes,
  postpone_minutes = EXCLUDED.postpone_minutes,
  buttons = EXCLUDED.buttons,
  updated_at = now()
RETURNING ` + eunColumns
	buttons := m.Buttons
	if buttons == nil {
		buttons = []proto.EUNButton{}
	}
	out, err := scanEUN(s.pool.QueryRow(ctx, q, m.ID, m.Kind, m.Name, m.Title, m.Body,
		m.DeadlineAt, m.AllowPostpone, m.CountdownMinutes, m.GentleMinutes,
		m.PostponeMinutes, buttons, m.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("upsert end-user notification: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteEUNMessage(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM eun_messages WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete end-user notification: %w", err)
	}
	return nil
}
