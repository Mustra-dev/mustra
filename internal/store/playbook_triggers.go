package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// What starts a playbook, other than a clock.

const (
	TriggerEvent   = "event"
	TriggerWebhook = "webhook"
)

type PlaybookTrigger struct {
	ID           string `json:"id" api:"readonly"`
	PlaybookID   string `json:"playbook_id" api:"required"`
	PlaybookName string `json:"playbook_name,omitempty" api:"readonly"`
	Kind         string `json:"kind" api:"required"`
	Enabled      bool   `json:"enabled"`

	// Event matching. Every empty field means "any", so a trigger with
	// none of them set fires on everything — which is why the console
	// makes you look at that rather than defaulting into it.
	Source     string `json:"source"`
	Severity   string `json:"severity"`
	TitleMatch string `json:"title_match"`

	// Token is the whole credential for a webhook trigger, chosen by the
	// server. It is returned once, in the answer to the save that issued
	// it: the creation of a webhook trigger, or the update that made one a
	// webhook. Afterwards the API returns only whether one exists. Read
	// from the database it is the SHA-256 of the token, never the token:
	// the store hashes on write and on lookup.
	Token string `json:"token,omitempty" api:"readonly"`
	// HasToken lets the console say "there is one" without carrying it.
	HasToken bool `json:"has_token" api:"readonly"`

	MinIntervalSeconds int        `json:"min_interval_seconds"`
	LastFiredAt        *time.Time `json:"last_fired_at,omitempty" api:"readonly"`
	LastDetail         string     `json:"last_detail,omitempty" api:"readonly"`
	FireCount          int        `json:"fire_count" api:"readonly"`

	CreatedAt time.Time `json:"created_at" api:"readonly"`
	CreatedBy string    `json:"created_by" api:"readonly"`
}

const triggerColumns = `t.id, t.playbook_id, coalesce(p.name,''), t.kind, t.enabled, t.source, t.severity,
       t.title_match, t.token, t.min_interval_seconds, t.last_fired_at, t.last_detail, t.fire_count,
       t.created_at, t.created_by`

func scanTrigger(row pgx.Row) (*PlaybookTrigger, error) {
	var t PlaybookTrigger
	if err := row.Scan(&t.ID, &t.PlaybookID, &t.PlaybookName, &t.Kind, &t.Enabled, &t.Source,
		&t.Severity, &t.TitleMatch, &t.Token, &t.MinIntervalSeconds, &t.LastFiredAt,
		&t.LastDetail, &t.FireCount, &t.CreatedAt, &t.CreatedBy); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListPlaybookTriggers(ctx context.Context) ([]PlaybookTrigger, error) {
	const q = `SELECT ` + triggerColumns + `
FROM playbook_triggers t LEFT JOIN playbooks p ON p.id = t.playbook_id
ORDER BY t.created_at DESC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list playbook triggers: %w", err)
	}
	defer rows.Close()
	out := []PlaybookTrigger{}
	for rows.Next() {
		t, err := scanTrigger(rows)
		if err != nil {
			return nil, fmt.Errorf("scan playbook trigger: %w", err)
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// GetPlaybookTrigger answers the trigger with this ID, or nil if there is none.
func (s *Store) GetPlaybookTrigger(ctx context.Context, id string) (*PlaybookTrigger, error) {
	const q = `SELECT ` + triggerColumns + `
FROM playbook_triggers t LEFT JOIN playbooks p ON p.id = t.playbook_id WHERE t.id = $1`
	t, err := scanTrigger(s.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get playbook trigger: %w", err)
	}
	return t, nil
}

// HashTriggerToken is how a webhook token is stored: hex SHA-256, the same
// form the schema migration gives tokens minted before hashing. A token is
// 192 random bits, so an unsalted fast hash is enough; what matters is that
// a database read (a backup, a support dump) no longer yields a working URL.
func HashTriggerToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) GetPlaybookTriggerByToken(ctx context.Context, token string) (*PlaybookTrigger, error) {
	if token == "" {
		return nil, nil
	}
	const q = `SELECT ` + triggerColumns + `
FROM playbook_triggers t LEFT JOIN playbooks p ON p.id = t.playbook_id
WHERE t.token = $1 AND t.token_hashed`
	t, err := scanTrigger(s.pool.QueryRow(ctx, q, HashTriggerToken(token)))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get playbook trigger by token: %w", err)
	}
	return t, nil
}

// CreatePlaybookTrigger inserts a new trigger. t.Token is the raw token
// of a webhook trigger, which is stored hashed; an event trigger has none.
func (s *Store) CreatePlaybookTrigger(ctx context.Context, t PlaybookTrigger) (*PlaybookTrigger, error) {
	const q = `
INSERT INTO playbook_triggers (id, playbook_id, kind, enabled, source, severity, title_match,
                               token, min_interval_seconds, created_by, token_hashed)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true)`
	stored := ""
	if t.Kind == TriggerWebhook && t.Token != "" {
		stored = HashTriggerToken(t.Token)
	}
	if _, err := s.pool.Exec(ctx, q, t.ID, t.PlaybookID, t.Kind, t.Enabled, t.Source, t.Severity,
		t.TitleMatch, stored, t.MinIntervalSeconds, t.CreatedBy); err != nil {
		return nil, fmt.Errorf("create playbook trigger: %w", err)
	}
	return s.GetPlaybookTrigger(ctx, t.ID)
}

// UpdatePlaybookTrigger rewrites the trigger t.ID names, and answers nil
// when there is none: an update never creates one.
//
// The token follows the kind. A trigger that stays a webhook keeps its
// token. One that becomes a webhook, or is a webhook without a token,
// gets token (a raw token the caller has just minted, stored hashed), and
// issued says so; the caller shows it once, as at creation. One that stops
// being a webhook loses its token: the fire path already refuses a
// non-webhook trigger, and clearing it means the old URL stays dead if the
// trigger becomes a webhook again, which gets it a new one.
func (s *Store) UpdatePlaybookTrigger(ctx context.Context, t PlaybookTrigger, token string) (out *PlaybookTrigger, issued bool, err error) {
	// SET reads the row as it was; RETURNING reads it as written.
	const q = `
UPDATE playbook_triggers SET
  playbook_id = $2, kind = $3, enabled = $4, source = $5, severity = $6, title_match = $7,
  min_interval_seconds = $8,
  token = CASE WHEN $3 <> 'webhook' THEN ''
               WHEN kind = 'webhook' AND token <> '' THEN token
               ELSE $9 END,
  token_hashed = CASE WHEN $3 = 'webhook' AND kind = 'webhook' AND token <> '' THEN token_hashed
                      ELSE true END
WHERE id = $1
RETURNING token <> '' AND token = $9`
	stored := ""
	if token != "" {
		stored = HashTriggerToken(token)
	}
	err = s.pool.QueryRow(ctx, q, t.ID, t.PlaybookID, t.Kind, t.Enabled, t.Source, t.Severity,
		t.TitleMatch, t.MinIntervalSeconds, stored).Scan(&issued)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("update playbook trigger: %w", err)
	}
	out, err = s.GetPlaybookTrigger(ctx, t.ID)
	return out, issued, err
}

func (s *Store) DeletePlaybookTrigger(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM playbook_triggers WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete playbook trigger: %w", err)
	}
	return nil
}

// ClaimPlaybookTrigger is the cooldown, enforced in the database rather
// than in memory.
//
// It is one conditional UPDATE on purpose. Two events arriving in the same
// millisecond — which is exactly what a vulnerability feed refresh looks
// like — would both pass a read-then-write check and both launch a run.
// Postgres decides which one wins; the loser is told no and the caller
// does nothing.
func (s *Store) ClaimPlaybookTrigger(ctx context.Context, id, detail string) (bool, error) {
	const q = `
UPDATE playbook_triggers
SET last_fired_at = now(), fire_count = fire_count + 1, last_detail = $2
WHERE id = $1 AND enabled
  AND (last_fired_at IS NULL OR last_fired_at < now() - (min_interval_seconds || ' seconds')::interval)`
	tag, err := s.pool.Exec(ctx, q, id, detail)
	if err != nil {
		return false, fmt.Errorf("claim playbook trigger: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// --- parked runs -----------------------------------------------------

type PlaybookPause struct {
	RunID       string     `json:"run_id"`
	PlaybookID  string     `json:"playbook_id"`
	PlaybookRun string     `json:"run_name,omitempty"`
	StepIndex   int        `json:"step_index"`
	StepName    string     `json:"step_name"`
	AgentIDs    []string   `json:"agent_ids"`
	State       string     `json:"state"`
	Reason      string     `json:"reason"`
	RequestedBy string     `json:"requested_by"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	Note        string     `json:"note,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

// pauseColumns reads a pause's playbook from its run when the pause has
// none: the approval gate has never recorded it, and the run row (which
// the pause cascades from) always has it.
const pauseColumns = `z.run_id, coalesce(nullif(z.playbook_id,''), r.playbook_id, ''), coalesce(r.name,''), z.step_index, z.step_name, z.agent_ids,
       z.state, z.reason, z.requested_by, z.decided_by, z.note, z.created_at, z.expires_at, z.decided_at`

func scanPause(row pgx.Row) (*PlaybookPause, error) {
	var p PlaybookPause
	if err := row.Scan(&p.RunID, &p.PlaybookID, &p.PlaybookRun, &p.StepIndex, &p.StepName,
		&p.AgentIDs, &p.State, &p.Reason, &p.RequestedBy, &p.DecidedBy, &p.Note,
		&p.CreatedAt, &p.ExpiresAt, &p.DecidedAt); err != nil {
		return nil, err
	}
	if p.AgentIDs == nil {
		p.AgentIDs = []string{}
	}
	return &p, nil
}

func (s *Store) CreatePlaybookPause(ctx context.Context, p PlaybookPause) error {
	const q = `
INSERT INTO playbook_run_pauses (run_id, playbook_id, step_index, step_name, agent_ids,
                                 state, reason, requested_by, expires_at)
VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8)
ON CONFLICT (run_id) DO NOTHING`
	ids := p.AgentIDs
	if ids == nil {
		ids = []string{}
	}
	if _, err := s.pool.Exec(ctx, q, p.RunID, p.PlaybookID, p.StepIndex, p.StepName, ids,
		p.Reason, p.RequestedBy, p.ExpiresAt); err != nil {
		return fmt.Errorf("create playbook pause: %w", err)
	}
	return nil
}

// AddPausedAgents appends endpoints to a pause that already exists. Every
// endpoint reaches the gate separately, and they all wait on the one
// decision.
func (s *Store) AddPausedAgent(ctx context.Context, runID, agentID string) error {
	const q = `
UPDATE playbook_run_pauses
SET agent_ids = array_append(agent_ids, $2)
WHERE run_id = $1 AND state = 'pending' AND NOT (agent_ids @> ARRAY[$2]::text[])`
	if _, err := s.pool.Exec(ctx, q, runID, agentID); err != nil {
		return fmt.Errorf("add paused agent: %w", err)
	}
	return nil
}

func (s *Store) ListPlaybookPauses(ctx context.Context, state string) ([]PlaybookPause, error) {
	q := `SELECT ` + pauseColumns + ` FROM playbook_run_pauses z
LEFT JOIN playbook_runs r ON r.id = z.run_id`
	args := []any{}
	if state != "" {
		q += ` WHERE z.state = $1`
		args = append(args, state)
	}
	q += ` ORDER BY z.created_at DESC LIMIT 200`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list playbook pauses: %w", err)
	}
	defer rows.Close()
	out := []PlaybookPause{}
	for rows.Next() {
		p, err := scanPause(rows)
		if err != nil {
			return nil, fmt.Errorf("scan playbook pause: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) GetPlaybookPause(ctx context.Context, runID string) (*PlaybookPause, error) {
	const q = `SELECT ` + pauseColumns + ` FROM playbook_run_pauses z
LEFT JOIN playbook_runs r ON r.id = z.run_id WHERE z.run_id = $1`
	p, err := scanPause(s.pool.QueryRow(ctx, q, runID))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get playbook pause: %w", err)
	}
	return p, nil
}

// DecidePlaybookPause records an approval or a rejection. Like the Jump
// Gate's, it is conditional on the pause still being pending, so a second
// decision loses rather than overwriting the first.
func (s *Store) DecidePlaybookPause(ctx context.Context, runID, state, who, note string) (bool, error) {
	const q = `
UPDATE playbook_run_pauses
SET state = $2, decided_by = $3, note = $4, decided_at = now()
WHERE run_id = $1 AND state = 'pending'`
	tag, err := s.pool.Exec(ctx, q, runID, state, who, note)
	if err != nil {
		return false, fmt.Errorf("decide playbook pause: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ExpirePlaybookPauses times out gates nobody decided. An approval that
// sat for a day is not an approval of today's fleet — the same rule the
// operator approvals follow.
func (s *Store) ExpirePlaybookPauses(ctx context.Context) ([]string, error) {
	const q = `
UPDATE playbook_run_pauses SET state = 'expired', decided_at = now()
WHERE state = 'pending' AND expires_at IS NOT NULL AND expires_at < now()
RETURNING run_id`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("expire playbook pauses: %w", err)
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
