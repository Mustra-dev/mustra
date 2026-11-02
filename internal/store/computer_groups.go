package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mustra-dev/mustra/internal/groups"
)

// ComputerGroup is a named slice of the fleet — see schema.sql's
// computer_groups table. A dynamic group carries rules evaluated live
// against inventory; a static group carries an explicit member list.
type ComputerGroup struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Kind        string        `json:"kind"`       // "dynamic" | "static"
	MatchMode   string        `json:"match_mode"` // "all" | "any"
	Rules       []groups.Rule `json:"rules"`
	MemberIDs   []string      `json:"member_ids"`
	CreatedAt   time.Time     `json:"created_at"`
	CreatedBy   string        `json:"created_by"`
}

const computerGroupColumns = `id, name, description, kind, match_mode, rules, member_ids, created_at, created_by`

func scanComputerGroup(row pgx.Row) (*ComputerGroup, error) {
	var g ComputerGroup
	var rulesRaw []byte
	if err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Kind, &g.MatchMode,
		&rulesRaw, &g.MemberIDs, &g.CreatedAt, &g.CreatedBy); err != nil {
		return nil, err
	}
	if len(rulesRaw) > 0 {
		if err := json.Unmarshal(rulesRaw, &g.Rules); err != nil {
			return nil, fmt.Errorf("decode rules for group %s: %w", g.ID, err)
		}
	}
	if g.Rules == nil {
		g.Rules = []groups.Rule{}
	}
	if g.MemberIDs == nil {
		g.MemberIDs = []string{}
	}
	return &g, nil
}

func (s *Store) ListComputerGroups(ctx context.Context) ([]ComputerGroup, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+computerGroupColumns+` FROM computer_groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list computer groups: %w", err)
	}
	defer rows.Close()
	var out []ComputerGroup
	for rows.Next() {
		g, err := scanComputerGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("scan computer group: %w", err)
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (s *Store) GetComputerGroup(ctx context.Context, id string) (*ComputerGroup, error) {
	g, err := scanComputerGroup(s.pool.QueryRow(ctx,
		`SELECT `+computerGroupColumns+` FROM computer_groups WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get computer group: %w", err)
	}
	return g, nil
}

func (s *Store) UpsertComputerGroup(ctx context.Context, g ComputerGroup) (*ComputerGroup, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = validateCustomReferences(ctx, tx, nil, g.Rules, ""); err != nil {
		return nil, err
	}
	rulesRaw, err := json.Marshal(g.Rules)
	if err != nil {
		return nil, fmt.Errorf("encode rules: %w", err)
	}
	if g.MemberIDs == nil {
		g.MemberIDs = []string{}
	}
	const q = `
INSERT INTO computer_groups (id, name, description, kind, match_mode, rules, member_ids, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name, description = EXCLUDED.description, kind = EXCLUDED.kind,
    match_mode = EXCLUDED.match_mode, rules = EXCLUDED.rules, member_ids = EXCLUDED.member_ids
RETURNING ` + computerGroupColumns
	out, err := scanComputerGroup(tx.QueryRow(ctx, q, g.ID, g.Name, g.Description,
		g.Kind, g.MatchMode, rulesRaw, g.MemberIDs, g.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("upsert computer group: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// OrphanTargetingOnGroupDelete disables everything that targeted a group,
// and marks it as having lost its targeting, before the group goes.
//
// This has to happen in the same transaction as the delete. Enforce
// policies and playbooks both read a NULL group as "the whole fleet", so
// between the group vanishing and anything noticing, a policy scoped to
// twelve servers means all thirty-nine — with remediation commands or a
// reboot step attached, at the next scheduled run, with nobody having
// asked for it.
//
// Returns how many of each were disabled, so the deletion can say what it
// just switched off rather than doing it silently.
func (s *Store) DeleteComputerGroupAndOrphans(ctx context.Context, id string) (policies, playbooks int, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin group delete: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
UPDATE enforce_policies SET enabled = false, group_deleted = true, updated_at = now()
WHERE group_id = $1`, id)
	if err != nil {
		return 0, 0, fmt.Errorf("orphan enforce policies: %w", err)
	}
	policies = int(tag.RowsAffected())

	tag, err = tx.Exec(ctx, `
UPDATE playbooks SET enabled = false, group_deleted = true, next_run_at = NULL, updated_at = now()
WHERE group_id = $1`, id)
	if err != nil {
		return 0, 0, fmt.Errorf("orphan playbooks: %w", err)
	}
	playbooks = int(tag.RowsAffected())

	if _, err := tx.Exec(ctx, `DELETE FROM computer_groups WHERE id = $1`, id); err != nil {
		return 0, 0, fmt.Errorf("delete computer group: %w", err)
	}
	return policies, playbooks, tx.Commit(ctx)
}
