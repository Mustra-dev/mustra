package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds the store operations the SCIM provisioning endpoint
// needs: creating/updating/deleting users and groups by the IdP's
// external_id, and a minimal single-clause equality filter — the only
// filter shape a SCIM client typically sends when checking "does this
// user/group already exist" before creating one.

// CreateSCIMUser inserts a user provisioned by an IdP over SCIM.
func (s *Store) CreateSCIMUser(ctx context.Context, id, externalID, username, email, displayName string, active bool) (*User, error) {
	const q = `
INSERT INTO users (id, username, email, display_name, source, external_id, active, updated_at)
VALUES ($1, $2, $3, $4, 'scim', $5, $6, now())
RETURNING ` + userColumns
	row := s.pool.QueryRow(ctx, q, id, username, email, displayName, externalID, active)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("create scim user: %w", err)
	}
	return u, nil
}

// ReplaceSCIMUser overwrites a SCIM-provisioned user's attributes (PUT).
func (s *Store) ReplaceSCIMUser(ctx context.Context, id, username, email, displayName string, active bool) (*User, error) {
	const q = `
UPDATE users SET username = $2, email = $3, display_name = $4, active = $5, updated_at = now()
WHERE id = $1 AND source = 'scim' AND NOT is_admin
RETURNING ` + userColumns
	row := s.pool.QueryRow(ctx, q, id, username, email, displayName, active)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("replace scim user: %w", err)
	}
	return u, nil
}

// SetUserActive is the common SCIM PATCH case: an IdP deprovisioning a user
// sends {"op":"replace","path":"active","value":false} rather than a full
// PUT.
func (s *Store) SetUserActive(ctx context.Context, id string, active bool) (*User, error) {
	const q = `UPDATE users SET active = $2, updated_at = now() WHERE id = $1 RETURNING ` + userColumns
	row := s.pool.QueryRow(ctx, q, id, active)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("set user active: %w", err)
	}
	return u, nil
}

// DeleteUser removes a user outright (SCIM DELETE). Cascades to their
// sessions and group memberships.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

// FindUserByExternalID looks up a SCIM- or OIDC-provisioned user by the
// IdP's external_id.
func (s *Store) FindUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE external_id = $1`, externalID)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find user by external id: %w", err)
	}
	return u, nil
}

// ListUsers returns a page of users, optionally filtered to an exact
// username match (the only SCIM filter shape implemented — see
// docs/ROADMAP.md for the full SCIM filter grammar).
func (s *Store) ListUsers(ctx context.Context, usernameEquals string, startIndex, count int) ([]User, int, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if usernameEquals != "" {
		total, terr := s.countUsers(ctx, usernameEquals)
		if terr != nil {
			return nil, 0, terr
		}
		rows, err = s.pool.Query(ctx, `SELECT `+userColumns+` FROM users WHERE username = $1 AND source = 'scim' ORDER BY username LIMIT $2 OFFSET $3`, usernameEquals, count, startIndex)
		if err != nil {
			return nil, 0, fmt.Errorf("list users filtered: %w", err)
		}
		return scanUsers(rows, total)
	}
	total, terr := s.countUsers(ctx, "")
	if terr != nil {
		return nil, 0, terr
	}
	rows, err = s.pool.Query(ctx, `SELECT `+userColumns+` FROM users WHERE source = 'scim' ORDER BY username LIMIT $1 OFFSET $2`, count, startIndex)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	return scanUsers(rows, total)
}

func (s *Store) countUsers(ctx context.Context, usernameEquals string) (int, error) {
	var n int
	var err error
	if usernameEquals != "" {
		err = s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username = $1 AND source = 'scim'`, usernameEquals).Scan(&n)
	} else {
		err = s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE source = 'scim'`).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

func scanUsers(rows pgx.Rows, total int) ([]User, int, error) {
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan user row: %w", err)
		}
		out = append(out, *u)
	}
	return out, total, rows.Err()
}

// --- Groups ---

// Group is a SCIM-provisioned group used to mirror IdP group membership.
// Slice 1 doesn't yet gate any feature by group membership — see
// docs/ROADMAP.md — but the provisioning target needs to exist for an IdP's
// SCIM sync to succeed.
type Group struct {
	ID          string
	DisplayName string
	ExternalID  string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	MemberIDs   []string
	// SCIMManaged marks a group SCIM provisioned. SCIM may change only
	// these; a group created in the console is not the IdP's to edit.
	SCIMManaged bool
}

func scanGroup(row pgx.Row) (*Group, error) {
	var g Group
	var externalID *string
	if err := row.Scan(&g.ID, &g.DisplayName, &externalID, &g.CreatedAt, &g.UpdatedAt, &g.SCIMManaged); err != nil {
		return nil, err
	}
	if externalID != nil {
		g.ExternalID = *externalID
	}
	return &g, nil
}

const groupColumns = `id, display_name, external_id, created_at, updated_at, scim_managed`

// MarkGroupSCIMManaged records that SCIM provisioned a group.
func (s *Store) MarkGroupSCIMManaged(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `UPDATE groups SET scim_managed = true WHERE id = $1`, id); err != nil {
		return fmt.Errorf("mark scim group: %w", err)
	}
	return nil
}

func (s *Store) CreateGroup(ctx context.Context, id, externalID, displayName string) (*Group, error) {
	const q = `INSERT INTO groups (id, display_name, external_id, updated_at) VALUES ($1, $2, $3, now()) RETURNING ` + groupColumns
	row := s.pool.QueryRow(ctx, q, id, displayName, externalID)
	g, err := scanGroup(row)
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	g.MemberIDs = []string{}
	return g, nil
}

func (s *Store) GetGroup(ctx context.Context, id string) (*Group, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+groupColumns+` FROM groups WHERE id = $1`, id)
	g, err := scanGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get group: %w", err)
	}
	members, err := s.ListGroupMemberIDs(ctx, id)
	if err != nil {
		return nil, err
	}
	g.MemberIDs = members
	return g, nil
}

func (s *Store) FindGroupByExternalID(ctx context.Context, externalID string) (*Group, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+groupColumns+` FROM groups WHERE external_id = $1`, externalID)
	g, err := scanGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find group by external id: %w", err)
	}
	return g, nil
}

// ListGroups returns a page of groups, optionally filtered to an exact
// displayName match.
func (s *Store) ListGroups(ctx context.Context, displayNameEquals string, startIndex, count int) ([]Group, int, error) {
	var total int
	var err error
	if displayNameEquals != "" {
		err = s.pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE display_name = $1`, displayNameEquals).Scan(&total)
	} else {
		err = s.pool.QueryRow(ctx, `SELECT count(*) FROM groups`).Scan(&total)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("count groups: %w", err)
	}

	var rows pgx.Rows
	if displayNameEquals != "" {
		rows, err = s.pool.Query(ctx, `SELECT `+groupColumns+` FROM groups WHERE display_name = $1 ORDER BY display_name LIMIT $2 OFFSET $3`, displayNameEquals, count, startIndex)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT `+groupColumns+` FROM groups ORDER BY display_name LIMIT $1 OFFSET $2`, count, startIndex)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var out []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan group row: %w", err)
		}
		members, err := s.ListGroupMemberIDs(ctx, g.ID)
		if err != nil {
			return nil, 0, err
		}
		g.MemberIDs = members
		out = append(out, *g)
	}
	return out, total, rows.Err()
}

func (s *Store) RenameGroup(ctx context.Context, id, displayName string) (*Group, error) {
	const q = `UPDATE groups SET display_name = $2, updated_at = now() WHERE id = $1 RETURNING ` + groupColumns
	row := s.pool.QueryRow(ctx, q, id, displayName)
	g, err := scanGroup(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("rename group: %w", err)
	}
	members, err := s.ListGroupMemberIDs(ctx, id)
	if err != nil {
		return nil, err
	}
	g.MemberIDs = members
	return g, nil
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}

func (s *Store) ListGroupMemberIDs(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_id FROM group_members WHERE group_id = $1 ORDER BY user_id`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) AddGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, groupID, userID)
	if err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, groupID, userID)
	if err != nil {
		return fmt.Errorf("remove group member: %w", err)
	}
	return nil
}

// ReplaceGroupMembers overwrites full membership (PUT semantics).
func (s *Store) ReplaceGroupMembers(ctx context.Context, groupID string, userIDs []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace group members: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1`, groupID); err != nil {
		return fmt.Errorf("clear group members: %w", err)
	}
	for _, uid := range userIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, groupID, uid); err != nil {
			return fmt.Errorf("insert group member: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit replace group members: %w", err)
	}
	return nil
}
