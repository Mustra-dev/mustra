package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Role is a named bundle of permission keys (see
// internal/server/auth/permissions.go for the fixed set mustra checks),
// assignable to a user or a group. Builtin roles ("admin", "user") can't
// be deleted or renamed but their description/permissions can still be
// inspected; "admin" is reseeded to the full permission set on every
// startup so it can't be crippled by accident.
//
// The JSON tags are not decoration. Without them the fields marshalled
// under their capitalised Go names while every other type in the API is
// lower_snake, and the console read it both ways in the same file: the
// roles table used the capitalised names and the assign-a-role dropdowns
// used the lower-case ones, so every dropdown rendered "undefined" and
// assigning a role to a group silently could not work.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	// ComputerGroupIDs are the role's management rights: the endpoints it
	// may act on. Empty means the whole fleet, so a role written before
	// management rights existed keeps working.
	ComputerGroupIDs []string  `json:"computer_group_ids"`
	IsBuiltin        bool      `json:"is_builtin"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

const roleColumns = `id, name, description, permissions, computer_group_ids, is_builtin, created_at, updated_at`

func scanRole(row pgx.Row) (*Role, error) {
	var r Role
	if err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Permissions, &r.ComputerGroupIDs, &r.IsBuiltin, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	if r.ComputerGroupIDs == nil {
		r.ComputerGroupIDs = []string{}
	}
	return &r, nil
}

// SeedBuiltinRoles ensures "admin" (always the full permission set passed
// in — reseeded every startup so new permission keys added by later
// releases are picked up automatically) and "user" (seeded once, empty by
// default, left alone thereafter so an admin's customization sticks)
// exist.
func (s *Store) SeedBuiltinRoles(ctx context.Context, allPermissions []string) error {
	const upsertAdmin = `
INSERT INTO roles (id, name, description, permissions, is_builtin, updated_at)
VALUES ('role-admin', 'admin', 'Full access to every admin feature.', $1, true, now())
ON CONFLICT (id) DO UPDATE SET permissions = EXCLUDED.permissions, is_builtin = true, updated_at = now()`
	if _, err := s.pool.Exec(ctx, upsertAdmin, allPermissions); err != nil {
		return fmt.Errorf("seed admin role: %w", err)
	}
	const insertUser = `
INSERT INTO roles (id, name, description, permissions, is_builtin, updated_at)
VALUES ('role-user', 'user', 'Read-only access.', '{fleet.read,audit.read}', true, now())
ON CONFLICT (id) DO NOTHING`
	if _, err := s.pool.Exec(ctx, insertUser); err != nil {
		return fmt.Errorf("seed user role: %w", err)
	}
	// ON CONFLICT DO NOTHING above means an existing deployment keeps
	// whatever description it was created with, and the old wording
	// ("Standard access") did not convey that this role is the read-only
	// one. Corrected in place, but only while it is still untouched, so a
	// deployment that has edited it keeps its own words. Permissions are
	// deliberately not touched here: that is the operator's to decide.
	//
	// The match list covers every wording this role has shipped with, so a
	// deployment that has already taken one of them still lands on the
	// current text — and one where an operator wrote their own is left
	// alone.
	const describeUser = `
UPDATE roles SET description = $1, updated_at = now()
WHERE id = 'role-user' AND description IN (
  'Standard access: view endpoints, run queries.',
  'Read-only: sees every endpoint, sensor, deployment and finding; changes nothing.'
)`
	if _, err := s.pool.Exec(ctx, describeUser, "Read-only access."); err != nil {
		return fmt.Errorf("describe user role: %w", err)
	}
	return nil
}

func (s *Store) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+roleColumns+` FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *Store) GetRole(ctx context.Context, id string) (*Role, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+roleColumns+` FROM roles WHERE id = $1`, id)
	r, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	return r, nil
}

func (s *Store) CreateRole(ctx context.Context, id, name, description string, permissions, groupIDs []string) (*Role, error) {
	if groupIDs == nil {
		groupIDs = []string{}
	}
	const q = `
INSERT INTO roles (id, name, description, permissions, computer_group_ids, is_builtin, updated_at)
VALUES ($1, $2, $3, $4, $5, false, now())
RETURNING ` + roleColumns
	row := s.pool.QueryRow(ctx, q, id, name, description, permissions, groupIDs)
	r, err := scanRole(row)
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}
	return r, nil
}

// UpdateRole edits name/description/permissions. Callers must check
// IsBuiltin themselves before allowing a rename (permissions on a builtin
// role can still be viewed but shouldn't be hand-edited outside the
// reseed — the HTTP handler enforces that, not this layer).
func (s *Store) UpdateRole(ctx context.Context, id, name, description string, permissions, groupIDs []string) (*Role, error) {
	if groupIDs == nil {
		groupIDs = []string{}
	}
	const q = `
UPDATE roles SET name = $2, description = $3, permissions = $4, computer_group_ids = $5, updated_at = now()
WHERE id = $1
RETURNING ` + roleColumns
	row := s.pool.QueryRow(ctx, q, id, name, description, permissions, groupIDs)
	r, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("update role: %w", err)
	}
	return r, nil
}

func (s *Store) DeleteRole(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM roles WHERE id = $1 AND is_builtin = false`, id)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	return nil
}

// --- Role assignment ---

func (s *Store) AssignUserRole(ctx context.Context, userID, roleID string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, userID, roleID)
	if err != nil {
		return fmt.Errorf("assign user role: %w", err)
	}
	return nil
}

func (s *Store) RemoveUserRole(ctx context.Context, userID, roleID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID)
	if err != nil {
		return fmt.Errorf("remove user role: %w", err)
	}
	return nil
}

func (s *Store) ListUserRoleIDs(ctx context.Context, userID string) ([]string, error) {
	return s.listIDs(ctx, `SELECT role_id FROM user_roles WHERE user_id = $1 ORDER BY role_id`, userID)
}

func (s *Store) AssignGroupRole(ctx context.Context, groupID, roleID string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, groupID, roleID)
	if err != nil {
		return fmt.Errorf("assign group role: %w", err)
	}
	return nil
}

func (s *Store) RemoveGroupRole(ctx context.Context, groupID, roleID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM group_roles WHERE group_id = $1 AND role_id = $2`, groupID, roleID)
	if err != nil {
		return fmt.Errorf("remove group role: %w", err)
	}
	return nil
}

func (s *Store) ListGroupRoleIDs(ctx context.Context, groupID string) ([]string, error) {
	return s.listIDs(ctx, `SELECT role_id FROM group_roles WHERE group_id = $1 ORDER BY role_id`, groupID)
}

// ListUserGroupIDs returns the IDs of every group userID directly belongs
// to — the admin Users tab's "which groups is this user in" view.
func (s *Store) ListUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	return s.listIDs(ctx, `SELECT group_id FROM group_members WHERE user_id = $1 ORDER BY group_id`, userID)
}

func (s *Store) listIDs(ctx context.Context, q string, arg string) ([]string, error) {
	rows, err := s.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, fmt.Errorf("list ids: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// EffectivePermissions returns the union of permission keys granted to
// userID by every role it holds directly plus every role granted to any
// group it belongs to. Does not consider the legacy users.is_admin
// fast-path flag — callers (the requirePermission middleware) check that
// separately since it grants everything unconditionally.
func (s *Store) EffectivePermissions(ctx context.Context, userID string) (map[string]bool, error) {
	const q = `
SELECT DISTINCT unnest(r.permissions) AS perm
FROM roles r
WHERE r.id IN (
    SELECT role_id FROM user_roles WHERE user_id = $1
    UNION
    SELECT gr.role_id FROM group_roles gr JOIN group_members gm ON gm.group_id = gr.group_id WHERE gm.user_id = $1
)`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("effective permissions: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		out[perm] = true
	}
	return out, rows.Err()
}

// GrandfatherAllUsersAdminOnce is a one-time migration for the introduction
// of RBAC: before permissions existed, every authenticated user could use
// every feature (deploy push, credential vault, etc.) — nothing was
// gated. Silently defaulting existing accounts to zero permissions the
// moment RBAC ships would lock people out of things they could do
// yesterday. So: the first time this ever runs (tracked by the
// "rbac.grandfather_done" setting), every existing user is flipped to
// is_admin — matching their actual prior access level — and the flag is
// set so it never runs again. Any user created after this point starts
// with no permissions, as intended; an admin can also freely revoke a
// grandfathered account's admin flag afterward via the Users tab.
func (s *Store) GrandfatherAllUsersAdminOnce(ctx context.Context) (ran bool, err error) {
	var done string
	err = s.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'rbac.grandfather_done'`).Scan(&done)
	if err == nil && done == "true" {
		return false, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("check grandfather migration state: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE users SET is_admin = true, updated_at = now() WHERE is_admin = false`)
	if err != nil {
		return false, fmt.Errorf("grandfather existing users as admin: %w", err)
	}
	if err := s.SetSetting(ctx, "rbac.grandfather_done", "true", "startup-migration"); err != nil {
		return false, err
	}
	// Reported only when it changed somebody: on a fresh database there is
	// nobody to grandfather, and saying "existing users granted admin" there
	// reads as if accounts were created.
	return tag.RowsAffected() > 0, nil
}

// SetUserAdmin toggles the legacy super-admin fast path (grants every
// permission unconditionally, independent of role assignment).
func (s *Store) SetUserAdmin(ctx context.Context, userID string, isAdmin bool) (*User, error) {
	const q = `UPDATE users SET is_admin = $2, updated_at = now() WHERE id = $1 RETURNING ` + userColumns
	row := s.pool.QueryRow(ctx, q, userID, isAdmin)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("set user admin: %w", err)
	}
	return u, nil
}

// RoleNamesForUser returns the names of the roles granted to a user, both
// directly and through group membership. It backs the profile menu's
// "Persona" line — the named permission set someone is
// acting under, and a thing worth being able to see at a glance when a
// console can act on a whole fleet.
func (s *Store) RoleNamesForUser(ctx context.Context, userID string) ([]string, error) {
	const q = `
SELECT DISTINCT r.name FROM roles r
LEFT JOIN user_roles ur ON ur.role_id = r.id
LEFT JOIN group_roles gr ON gr.role_id = r.id
LEFT JOIN group_members gm ON gm.group_id = gr.group_id
WHERE ur.user_id = $1 OR gm.user_id = $1
ORDER BY r.name`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("role names for user: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan role name: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// RecordSignIn rolls the current sign-in time into the previous one and
// stamps now as the latest, so "Last Sign In" can show the time before this
// session rather than this session's own start.
func (s *Store) RecordSignIn(ctx context.Context, userID string) error {
	const q = `UPDATE users SET previous_sign_in = last_sign_in, last_sign_in = now() WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("record sign in: %w", err)
	}
	return nil
}

// ManagementGroupsForUser returns the computer groups a user's roles limit
// them to, and whether they are unrestricted. Unrestricted wins: a user
// who holds one unscoped role is unscoped, because a role with no
// management rights means "the whole fleet" and adding a second role must
// not take away what the first one granted.
func (s *Store) ManagementGroupsForUser(ctx context.Context, userID string) (groupIDs []string, unrestricted bool, err error) {
	const q = `
SELECT r.computer_group_ids
FROM roles r
WHERE r.id IN (
    SELECT role_id FROM user_roles WHERE user_id = $1
    UNION
    SELECT gr.role_id FROM group_roles gr JOIN group_members gm ON gm.group_id = gr.group_id WHERE gm.user_id = $1
)`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, false, fmt.Errorf("management groups: %w", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	any := false
	for rows.Next() {
		var ids []string
		if err := rows.Scan(&ids); err != nil {
			return nil, false, fmt.Errorf("scan management groups: %w", err)
		}
		any = true
		if len(ids) == 0 {
			return nil, true, nil
		}
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				groupIDs = append(groupIDs, id)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	// No roles at all is not the same as an unscoped role, but a user with
	// no roles holds no permissions either, so nothing reaches a scope
	// check. Treat it as unrestricted rather than inventing a denial the
	// permission layer already makes.
	if !any {
		return nil, true, nil
	}
	return groupIDs, false, nil
}

// ContentSetIDsForUser returns the content sets a user's roles grant, and
// whether they are unrestricted (a role holding no content set sees all).
func (s *Store) ContentSetIDsForUser(ctx context.Context, userID string) (ids []string, unrestricted bool, err error) {
	const q = `
SELECT r.id, coalesce(array_agg(rcs.content_set_id) FILTER (WHERE rcs.content_set_id IS NOT NULL), '{}')
FROM roles r
LEFT JOIN role_content_sets rcs ON rcs.role_id = r.id
WHERE r.id IN (
    SELECT role_id FROM user_roles WHERE user_id = $1
    UNION
    SELECT gr.role_id FROM group_roles gr JOIN group_members gm ON gm.group_id = gr.group_id WHERE gm.user_id = $1
)
GROUP BY r.id`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, false, fmt.Errorf("content sets for user: %w", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	any := false
	for rows.Next() {
		var roleID string
		var sets []string
		if err := rows.Scan(&roleID, &sets); err != nil {
			return nil, false, fmt.Errorf("scan content sets: %w", err)
		}
		any = true
		if len(sets) == 0 {
			return nil, true, nil
		}
		for _, id := range sets {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if !any {
		return nil, true, nil
	}
	return ids, false, nil
}

// SetRoleContentSets replaces a role's content sets.
func (s *Store) SetRoleContentSets(ctx context.Context, roleID string, setIDs []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM role_content_sets WHERE role_id = $1`, roleID); err != nil {
		return fmt.Errorf("clear role content sets: %w", err)
	}
	for _, id := range setIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO role_content_sets (role_id, content_set_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, roleID, id); err != nil {
			return fmt.Errorf("add role content set: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// RoleContentSetIDs lists one role's content sets.
func (s *Store) RoleContentSetIDs(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT content_set_id FROM role_content_sets WHERE role_id = $1 ORDER BY content_set_id`, roleID)
	if err != nil {
		return nil, fmt.Errorf("role content sets: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
