package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file backs Scan Management (a subcategory of the Patches tab):
// named, reusable repo definitions ("patch lists") an admin can assign to
// specific hosts/sites/platforms, scoping what an agent's patch scan/apply
// draws from instead of whatever's natively configured on the host. See
// schema.sql's patch_lists/patch_list_assignments comments for the field
// semantics, and internal/server/patchlist_query.go for how an agent
// resolves which list (if any) applies to it.

// PatchList is one named repo definition.
type PatchList struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	OSFamily    string    `json:"os_family"` // "apt" | "dnf"
	Repos       string    `json:"repos"`     // newline-separated
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

const patchListColumns = `id, name, os_family, repos, description, created_at, created_by`

func scanPatchList(row pgx.Row) (*PatchList, error) {
	var pl PatchList
	if err := row.Scan(&pl.ID, &pl.Name, &pl.OSFamily, &pl.Repos, &pl.Description, &pl.CreatedAt, &pl.CreatedBy); err != nil {
		return nil, err
	}
	return &pl, nil
}

func (s *Store) CreatePatchList(ctx context.Context, pl PatchList) (*PatchList, error) {
	const q = `
INSERT INTO patch_lists (id, name, os_family, repos, description, created_by)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING ` + patchListColumns
	row := s.pool.QueryRow(ctx, q, pl.ID, pl.Name, pl.OSFamily, pl.Repos, pl.Description, pl.CreatedBy)
	out, err := scanPatchList(row)
	if err != nil {
		return nil, fmt.Errorf("create patch list: %w", err)
	}
	return out, nil
}

func (s *Store) ListPatchLists(ctx context.Context) ([]PatchList, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+patchListColumns+` FROM patch_lists ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list patch lists: %w", err)
	}
	defer rows.Close()
	out := []PatchList{}
	for rows.Next() {
		pl, err := scanPatchList(rows)
		if err != nil {
			return nil, fmt.Errorf("scan patch list: %w", err)
		}
		out = append(out, *pl)
	}
	return out, rows.Err()
}

// GetPatchList returns one list, or nil when there is none.
func (s *Store) GetPatchList(ctx context.Context, id string) (*PatchList, error) {
	pl, err := scanPatchList(s.pool.QueryRow(ctx, `SELECT `+patchListColumns+` FROM patch_lists WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get patch list: %w", err)
	}
	return pl, nil
}

// GetPatchListAssignment returns one assignment with its list's name, or
// nil when there is none.
func (s *Store) GetPatchListAssignment(ctx context.Context, id string) (*PatchListAssignment, error) {
	var a PatchListAssignment
	err := s.pool.QueryRow(ctx, `
SELECT a.id, a.patch_list_id, coalesce(pl.name, ''), a.target_platform, a.target_site, a.target_agent, a.created_at, a.created_by
FROM patch_list_assignments a LEFT JOIN patch_lists pl ON pl.id = a.patch_list_id
WHERE a.id = $1`, id).Scan(&a.ID, &a.PatchListID, &a.PatchListName, &a.TargetPlatform, &a.TargetSite, &a.TargetAgent, &a.CreatedAt, &a.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get patch list assignment: %w", err)
	}
	return &a, nil
}

// DeletePatchList removes a patch list; its assignments cascade (FK ON
// DELETE CASCADE), so any host relying on it silently falls back to native
// repos on its next scan/apply rather than erroring.
func (s *Store) DeletePatchList(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM patch_lists WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete patch list: %w", err)
	}
	return nil
}

// PatchListAssignment is one targeting rule pointing a slice of the fleet
// at a patch list. One naming an endpoint applies to that endpoint
// whatever else it names; otherwise a host must match both the site and
// the platform, where set. When several match, the most specific wins:
// endpoint, then site and platform, then site, then platform.
type PatchListAssignment struct {
	ID             string    `json:"id"`
	PatchListID    string    `json:"patch_list_id"`
	PatchListName  string    `json:"patch_list_name"` // joined in, for the UI — not a stored column
	TargetPlatform string    `json:"target_platform"`
	TargetSite     string    `json:"target_site"`
	TargetAgent    string    `json:"target_agent"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
}

func (s *Store) CreatePatchListAssignment(ctx context.Context, a PatchListAssignment) (*PatchListAssignment, error) {
	// The list's name is joined in, as the list of assignments has it, so
	// the answer to a create is the row that list will show.
	const q = `
WITH a AS (
  INSERT INTO patch_list_assignments (id, patch_list_id, target_platform, target_site, target_agent, created_by)
  VALUES ($1, $2, $3, $4, $5, $6)
  RETURNING id, patch_list_id, target_platform, target_site, target_agent, created_at, created_by
)
SELECT a.id, a.patch_list_id, coalesce(pl.name, ''), a.target_platform, a.target_site, a.target_agent, a.created_at, a.created_by
FROM a LEFT JOIN patch_lists pl ON pl.id = a.patch_list_id`
	row := s.pool.QueryRow(ctx, q, a.ID, a.PatchListID, a.TargetPlatform, a.TargetSite, a.TargetAgent, a.CreatedBy)
	var out PatchListAssignment
	if err := row.Scan(&out.ID, &out.PatchListID, &out.PatchListName, &out.TargetPlatform, &out.TargetSite, &out.TargetAgent, &out.CreatedAt, &out.CreatedBy); err != nil {
		return nil, fmt.Errorf("create patch list assignment: %w", err)
	}
	return &out, nil
}

// ListPatchListAssignments returns every assignment with its patch list's
// name joined in, for the Scan Management table.
func (s *Store) ListPatchListAssignments(ctx context.Context) ([]PatchListAssignment, error) {
	const q = `
SELECT a.id, a.patch_list_id, pl.name, a.target_platform, a.target_site, a.target_agent, a.created_at, a.created_by
FROM patch_list_assignments a
JOIN patch_lists pl ON pl.id = a.patch_list_id
ORDER BY a.created_at DESC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list patch list assignments: %w", err)
	}
	defer rows.Close()
	out := []PatchListAssignment{}
	for rows.Next() {
		var a PatchListAssignment
		if err := rows.Scan(&a.ID, &a.PatchListID, &a.PatchListName, &a.TargetPlatform, &a.TargetSite, &a.TargetAgent, &a.CreatedAt, &a.CreatedBy); err != nil {
			return nil, fmt.Errorf("scan patch list assignment: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) DeletePatchListAssignment(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM patch_list_assignments WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete patch list assignment: %w", err)
	}
	return nil
}

// ResolvePatchListForAgent returns the patch list (if any) that applies to
// a given agent. An assignment naming the agent applies to it whatever
// site or platform it also names. Otherwise an assignment matches only
// when both its site and its platform, where set, match the agent: "site
// hq, platform debian" is for the Debian hosts at hq, not every host
// there. Of the matches, the most specific wins: one naming the agent,
// then site and platform, then site, then platform. Within a rank the most
// recent assignment wins, and the ID settles rows created at the same
// instant, so the answer never rests on row order. Returns (nil, nil) when
// no rule matches — the caller should fall back to native/official repos.
//
// This is the only place assignments are resolved; the agent's
// patch-list query (internal/server/patchlist_query.go) answers from it.
func (s *Store) ResolvePatchListForAgent(ctx context.Context, agentID, platform, site string) (*PatchList, error) {
	// The handler refuses an assignment with no target, but a row like
	// that would match every host here, so it is excluded explicitly
	// rather than trusted never to exist.
	const q = `
SELECT pl.id, pl.name, pl.os_family, pl.repos, pl.description, pl.created_at, pl.created_by
FROM patch_list_assignments a
JOIN patch_lists pl ON pl.id = a.patch_list_id
WHERE a.target_agent = $1
   OR (a.target_agent = ''
       AND (a.target_site <> '' OR a.target_platform <> '')
       AND (a.target_site = '' OR a.target_site = $3)
       AND (a.target_platform = '' OR a.target_platform = $2))
ORDER BY
  CASE
    WHEN a.target_agent <> '' THEN 0
    WHEN a.target_site <> '' AND a.target_platform <> '' THEN 1
    WHEN a.target_site <> '' THEN 2
    ELSE 3
  END,
  a.created_at DESC,
  a.id
LIMIT 1`
	row := s.pool.QueryRow(ctx, q, agentID, platform, site)
	pl, err := scanPatchList(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("resolve patch list for agent: %w", err)
	}
	return pl, nil
}
