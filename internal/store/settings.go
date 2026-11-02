package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"time"
)

// Setting is one runtime-editable configuration value — see schema.sql for
// why this exists (the admin Settings tab, backed by Postgres rather than
// requiring a container restart to change SSO/backdoor/SCIM config).
type Setting struct {
	Key       string
	Value     string
	UpdatedAt time.Time
	UpdatedBy string
}

// GetAllSettings returns every stored setting as a plain key->value map —
// the shape callers actually want when seeding config at startup.
func (s *Store) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("get all settings: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan setting: %w", err)
		}
		out[k] = v
	}
	return out, rows.Err()
}

// ListSettings returns every stored setting with its metadata, for the
// admin settings view (who changed what, when).
func (s *Store) ListSettings(ctx context.Context) ([]Setting, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value, updated_at, updated_by FROM settings ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("list settings: %w", err)
	}
	defer rows.Close()
	var out []Setting
	for rows.Next() {
		var st Setting
		if err := rows.Scan(&st.Key, &st.Value, &st.UpdatedAt, &st.UpdatedBy); err != nil {
			return nil, fmt.Errorf("scan setting: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SetSetting upserts one setting. Used both for the initial env-derived
// seed (updatedBy "startup-seed") and for admin edits (updatedBy the
// editing user's username).
func (s *Store) SetSetting(ctx context.Context, key, value, updatedBy string) error {
	const q = `
INSERT INTO settings (key, value, updated_at, updated_by) VALUES ($1, $2, now(), $3)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`
	if _, err := s.pool.Exec(ctx, q, key, value, updatedBy); err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

// SetSettingIfAbsent seeds a default only if the key isn't already present
// — used at startup so env/flag values act as an initial value the first
// time the server ever boots, without stomping an admin's later edit on
// every subsequent restart.
func (s *Store) SetSettingIfAbsent(ctx context.Context, key, value, updatedBy string) error {
	const q = `
INSERT INTO settings (key, value, updated_at, updated_by) VALUES ($1, $2, now(), $3)
ON CONFLICT (key) DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, key, value, updatedBy); err != nil {
		return fmt.Errorf("seed setting %q: %w", key, err)
	}
	return nil
}

// GetSetting reads one setting. An absent key is an empty string rather
// than an error: callers overwhelmingly want "the value, or the default",
// and forcing every one of them to distinguish absence from failure
// produces more bugs than it prevents.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get setting %q: %w", key, err)
	}
	return value, nil
}

// ClaimSetting writes a key only if nobody has, and reports whether this
// call is the one that did it. SetSettingIfAbsent does the same write but
// cannot tell a caller it lost, which is the whole question when the write
// is a one-shot claim -- first-run setup uses it so two people opening a
// fresh console at once cannot both create the first administrator.
func (s *Store) ClaimSetting(ctx context.Context, key, value, updatedBy string) (bool, error) {
	const q = `
INSERT INTO settings (key, value, updated_at, updated_by) VALUES ($1, $2, now(), $3)
ON CONFLICT (key) DO NOTHING`
	tag, err := s.pool.Exec(ctx, q, key, value, updatedBy)
	if err != nil {
		return false, fmt.Errorf("claim setting %q: %w", key, err)
	}
	return tag.RowsAffected() == 1, nil
}

// CountUsers reports how many accounts exist, of any source. First-run
// setup asks so it can tell an empty deployment from one whose operator
// simply has not configured a break-glass account.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}
