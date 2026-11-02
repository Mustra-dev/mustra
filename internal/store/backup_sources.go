package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// BackupSource is a connected backup system (see backupsrc). Secret is
// sealed by the server and never leaves it.
type BackupSource struct {
	ID          string     `json:"id" api:"readonly"`
	Kind        string     `json:"kind" api:"required"` // pbs | rubrik
	Name        string     `json:"name" api:"required"`
	URL         string     `json:"url" api:"required"`
	TokenID     string     `json:"token_id"`
	Secret      string     `json:"-"`
	Fingerprint string     `json:"fingerprint"`
	Datastore   string     `json:"datastore"`
	Enabled     bool       `json:"enabled"`
	LastPolled  *time.Time `json:"last_polled_at,omitempty" api:"readonly"`
	LastOK      *time.Time `json:"last_ok_at,omitempty" api:"readonly"`
	LastError   string     `json:"last_error" api:"readonly"`
	// LastResult is the newest successful read, as backupsrc.Result JSON.
	LastResult json.RawMessage `json:"-"`
	CreatedBy  string          `json:"created_by" api:"readonly"`
	CreatedAt  time.Time       `json:"created_at" api:"readonly"`
	UpdatedAt  time.Time       `json:"updated_at" api:"readonly"`
}

const backupSourceColumns = `id, kind, name, url, token_id, secret, fingerprint, datastore, enabled,
	last_polled_at, last_ok_at, last_error, last_result, created_by, created_at, updated_at`

func scanBackupSource(row pgx.Row) (*BackupSource, error) {
	var b BackupSource
	var result []byte
	if err := row.Scan(&b.ID, &b.Kind, &b.Name, &b.URL, &b.TokenID, &b.Secret, &b.Fingerprint, &b.Datastore, &b.Enabled,
		&b.LastPolled, &b.LastOK, &b.LastError, &result, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt); err != nil {
		return nil, err
	}
	b.LastResult = result
	return &b, nil
}

func (s *Store) ListBackupSources(ctx context.Context) ([]BackupSource, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+backupSourceColumns+` FROM backup_sources ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list backup sources: %w", err)
	}
	defer rows.Close()
	out := []BackupSource{}
	for rows.Next() {
		b, err := scanBackupSource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan backup source: %w", err)
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// GetBackupSource returns one source, or nil when there is none.
func (s *Store) GetBackupSource(ctx context.Context, id string) (*BackupSource, error) {
	b, err := scanBackupSource(s.pool.QueryRow(ctx, `SELECT `+backupSourceColumns+` FROM backup_sources WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get backup source: %w", err)
	}
	return b, nil
}

// SaveBackupSource inserts or updates a source's settings and secret.
// Poll state is left as it is.
func (s *Store) SaveBackupSource(ctx context.Context, b BackupSource) (*BackupSource, error) {
	out, err := scanBackupSource(s.pool.QueryRow(ctx, `
INSERT INTO backup_sources (id, kind, name, url, token_id, secret, fingerprint, datastore, enabled, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, url = EXCLUDED.url, token_id = EXCLUDED.token_id,
  secret = EXCLUDED.secret, fingerprint = EXCLUDED.fingerprint, datastore = EXCLUDED.datastore,
  enabled = EXCLUDED.enabled, updated_at = now()
RETURNING `+backupSourceColumns,
		b.ID, b.Kind, b.Name, b.URL, b.TokenID, b.Secret, b.Fingerprint, b.Datastore, b.Enabled, b.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("save backup source: %w", err)
	}
	return out, nil
}

// RecordBackupSourcePoll stores a poll's outcome: the result when it
// worked, the error when it did not (the last good result is kept).
func (s *Store) RecordBackupSourcePoll(ctx context.Context, id string, result []byte, pollErr string) error {
	var err error
	if pollErr == "" {
		_, err = s.pool.Exec(ctx, `UPDATE backup_sources SET last_polled_at = now(), last_ok_at = now(), last_error = '', last_result = $2 WHERE id = $1`, id, result)
	} else {
		_, err = s.pool.Exec(ctx, `UPDATE backup_sources SET last_polled_at = now(), last_error = $2 WHERE id = $1`, id, pollErr)
	}
	if err != nil {
		return fmt.Errorf("record backup source poll: %w", err)
	}
	return nil
}

func (s *Store) DeleteBackupSource(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM backup_sources WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete backup source: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
