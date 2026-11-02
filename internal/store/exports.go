package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// An export config is a standing instruction: take this source, in this
// format, to this destination, on this interval. History sources keep a
// cursor so a run sends what is new rather than everything again.

type ExportConfig struct {
	ID              string `json:"id"`
	Name            string `json:"name" api:"required"`
	Source          string `json:"source" api:"required"`
	SavedQuestionID string `json:"saved_question_id,omitempty"`
	Format          string `json:"format"`
	Destination     string `json:"destination" api:"required"`
	Target          string `json:"target"`
	WebhookStyle    string `json:"webhook_style,omitempty"` // "", "discord", "slack"
	// Headers are sent with a webhook post, an Authorization token
	// typically. They are stored sealed (HeadersSealed) and never listed;
	// Headers is set only on a row written before sealing, until it is
	// next saved, and in a request body.
	Headers map[string]string `json:"headers,omitempty"`
	// HeadersSealed is the vault-sealed JSON of the headers (the server
	// seals and opens it). Stored in the headers column as
	// {"$sealed": "..."}, so no migration touches rows written before.
	HeadersSealed   string     `json:"-"`
	IntervalMinutes int        `json:"interval_minutes"` // 0 = manual only
	Enabled         bool       `json:"enabled"`
	Cursor          string     `json:"cursor,omitempty" api:"readonly"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty" api:"readonly"`
	LastRowCount    int        `json:"last_row_count" api:"readonly"`
	LastError       string     `json:"last_error,omitempty" api:"readonly"`
	CreatedAt       time.Time  `json:"created_at" api:"readonly"`
	CreatedBy       string     `json:"created_by" api:"readonly"`
}

// sealedHeadersKey marks a headers column holding the sealed form.
const sealedHeadersKey = "$sealed"

const exportColumns = `id, name, source, saved_question_id, format, destination, target,
       webhook_style, headers, interval_minutes, enabled, cursor, last_run_at,
       last_row_count, last_error, created_at, created_by`

func scanExport(row pgx.Row) (*ExportConfig, error) {
	var c ExportConfig
	var headers []byte
	if err := row.Scan(&c.ID, &c.Name, &c.Source, &c.SavedQuestionID, &c.Format,
		&c.Destination, &c.Target, &c.WebhookStyle, &headers, &c.IntervalMinutes,
		&c.Enabled, &c.Cursor, &c.LastRunAt, &c.LastRowCount, &c.LastError,
		&c.CreatedAt, &c.CreatedBy); err != nil {
		return nil, err
	}
	var raw map[string]string
	_ = json.Unmarshal(headers, &raw)
	if sealed, ok := raw[sealedHeadersKey]; ok {
		c.HeadersSealed = sealed
	} else if len(raw) > 0 {
		c.Headers = raw
	}
	return &c, nil
}

// headersColumn is what the headers column holds for c: the sealed form
// when there is one, else the plain map (empty when there are none).
func (c ExportConfig) headersColumn() ([]byte, error) {
	if c.HeadersSealed != "" {
		return json.Marshal(map[string]string{sealedHeadersKey: c.HeadersSealed})
	}
	if c.Headers == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(c.Headers)
}

func (s *Store) ListExportConfigs(ctx context.Context) ([]ExportConfig, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+exportColumns+` FROM export_configs ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list export configs: %w", err)
	}
	defer rows.Close()
	var out []ExportConfig
	for rows.Next() {
		c, err := scanExport(rows)
		if err != nil {
			return nil, fmt.Errorf("scan export config: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Store) GetExportConfig(ctx context.Context, id string) (*ExportConfig, error) {
	c, err := scanExport(s.pool.QueryRow(ctx, `SELECT `+exportColumns+` FROM export_configs WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get export config: %w", err)
	}
	return c, nil
}

func (s *Store) UpsertExportConfig(ctx context.Context, c ExportConfig) (*ExportConfig, error) {
	headers, err := c.headersColumn()
	if err != nil {
		return nil, fmt.Errorf("encode headers: %w", err)
	}
	const q = `
INSERT INTO export_configs (id, name, source, saved_question_id, format, destination, target,
                            webhook_style, headers, interval_minutes, enabled, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, source = EXCLUDED.source, saved_question_id = EXCLUDED.saved_question_id,
  format = EXCLUDED.format, destination = EXCLUDED.destination, target = EXCLUDED.target,
  webhook_style = EXCLUDED.webhook_style, headers = EXCLUDED.headers,
  interval_minutes = EXCLUDED.interval_minutes, enabled = EXCLUDED.enabled
RETURNING ` + exportColumns
	out, err := scanExport(s.pool.QueryRow(ctx, q, c.ID, c.Name, c.Source, c.SavedQuestionID,
		c.Format, c.Destination, c.Target, c.WebhookStyle, headers, c.IntervalMinutes,
		c.Enabled, c.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("upsert export config: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteExportConfig(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM export_configs WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete export config: %w", err)
	}
	return nil
}

// RecordExportRun stores the outcome. An error is kept on the row rather
// than only logged, so a destination that has been failing for a week is
// visible in the list instead of buried in the server log.
func (s *Store) RecordExportRun(ctx context.Context, id string, rowCount int, errText string) error {
	_, err := s.pool.Exec(ctx, `
UPDATE export_configs SET last_run_at = now(), last_row_count = $2, last_error = $3 WHERE id = $1`,
		id, rowCount, errText)
	return err
}

func (s *Store) SetExportCursor(ctx context.Context, id, cursor string) error {
	_, err := s.pool.Exec(ctx, `UPDATE export_configs SET cursor = $2 WHERE id = $1`, id, cursor)
	return err
}

// DueExports are enabled configs with an interval whose next run has
// arrived. Evaluated in SQL so the scheduler doesn't load every config
// each tick.
func (s *Store) DueExports(ctx context.Context) ([]ExportConfig, error) {
	rows, err := s.pool.Query(ctx, `
SELECT `+exportColumns+` FROM export_configs
WHERE enabled AND interval_minutes > 0
  AND (last_run_at IS NULL OR last_run_at < now() - make_interval(mins => interval_minutes))`)
	if err != nil {
		return nil, fmt.Errorf("due exports: %w", err)
	}
	defer rows.Close()
	var out []ExportConfig
	for rows.Next() {
		c, err := scanExport(rows)
		if err != nil {
			return nil, fmt.Errorf("scan due export: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}
