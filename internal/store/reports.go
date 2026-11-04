package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// maxReportKept is how many renderings of one report are retained. A
// report is history, so keeping some is the point; keeping all of them
// means an unbounded table of documents nobody will ever open, growing
// fastest for the report that runs most often.
const maxReportKept = 30

// maxPreviewKept is the preview shelf. Shallow on purpose: a preview is
// something you looked at once while writing the report, not a record of
// what the fleet looked like in September.
const maxPreviewKept = 5

// EmailTemplate is an email's wording: Go templates for each part. A blank
// field falls through to the next level, and finally the built-in default.
type EmailTemplate struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

type Report struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Sections     json.RawMessage `json:"sections"`
	SectionCount int             `json:"section_count"`
	Enabled      bool            `json:"enabled"`

	ScheduleKind string     `json:"schedule_kind"`
	TimeOfDay    string     `json:"time_of_day"`
	Weekday      *int       `json:"weekday,omitempty"`
	NextRunAt    *time.Time `json:"next_run_at,omitempty"`
	LastRunAt    *time.Time `json:"last_run_at,omitempty"`
	LastError    string     `json:"last_error,omitempty"`

	Destination  string `json:"destination"`
	Target       string `json:"target"`
	WebhookStyle string `json:"webhook_style,omitempty"`
	// EmailTemplate overrides the email this report goes out as. Blank fields
	// use Administration → Email's.
	EmailTemplate EmailTemplate `json:"email_template"`

	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// ReportRun is one rendering. HTML is omitted from list responses — a
// listing of thirty documents is a listing, not thirty documents.
type ReportRun struct {
	ID           string    `json:"id"`
	ReportID     string    `json:"report_id"`
	Name         string    `json:"name"`
	GeneratedAt  time.Time `json:"generated_at"`
	GeneratedBy  string    `json:"generated_by"`
	SectionCount int       `json:"section_count"`
	RowCount     int       `json:"row_count"`
	HTML         string    `json:"html,omitempty"`
	Summary      string    `json:"summary,omitempty"`
	Delivered    bool      `json:"delivered"`
	Preview      bool      `json:"preview,omitempty"`
	Error        string    `json:"error,omitempty"`
}

const reportColumns = `id, name, description, sections, enabled, schedule_kind, time_of_day,
       weekday, next_run_at, last_run_at, last_error, destination, target, webhook_style, email_template,
       created_at, created_by, updated_at, updated_by`

func scanReport(scan func(dest ...any) error) (Report, error) {
	var r Report
	var sections, emailTemplate []byte
	err := scan(&r.ID, &r.Name, &r.Description, &sections, &r.Enabled, &r.ScheduleKind,
		&r.TimeOfDay, &r.Weekday, &r.NextRunAt, &r.LastRunAt, &r.LastError,
		&r.Destination, &r.Target, &r.WebhookStyle, &emailTemplate,
		&r.CreatedAt, &r.CreatedBy, &r.UpdatedAt, &r.UpdatedBy)
	if err != nil {
		return r, err
	}
	r.Sections = sections
	_ = json.Unmarshal(emailTemplate, &r.EmailTemplate)
	var parsed []map[string]any
	_ = json.Unmarshal(sections, &parsed)
	r.SectionCount = len(parsed)
	return r, nil
}

func (s *Store) ListReports(ctx context.Context) ([]Report, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reportColumns+` FROM reports ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		r, err := scanReport(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan report: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetReport(ctx context.Context, id string) (*Report, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+reportColumns+` FROM reports WHERE id = $1`, id)
	r, err := scanReport(row.Scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		// Distinguished from "not found" deliberately: a connection reset
		// read as absence made a save audit itself as a create, and made a
		// playbook step report "no such report" for what was a database
		// problem.
		return nil, fmt.Errorf("get report: %w", err)
	}
	return &r, nil
}

func (s *Store) UpsertReport(ctx context.Context, r Report, nextRun *time.Time) error {
	sections := []byte(r.Sections)
	if len(sections) == 0 {
		sections = []byte("[]")
	}
	emailTemplate, err := json.Marshal(r.EmailTemplate)
	if err != nil {
		return fmt.Errorf("encode report email template: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO reports (id, name, description, sections, enabled, schedule_kind, time_of_day,
                     weekday, next_run_at, destination, target, webhook_style, created_by, updated_by, email_template)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, sections = EXCLUDED.sections,
  enabled = EXCLUDED.enabled, schedule_kind = EXCLUDED.schedule_kind,
  time_of_day = EXCLUDED.time_of_day, weekday = EXCLUDED.weekday,
  next_run_at = EXCLUDED.next_run_at, destination = EXCLUDED.destination,
  target = EXCLUDED.target, webhook_style = EXCLUDED.webhook_style,
  email_template = EXCLUDED.email_template,
  updated_at = now(), updated_by = EXCLUDED.updated_by`,
		r.ID, r.Name, r.Description, sections, r.Enabled, r.ScheduleKind, r.TimeOfDay,
		r.Weekday, nextRun, r.Destination, r.Target, r.WebhookStyle, r.UpdatedBy, emailTemplate)
	if err != nil {
		return fmt.Errorf("upsert report: %w", err)
	}
	return nil
}

func (s *Store) DeleteReport(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM reports WHERE id = $1`, id)
	return err
}

func (s *Store) DueReports(ctx context.Context, now time.Time) ([]Report, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+reportColumns+`
FROM reports WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1`, now)
	if err != nil {
		return nil, fmt.Errorf("list due reports: %w", err)
	}
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		r, err := scanReport(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan due report: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) MarkReportRun(ctx context.Context, id string, ranAt time.Time, next *time.Time, errText string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE reports SET last_run_at = $2, next_run_at = $3, last_error = $4 WHERE id = $1`,
		id, ranAt, next, errText)
	return err
}

// SaveReportRun stores one rendering and prunes the oldest beyond
// maxReportKept, so the table stays a shelf rather than an archive.
// GeneratedAt is stored as given, so the caller's answer and the stored
// run agree.
func (s *Store) SaveReportRun(ctx context.Context, r ReportRun) error {
	if _, err := s.pool.Exec(ctx, `
INSERT INTO report_runs (id, report_id, name, generated_at, generated_by, section_count, row_count, html, summary, delivered, preview, error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		r.ID, nullable(r.ReportID), r.Name, r.GeneratedAt, r.GeneratedBy, r.SectionCount, r.RowCount,
		r.HTML, r.Summary, r.Delivered, r.Preview, r.Error); err != nil {
		return fmt.Errorf("save report run: %w", err)
	}
	if r.ReportID != "" {
		// Two shelves, pruned separately, so previews can never evict the
		// archive they are not part of. The run just saved always stays:
		// it is dated when its rendering began, so a slow one can be the
		// oldest on its shelf, and its caller answers with its ID.
		const prune = `
DELETE FROM report_runs WHERE report_id = $1 AND preview = $3 AND id <> $4 AND id NOT IN (
  SELECT id FROM report_runs WHERE report_id = $1 AND preview = $3 AND id <> $4
  ORDER BY generated_at DESC LIMIT $2 - 1)`
		if _, err := s.pool.Exec(ctx, prune, r.ReportID, maxReportKept, false, r.ID); err != nil {
			return fmt.Errorf("prune report runs: %w", err)
		}
		if _, err := s.pool.Exec(ctx, prune, r.ReportID, maxPreviewKept, true, r.ID); err != nil {
			return fmt.Errorf("prune report previews: %w", err)
		}
	}
	return nil
}

// ListReportRuns omits the rendered documents themselves.
func (s *Store) ListReportRuns(ctx context.Context, reportID string, limit int) ([]ReportRun, error) {
	if limit <= 0 {
		limit = 30
	}
	rows, err := s.pool.Query(ctx, `
SELECT id, coalesce(report_id,''), name, generated_at, generated_by, section_count,
       row_count, delivered, preview, error
FROM report_runs WHERE ($1 = '' OR report_id = $1)
ORDER BY generated_at DESC LIMIT $2`, reportID, limit)
	if err != nil {
		return nil, fmt.Errorf("list report runs: %w", err)
	}
	defer rows.Close()
	out := []ReportRun{}
	for rows.Next() {
		var r ReportRun
		if err := rows.Scan(&r.ID, &r.ReportID, &r.Name, &r.GeneratedAt, &r.GeneratedBy,
			&r.SectionCount, &r.RowCount, &r.Delivered, &r.Preview, &r.Error); err != nil {
			return nil, fmt.Errorf("scan report run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetReportRun(ctx context.Context, id string) (*ReportRun, error) {
	var r ReportRun
	err := s.pool.QueryRow(ctx, `
SELECT id, coalesce(report_id,''), name, generated_at, generated_by, section_count,
       row_count, html, summary, delivered, preview, error
FROM report_runs WHERE id = $1`, id).
		Scan(&r.ID, &r.ReportID, &r.Name, &r.GeneratedAt, &r.GeneratedBy, &r.SectionCount,
			&r.RowCount, &r.HTML, &r.Summary, &r.Delivered, &r.Preview, &r.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		// Distinguished from "not found" deliberately: a connection reset
		// read as absence made a save audit itself as a create, and made a
		// playbook step report "no such report rendering" for what was a database
		// problem.
		return nil, fmt.Errorf("get report rendering: %w", err)
	}
	return &r, nil
}
