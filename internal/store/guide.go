package store

import (
	"context"
	"fmt"
	"time"
)

// GuideNotification is one item in the tray.
type GuideNotification struct {
	ID          string     `json:"id"`
	SubjectKey  string     `json:"subject_key"`
	Source      string     `json:"source"`
	Kind        string     `json:"kind"`     // guidance | observation
	Severity    string     `json:"severity"` // critical | high | medium | low
	Title       string     `json:"title"`
	Detail      string     `json:"detail"`
	Link        string     `json:"link"`
	Count       int        `json:"count"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	DismissedAt *time.Time `json:"dismissed_at,omitempty"`
	DismissedBy string     `json:"dismissed_by,omitempty"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

const guideColumns = `id, subject_key, source, kind, severity, title, detail, link, count, first_seen, last_seen, dismissed_at, dismissed_by, resolved_at`

// UpsertGuide records that a condition holds right now. A row that was
// resolved earlier and is back is reopened as the same subject with a
// fresh first_seen -- and its dismissal cleared, because the operator
// dismissed the old occurrence, not this one. A dismissed row whose
// condition merely persists stays dismissed; only its details refresh.
func (s *Store) UpsertGuide(ctx context.Context, n GuideNotification) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO guide_notifications (`+guideColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),now(),NULL,'',NULL)
		ON CONFLICT (subject_key) DO UPDATE SET
		  kind=EXCLUDED.kind, severity=EXCLUDED.severity, title=EXCLUDED.title, detail=EXCLUDED.detail, link=EXCLUDED.link, count=EXCLUDED.count,
		  last_seen=now(),
		  first_seen=CASE WHEN guide_notifications.resolved_at IS NULL THEN guide_notifications.first_seen ELSE now() END,
		  dismissed_at=CASE WHEN guide_notifications.resolved_at IS NULL THEN guide_notifications.dismissed_at ELSE NULL END,
		  dismissed_by=CASE WHEN guide_notifications.resolved_at IS NULL THEN guide_notifications.dismissed_by ELSE '' END,
		  resolved_at=NULL`,
		n.ID, n.SubjectKey, n.Source, n.Kind, n.Severity, n.Title, n.Detail, n.Link, n.Count)
	if err != nil {
		return fmt.Errorf("upsert guide notification: %w", err)
	}
	return nil
}

// ResolveGuideExcept closes every open item from a source whose subject is
// not in keep: the evaluator saw the whole picture, and what it did not
// report is no longer true.
func (s *Store) ResolveGuideExcept(ctx context.Context, source string, keep []string) error {
	if keep == nil {
		keep = []string{}
	}
	_, err := s.pool.Exec(ctx, `UPDATE guide_notifications SET resolved_at = now()
		WHERE source = $1 AND resolved_at IS NULL AND NOT (subject_key = ANY($2))`, source, keep)
	if err != nil {
		return fmt.Errorf("resolve guide notifications: %w", err)
	}
	return nil
}

// ListGuide returns open items (not resolved, not dismissed) unless all
// is set, in which case everything from the last thirty days comes back
// for the history view.
func (s *Store) ListGuide(ctx context.Context, all bool) ([]GuideNotification, error) {
	q := `SELECT ` + guideColumns + ` FROM guide_notifications WHERE resolved_at IS NULL AND dismissed_at IS NULL
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, last_seen DESC`
	if all {
		q = `SELECT ` + guideColumns + ` FROM guide_notifications WHERE last_seen > now() - interval '30 days'
			ORDER BY (resolved_at IS NULL AND dismissed_at IS NULL) DESC, last_seen DESC LIMIT 500`
	}
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list guide notifications: %w", err)
	}
	defer rows.Close()
	out := []GuideNotification{}
	for rows.Next() {
		var n GuideNotification
		if err := rows.Scan(&n.ID, &n.SubjectKey, &n.Source, &n.Kind, &n.Severity, &n.Title, &n.Detail, &n.Link, &n.Count,
			&n.FirstSeen, &n.LastSeen, &n.DismissedAt, &n.DismissedBy, &n.ResolvedAt); err != nil {
			return nil, fmt.Errorf("scan guide notification: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) DismissGuide(ctx context.Context, id, who string, dismissed bool) (bool, error) {
	q := `UPDATE guide_notifications SET dismissed_at = now(), dismissed_by = $2 WHERE id = $1 AND resolved_at IS NULL`
	if !dismissed {
		q = `UPDATE guide_notifications SET dismissed_at = NULL, dismissed_by = '' WHERE id = $1 AND $2 = $2`
	}
	tag, err := s.pool.Exec(ctx, q, id, who)
	if err != nil {
		return false, fmt.Errorf("dismiss guide notification: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// GuideCounts is what the bell shows.
type GuideCounts struct {
	Open     int `json:"open"`
	Critical int `json:"critical"`
	High     int `json:"high"`
}

func (s *Store) GuideCounts(ctx context.Context) (GuideCounts, error) {
	var c GuideCounts
	err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE severity='critical'), count(*) FILTER (WHERE severity='high')
		FROM guide_notifications WHERE resolved_at IS NULL AND dismissed_at IS NULL`).Scan(&c.Open, &c.Critical, &c.High)
	if err != nil {
		return c, fmt.Errorf("guide counts: %w", err)
	}
	return c, nil
}
