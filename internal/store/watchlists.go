package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Watchlist is a named set of paths and registry keys to monitor.
type Watchlist struct {
	ID             string    `json:"id"`
	Name           string    `json:"name" api:"required"`
	Description    string    `json:"description"`
	Template       string    `json:"template"`
	Paths          []string  `json:"paths"`
	RegistryKeys   []string  `json:"registry_keys"`
	FollowSymlinks bool      `json:"follow_symlinks"`
	CreatedBy      string    `json:"created_by" api:"readonly"`
	CreatedAt      time.Time `json:"created_at" api:"readonly"`
	UpdatedAt      time.Time `json:"updated_at" api:"readonly"`
}

const watchlistColumns = `id, name, description, template, paths, registry_keys, follow_symlinks, created_by, created_at, updated_at`

func scanWatchlist(row interface{ Scan(...any) error }) (Watchlist, error) {
	var w Watchlist
	err := row.Scan(&w.ID, &w.Name, &w.Description, &w.Template, &w.Paths, &w.RegistryKeys, &w.FollowSymlinks, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt)
	if w.Paths == nil {
		w.Paths = []string{}
	}
	if w.RegistryKeys == nil {
		w.RegistryKeys = []string{}
	}
	return w, err
}

func (s *Store) ListWatchlists(ctx context.Context) ([]Watchlist, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+watchlistColumns+` FROM watchlists ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list watchlists: %w", err)
	}
	defer rows.Close()
	out := []Watchlist{}
	for rows.Next() {
		w, err := scanWatchlist(rows)
		if err != nil {
			return nil, fmt.Errorf("scan watchlist: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) GetWatchlist(ctx context.Context, id string) (*Watchlist, error) {
	w, err := scanWatchlist(s.pool.QueryRow(ctx, `SELECT `+watchlistColumns+` FROM watchlists WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get watchlist: %w", err)
	}
	return &w, nil
}

func (s *Store) UpsertWatchlist(ctx context.Context, w Watchlist) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO watchlists (`+watchlistColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, template=EXCLUDED.template, paths=EXCLUDED.paths,
		registry_keys=EXCLUDED.registry_keys, follow_symlinks=EXCLUDED.follow_symlinks, updated_at=now()`,
		w.ID, w.Name, w.Description, w.Template, w.Paths, w.RegistryKeys, w.FollowSymlinks, w.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert watchlist: %w", err)
	}
	return nil
}

func (s *Store) DeleteWatchlist(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM watchlists WHERE id = $1`, id)
	return err
}

// IntegrityMonitor applies a watchlist to computer groups.
type IntegrityMonitor struct {
	ID            string    `json:"id"`
	Name          string    `json:"name" api:"required"`
	WatchlistID   string    `json:"watchlist_id" api:"required"`
	WatchlistName string    `json:"watchlist_name" api:"readonly"`
	GroupIDs      []string  `json:"group_ids" api:"required"`
	Enabled       bool      `json:"enabled"`
	CreatedBy     string    `json:"created_by" api:"readonly"`
	CreatedAt     time.Time `json:"created_at" api:"readonly"`
	UpdatedAt     time.Time `json:"updated_at" api:"readonly"`
}

func (s *Store) ListIntegrityMonitors(ctx context.Context) ([]IntegrityMonitor, error) {
	rows, err := s.pool.Query(ctx, `SELECT m.id, m.name, m.watchlist_id, coalesce(w.name, ''), m.group_ids, m.enabled, m.created_by, m.created_at, m.updated_at
		FROM integrity_monitors m LEFT JOIN watchlists w ON w.id = m.watchlist_id ORDER BY lower(m.name)`)
	if err != nil {
		return nil, fmt.Errorf("list integrity monitors: %w", err)
	}
	defer rows.Close()
	out := []IntegrityMonitor{}
	for rows.Next() {
		var m IntegrityMonitor
		if err := rows.Scan(&m.ID, &m.Name, &m.WatchlistID, &m.WatchlistName, &m.GroupIDs, &m.Enabled, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan integrity monitor: %w", err)
		}
		if m.GroupIDs == nil {
			m.GroupIDs = []string{}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) GetIntegrityMonitor(ctx context.Context, id string) (*IntegrityMonitor, error) {
	list, err := s.ListIntegrityMonitors(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, nil
}

func (s *Store) UpsertIntegrityMonitor(ctx context.Context, m IntegrityMonitor) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO integrity_monitors (id, name, watchlist_id, group_ids, enabled, created_by, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, watchlist_id=EXCLUDED.watchlist_id, group_ids=EXCLUDED.group_ids, enabled=EXCLUDED.enabled, updated_at=now()`,
		m.ID, m.Name, m.WatchlistID, m.GroupIDs, m.Enabled, m.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert integrity monitor: %w", err)
	}
	return nil
}

func (s *Store) DeleteIntegrityMonitor(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM integrity_monitors WHERE id = $1`, id)
	return err
}

// IntegrityLabel is a rule that tags a change, and may mark it expected.
type IntegrityLabel struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Expected  bool            `json:"expected"`
	Criteria  json.RawMessage `json:"criteria" api:"required"`
	Priority  int             `json:"priority"`
	Enabled   bool            `json:"enabled"`
	CreatedBy string          `json:"created_by" api:"readonly"`
	CreatedAt time.Time       `json:"created_at" api:"readonly"`
	UpdatedAt time.Time       `json:"updated_at" api:"readonly"`
}

func (s *Store) ListIntegrityLabels(ctx context.Context) ([]IntegrityLabel, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, expected, criteria, priority, enabled, created_by, created_at, updated_at FROM integrity_labels ORDER BY priority DESC, lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list integrity labels: %w", err)
	}
	defer rows.Close()
	out := []IntegrityLabel{}
	for rows.Next() {
		var l IntegrityLabel
		var crit []byte
		if err := rows.Scan(&l.ID, &l.Name, &l.Expected, &crit, &l.Priority, &l.Enabled, &l.CreatedBy, &l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan integrity label: %w", err)
		}
		l.Criteria = json.RawMessage(crit)
		if len(l.Criteria) == 0 {
			l.Criteria = json.RawMessage("{}")
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) GetIntegrityLabel(ctx context.Context, id string) (*IntegrityLabel, error) {
	list, err := s.ListIntegrityLabels(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, nil
}

func (s *Store) UpsertIntegrityLabel(ctx context.Context, l IntegrityLabel) error {
	if len(l.Criteria) == 0 {
		l.Criteria = json.RawMessage("{}")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO integrity_labels (id, name, expected, criteria, priority, enabled, created_by, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, expected=EXCLUDED.expected, criteria=EXCLUDED.criteria, priority=EXCLUDED.priority, enabled=EXCLUDED.enabled, updated_at=now()`,
		l.ID, l.Name, l.Expected, []byte(l.Criteria), l.Priority, l.Enabled, l.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert integrity label: %w", err)
	}
	return nil
}

func (s *Store) DeleteIntegrityLabel(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM integrity_labels WHERE id = $1`, id)
	return err
}

// AcknowledgeIntegrityChange marks a change investigated; the gap between
// detection and this is what mean time to investigate measures.
func (s *Store) AcknowledgeIntegrityChange(ctx context.Context, id int64, who string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE integrity_changes SET acknowledged_at = now(), acknowledged_by = $2 WHERE id = $1 AND acknowledged_at IS NULL`, id, who)
	if err != nil {
		return false, fmt.Errorf("acknowledge integrity change: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// IntegrityMetrics are the Integrity Monitor headline numbers.
type IntegrityMetrics struct {
	Unexpected7d      int      `json:"unexpected_7d"`
	Expected7d        int      `json:"expected_7d"`
	Unacknowledged    int      `json:"unacknowledged"`
	MeanInvestigateHr *float64 `json:"mean_time_to_investigate_hours,omitempty"`
	// ByEndpoint are the ten endpoints with the most unexpected changes,
	// most first.
	ByEndpoint []IntegrityEndpointCount `json:"by_endpoint"`
}

// IntegrityEndpointCount is one endpoint's unexpected changes.
type IntegrityEndpointCount struct {
	AgentID string `json:"agent_id"`
	// Hostname is empty for an endpoint since removed.
	Hostname string `json:"hostname"`
	// Unexpected is how many of its changes were not expected.
	Unexpected int `json:"unexpected"`
}

func (s *Store) IntegrityMetricsSince(ctx context.Context, since time.Time) (IntegrityMetrics, error) {
	m := IntegrityMetrics{ByEndpoint: []IntegrityEndpointCount{}}
	err := s.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE NOT expected),
		count(*) FILTER (WHERE expected),
		count(*) FILTER (WHERE NOT expected AND acknowledged_at IS NULL),
		avg(EXTRACT(EPOCH FROM (acknowledged_at - detected_at)) / 3600.0) FILTER (WHERE acknowledged_at IS NOT NULL)
		FROM integrity_changes WHERE detected_at >= $1`, since).Scan(&m.Unexpected7d, &m.Expected7d, &m.Unacknowledged, &m.MeanInvestigateHr)
	if err != nil {
		return m, fmt.Errorf("integrity metrics: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT c.agent_id, coalesce(a.hostname, ''), count(*)::int FROM integrity_changes c LEFT JOIN agents a ON a.agent_id = c.agent_id
		WHERE c.detected_at >= $1 AND NOT c.expected GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10`, since)
	if err != nil {
		return m, fmt.Errorf("integrity metrics by endpoint: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r IntegrityEndpointCount
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.Unexpected); err != nil {
			return m, err
		}
		m.ByEndpoint = append(m.ByEndpoint, r)
	}
	return m, rows.Err()
}

// GetWatchBaseline returns the roots an endpoint's last diffed snapshot
// covered; nil when there is no record yet.
func (s *Store) GetWatchBaseline(ctx context.Context, agentID string) (string, []string, error) {
	var rev string
	var roots []string
	err := s.pool.QueryRow(ctx, `SELECT revision, roots FROM agent_watch_baseline WHERE agent_id = $1`, agentID).Scan(&rev, &roots)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, nil
		}
		return "", nil, fmt.Errorf("get watch baseline: %w", err)
	}
	return rev, roots, nil
}

func (s *Store) SetWatchBaseline(ctx context.Context, agentID, revision string, roots []string) error {
	if roots == nil {
		roots = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO agent_watch_baseline (agent_id, revision, roots, updated_at) VALUES ($1,$2,$3,now())
		ON CONFLICT (agent_id) DO UPDATE SET revision = EXCLUDED.revision, roots = EXCLUDED.roots, updated_at = now()`, agentID, revision, roots)
	if err != nil {
		return fmt.Errorf("set watch baseline: %w", err)
	}
	return nil
}

// ApplyExpectedLabelToPastChanges marks already-recorded changes under a
// path prefix as expected and tags them, for a label seeded after the
// change was recorded. Whether a change needs investigating is a property
// of the change, not of when someone wrote the rule — and leaving a
// fleet's existing Windows task churn unlabelled would make "awaiting
// investigation" useless on the day the label ships. Returns rows changed.
//
// starts_with, not LIKE: these paths are full of backslashes and LIKE
// reads a backslash as its escape character, so the Windows prefix this
// exists for would match nothing at all.
func (s *Store) ApplyExpectedLabelToPastChanges(ctx context.Context, pathPrefix, kind, labelName string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE integrity_changes
SET expected = true, because = $3, labels = array_append(labels, $4)
WHERE NOT expected AND kind = $2 AND starts_with(path, $1) AND NOT ($4 = ANY(labels))`,
		pathPrefix, kind, "label: "+labelName, labelName)
	if err != nil {
		return 0, fmt.Errorf("apply expected label to past changes: %w", err)
	}
	return tag.RowsAffected(), nil
}
