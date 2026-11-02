package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// PresenceRow is one normalised product on one endpoint, as the inventory
// rollup writes it and the inventory view reads it back.
type PresenceRow struct {
	AgentID          string
	Hostname         string
	OS               string
	Online           bool
	ProductKey       string
	Name             string
	Vendor           string
	Version          string
	Executable       string
	InstallDate      string
	LastUsedReported time.Time // zero when the endpoint reported none
	FirstSeen        time.Time
	LastSeen         time.Time
}

// UpsertPresence records the products seen on one endpoint in this
// rollup. Everything on the endpoint that is not in rows is marked
// removed; a product that comes back clears removed_at and keeps its
// original first_seen, which is the point of keeping the row at all.
func (s *Store) UpsertPresence(ctx context.Context, agentID string, at time.Time, rows []PresenceRow) error {
	n := len(rows)
	keys := make([]string, n)
	names := make([]string, n)
	vendors := make([]string, n)
	versions := make([]string, n)
	exes := make([]string, n)
	dates := make([]string, n)
	used := make([]*time.Time, n)
	for i, r := range rows {
		keys[i], names[i], vendors[i], versions[i], exes[i], dates[i] = r.ProductKey, r.Name, r.Vendor, r.Version, r.Executable, r.InstallDate
		if !r.LastUsedReported.IsZero() {
			t := r.LastUsedReported
			used[i] = &t
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if n > 0 {
		_, err = tx.Exec(ctx, `
INSERT INTO software_presence (agent_id, product_key, name, vendor, version, executable, install_date, last_used_reported, first_seen, last_seen)
SELECT $1, k, n, v, ver, e, d, u, $2, $2
FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::timestamptz[]) AS t(k, n, v, ver, e, d, u)
ON CONFLICT (agent_id, product_key) DO UPDATE SET
  name = EXCLUDED.name, vendor = EXCLUDED.vendor, version = EXCLUDED.version,
  executable = CASE WHEN EXCLUDED.executable <> '' THEN EXCLUDED.executable ELSE software_presence.executable END,
  install_date = CASE WHEN EXCLUDED.install_date <> '' THEN EXCLUDED.install_date ELSE software_presence.install_date END,
  last_used_reported = greatest(EXCLUDED.last_used_reported, software_presence.last_used_reported),
  last_seen = EXCLUDED.last_seen, removed_at = NULL`,
			agentID, at, keys, names, vendors, versions, exes, dates, used)
		if err != nil {
			return fmt.Errorf("upsert software presence: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE software_presence SET removed_at = $2 WHERE agent_id = $1 AND removed_at IS NULL AND last_seen < $2`, agentID, at); err != nil {
		return fmt.Errorf("mark removed software: %w", err)
	}
	return tx.Commit(ctx)
}

// ListPresence returns every product currently present on every endpoint.
func (s *Store) ListPresence(ctx context.Context, staleAfter time.Duration) ([]PresenceRow, error) {
	rows, err := s.pool.Query(ctx, `
SELECT p.agent_id, a.hostname, a.os, coalesce(a.last_heartbeat > now() - $1::interval, false),
       p.product_key, p.name, p.vendor, p.version, p.executable, p.install_date, p.last_used_reported, p.first_seen, p.last_seen
FROM software_presence p JOIN agents a ON a.agent_id = p.agent_id
WHERE p.removed_at IS NULL
ORDER BY p.product_key, a.hostname`, staleAfter)
	if err != nil {
		return nil, fmt.Errorf("list software presence: %w", err)
	}
	defer rows.Close()
	var out []PresenceRow
	for rows.Next() {
		var r PresenceRow
		var used *time.Time
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.OS, &r.Online, &r.ProductKey, &r.Name, &r.Vendor, &r.Version, &r.Executable, &r.InstallDate, &used, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, fmt.Errorf("scan software presence: %w", err)
		}
		if used != nil {
			r.LastUsedReported = *used
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RollupUsageDays recomputes the per-day launch counts for every day from
// since onward from process_events. Days are UTC. Recomputing (rather than
// adding increments) is what makes it safe to run against the 5-minute
// buckets process_events merges new starts into: a bucket that grew since
// the last run is simply counted again at its new size.
func (s *Store) RollupUsageDays(ctx context.Context, since time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
INSERT INTO software_usage_days (agent_id, exe, day, launches)
SELECT agent_id,
       regexp_replace(lower(name), '\.exe$', '') AS exe,
       (at AT TIME ZONE 'UTC')::date AS day,
       sum(count)
FROM process_events
WHERE kind = 'start' AND at >= $1 AND name <> ''
GROUP BY 1, 2, 3
ON CONFLICT (agent_id, exe, day) DO UPDATE SET launches = EXCLUDED.launches`, since)
	if err != nil {
		return 0, fmt.Errorf("rollup usage days: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PruneUsageDays drops days older than keep.
func (s *Store) PruneUsageDays(ctx context.Context, keep time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM software_usage_days WHERE day < ($1::timestamptz AT TIME ZONE 'UTC')::date`, time.Now().Add(-keep))
	if err != nil {
		return 0, fmt.Errorf("prune usage days: %w", err)
	}
	return tag.RowsAffected(), nil
}

// UsageRow is one endpoint's use of one executable inside a window.
type UsageRow struct {
	AgentID  string
	Exe      string
	DaysUsed int
	Launches int64
	LastDay  time.Time
}

// ListUsage aggregates the rollup over the last windowDays days.
func (s *Store) ListUsage(ctx context.Context, windowDays int) ([]UsageRow, error) {
	rows, err := s.pool.Query(ctx, `
SELECT agent_id, exe, count(*)::int, sum(launches)::bigint, max(day)::timestamptz
FROM software_usage_days
WHERE day >= (now() AT TIME ZONE 'UTC')::date - $1::int
GROUP BY agent_id, exe`, windowDays)
	if err != nil {
		return nil, fmt.Errorf("list usage: %w", err)
	}
	defer rows.Close()
	var out []UsageRow
	for rows.Next() {
		var r UsageRow
		if err := rows.Scan(&r.AgentID, &r.Exe, &r.DaysUsed, &r.Launches, &r.LastDay); err != nil {
			return nil, fmt.Errorf("scan usage: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UsageHistoryDays is how many days of rollup exist at all — the most any
// window can really cover. 0 before the first rollup.
func (s *Store) UsageHistoryDays(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT coalesce(((now() AT TIME ZONE 'UTC')::date - min(day)) + 1, 0) FROM software_usage_days`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("usage history days: %w", err)
	}
	return n, nil
}

// UsageDayCount is how many endpoints launched any of a set of executables
// on one day.
type UsageDayCount struct {
	Day      string `json:"day"`
	Devices  int    `json:"devices"`
	Launches int64  `json:"launches"`
}

// UsageHistory is the per-day device count for a product's executables,
// optionally on one endpoint.
func (s *Store) UsageHistory(ctx context.Context, exes []string, agentID string, windowDays int) ([]UsageDayCount, error) {
	rows, err := s.pool.Query(ctx, `
SELECT to_char(day, 'YYYY-MM-DD'), count(DISTINCT agent_id)::int, sum(launches)::bigint
FROM software_usage_days
WHERE exe = ANY($1) AND day >= (now() AT TIME ZONE 'UTC')::date - $2::int AND ($3 = '' OR agent_id = $3)
GROUP BY day ORDER BY day`, exes, windowDays, agentID)
	if err != nil {
		return nil, fmt.Errorf("usage history: %w", err)
	}
	defer rows.Close()
	out := []UsageDayCount{}
	for rows.Next() {
		var r UsageDayCount
		if err := rows.Scan(&r.Day, &r.Devices, &r.Launches); err != nil {
			return nil, fmt.Errorf("scan usage history: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TrackedProduct is a product an operator has chosen to watch and price.
type TrackedProduct struct {
	ID               string    `json:"id"`
	ProductKey       string    `json:"product_key"`
	Name             string    `json:"name"`
	Vendor           string    `json:"vendor"`
	Executables      []string  `json:"executables"`
	CostPerSeatCents int64     `json:"cost_per_seat_cents"`
	Currency         string    `json:"currency"`
	PackageID        string    `json:"package_id"`
	Notes            string    `json:"notes"`
	CreatedBy        string    `json:"created_by" api:"readonly"`
	CreatedAt        time.Time `json:"created_at" api:"readonly"`
	UpdatedAt        time.Time `json:"updated_at" api:"readonly"`
}

const trackedProductColumns = `id, product_key, name, vendor, executables, cost_per_seat_cents, currency, package_id, notes, created_by, created_at, updated_at`

func scanTrackedProduct(row interface{ Scan(...any) error }) (TrackedProduct, error) {
	var t TrackedProduct
	err := row.Scan(&t.ID, &t.ProductKey, &t.Name, &t.Vendor, &t.Executables, &t.CostPerSeatCents, &t.Currency, &t.PackageID, &t.Notes, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if t.Executables == nil {
		t.Executables = []string{}
	}
	return t, err
}

func (s *Store) ListTrackedProducts(ctx context.Context) ([]TrackedProduct, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+trackedProductColumns+` FROM tracked_products ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list tracked products: %w", err)
	}
	defer rows.Close()
	out := []TrackedProduct{}
	for rows.Next() {
		t, err := scanTrackedProduct(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tracked product: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTrackedProduct(ctx context.Context, id string) (*TrackedProduct, error) {
	t, err := scanTrackedProduct(s.pool.QueryRow(ctx, `SELECT `+trackedProductColumns+` FROM tracked_products WHERE id = $1 OR product_key = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get tracked product: %w", err)
	}
	return &t, nil
}

func (s *Store) UpsertTrackedProduct(ctx context.Context, t TrackedProduct) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO tracked_products (`+trackedProductColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now(),now())
		ON CONFLICT (id) DO UPDATE SET product_key=EXCLUDED.product_key, name=EXCLUDED.name, vendor=EXCLUDED.vendor, executables=EXCLUDED.executables,
		cost_per_seat_cents=EXCLUDED.cost_per_seat_cents, currency=EXCLUDED.currency, package_id=EXCLUDED.package_id, notes=EXCLUDED.notes, updated_at=now()`,
		t.ID, t.ProductKey, t.Name, t.Vendor, t.Executables, t.CostPerSeatCents, t.Currency, t.PackageID, t.Notes, t.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert tracked product: %w", err)
	}
	return nil
}

func (s *Store) DeleteTrackedProduct(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM tracked_products WHERE id = $1`, id)
	return err
}
