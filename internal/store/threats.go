package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// KEVEntry is one CISA Known Exploited Vulnerabilities catalog entry as
// stored, for threat briefings.
type KEVEntry struct {
	CVE            string
	Vendor         string
	Product        string
	Name           string
	Description    string
	RequiredAction string
	DateAdded      *time.Time
	DueDate        *time.Time
	Ransomware     bool
	Notes          string
	EPSS           *float64
	Percentile     *float64
}

// ListKEVEntries returns every catalog entry with its EPSS score, newest
// first.
func (s *Store) ListKEVEntries(ctx context.Context) ([]KEVEntry, error) {
	rows, err := s.pool.Query(ctx, `
SELECT k.cve, k.vendor, k.product, k.name, k.description, k.required_action, k.date_added, k.due_date,
       k.ransomware, k.notes, e.epss, e.percentile
FROM kev_entries k LEFT JOIN epss_scores e ON e.cve = k.cve
ORDER BY k.date_added DESC NULLS LAST, k.cve`)
	if err != nil {
		return nil, fmt.Errorf("list kev entries: %w", err)
	}
	defer rows.Close()
	out := []KEVEntry{}
	for rows.Next() {
		var k KEVEntry
		var epss, pct *float32
		if err := rows.Scan(&k.CVE, &k.Vendor, &k.Product, &k.Name, &k.Description, &k.RequiredAction, &k.DateAdded, &k.DueDate,
			&k.Ransomware, &k.Notes, &epss, &pct); err != nil {
			return nil, fmt.Errorf("scan kev entry: %w", err)
		}
		if epss != nil {
			v := widenFloat32(*epss)
			k.EPSS = &v
		}
		if pct != nil {
			v := widenFloat32(*pct)
			k.Percentile = &v
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CVEFinding is one endpoint's vulnerable package for a CVE, from the
// vulnerability scan (an exact version match against the advisory).
type CVEFinding struct {
	CVE            string
	AgentID        string
	PackageName    string
	PackageVersion string
	FixedVersion   string
	Severity       string
	CVSS           *float64
}

// ListCVEFindings returns the fleet's unsuppressed findings for the given
// CVEs.
func (s *Store) ListCVEFindings(ctx context.Context, cves []string) ([]CVEFinding, error) {
	if len(cves) == 0 {
		return []CVEFinding{}, nil
	}
	upper := make([]string, 0, len(cves))
	for _, c := range cves {
		upper = append(upper, strings.ToUpper(strings.TrimSpace(c)))
	}
	rows, err := s.pool.Query(ctx, `
SELECT c.cve, v.agent_id, v.package_name, v.package_version,
       coalesce(d.fixed_versions ->> v.package_name, ''), v.severity, d.cvss_score
FROM agent_vulnerabilities v
JOIN vuln_details_cache d ON d.vuln_id = v.vuln_id
CROSS JOIN LATERAL unnest(d.cve_ids) AS c(cve)
WHERE NOT v.suppressed AND upper(c.cve) = ANY($1)`, upper)
	if err != nil {
		return nil, fmt.Errorf("list cve findings: %w", err)
	}
	defer rows.Close()
	out := []CVEFinding{}
	for rows.Next() {
		var f CVEFinding
		var cvss *float32
		if err := rows.Scan(&f.CVE, &f.AgentID, &f.PackageName, &f.PackageVersion, &f.FixedVersion, &f.Severity, &cvss); err != nil {
			return nil, fmt.Errorf("scan cve finding: %w", err)
		}
		f.CVE = strings.ToUpper(f.CVE)
		if cvss != nil {
			v := widenFloat32(*cvss)
			f.CVSS = &v
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SoftwareRow is one installed application or package on one endpoint.
type SoftwareRow struct {
	AgentID string
	Name    string
	Version string
}

// ListSoftwareRows returns every endpoint's installed software, as the
// software inventory last saw it.
func (s *Store) ListSoftwareRows(ctx context.Context) ([]SoftwareRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, name, version FROM software_presence`)
	if err != nil {
		return nil, fmt.Errorf("list software rows: %w", err)
	}
	defer rows.Close()
	out := []SoftwareRow{}
	for rows.Next() {
		var r SoftwareRow
		if err := rows.Scan(&r.AgentID, &r.Name, &r.Version); err != nil {
			return nil, fmt.Errorf("scan software row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ThreatRef is a labelled link in a briefing.
type ThreatRef struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// ThreatRule says how to find a product on an endpoint: installed
// software whose name matches one of Apps (regular expressions, matched
// case-insensitively against the whole name) on one of OS (any, when
// empty); with no Apps, every endpoint on one of OS. Processes and
// Services name what to look for in hunting questions.
type ThreatRule struct {
	Label     string   `json:"label,omitempty"`
	Apps      []string `json:"apps,omitempty"`
	OS        []string `json:"os,omitempty"`
	Processes []string `json:"processes,omitempty"`
	Services  []string `json:"services,omitempty"`
	// Appliance marks a product that runs on a network appliance or a
	// vendor-hosted service, which no endpoint agent can see.
	Appliance bool   `json:"appliance,omitempty"`
	Note      string `json:"note,omitempty"`
}

// ThreatBrief is a briefing written by hand.
type ThreatBrief struct {
	ID         string      `json:"id" api:"readonly"`
	Title      string      `json:"title" api:"required"`
	CVEs       []string    `json:"cves"`
	Summary    string      `json:"summary"`
	Mitigation string      `json:"mitigation"`
	Refs       []ThreatRef `json:"refs"`
	Rule       ThreatRule  `json:"rule"`
	Questions  []string    `json:"questions"`
	Archived   bool        `json:"archived"`
	CreatedBy  string      `json:"created_by" api:"readonly"`
	CreatedAt  time.Time   `json:"created_at" api:"readonly"`
	UpdatedAt  time.Time   `json:"updated_at" api:"readonly"`
}

const threatBriefColumns = `id, title, cves, summary, mitigation, refs, rule, questions, archived, created_by, created_at, updated_at`

func scanThreatBrief(row pgx.Row) (*ThreatBrief, error) {
	var b ThreatBrief
	var refs, rule, qs []byte
	if err := row.Scan(&b.ID, &b.Title, &b.CVEs, &b.Summary, &b.Mitigation, &refs, &rule, &qs, &b.Archived, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(refs, &b.Refs)
	_ = json.Unmarshal(rule, &b.Rule)
	_ = json.Unmarshal(qs, &b.Questions)
	if b.Refs == nil {
		b.Refs = []ThreatRef{}
	}
	if b.Questions == nil {
		b.Questions = []string{}
	}
	if b.CVEs == nil {
		b.CVEs = []string{}
	}
	return &b, nil
}

func (s *Store) ListThreatBriefs(ctx context.Context) ([]ThreatBrief, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+threatBriefColumns+` FROM threat_briefs ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("list threat briefs: %w", err)
	}
	defer rows.Close()
	out := []ThreatBrief{}
	for rows.Next() {
		b, err := scanThreatBrief(rows)
		if err != nil {
			return nil, fmt.Errorf("scan threat brief: %w", err)
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// GetThreatBrief returns one briefing, or nil when there is none.
func (s *Store) GetThreatBrief(ctx context.Context, id string) (*ThreatBrief, error) {
	b, err := scanThreatBrief(s.pool.QueryRow(ctx, `SELECT `+threatBriefColumns+` FROM threat_briefs WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get threat brief: %w", err)
	}
	return b, nil
}

// SaveThreatBrief inserts or replaces a briefing and returns it as stored.
func (s *Store) SaveThreatBrief(ctx context.Context, b ThreatBrief) (*ThreatBrief, error) {
	refs, _ := json.Marshal(b.Refs)
	rule, _ := json.Marshal(b.Rule)
	qs, _ := json.Marshal(b.Questions)
	if b.CVEs == nil {
		b.CVEs = []string{}
	}
	out, err := scanThreatBrief(s.pool.QueryRow(ctx, `
INSERT INTO threat_briefs (id, title, cves, summary, mitigation, refs, rule, questions, archived, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, cves = EXCLUDED.cves, summary = EXCLUDED.summary,
  mitigation = EXCLUDED.mitigation, refs = EXCLUDED.refs, rule = EXCLUDED.rule, questions = EXCLUDED.questions,
  archived = EXCLUDED.archived, updated_at = now()
RETURNING `+threatBriefColumns,
		b.ID, b.Title, b.CVEs, b.Summary, b.Mitigation, refs, rule, qs, b.Archived, b.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("save threat brief: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteThreatBrief(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM threat_briefs WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete threat brief: %w", err)
	}
	_, _ = s.pool.Exec(ctx, `DELETE FROM threat_counts WHERE brief_key = $1`, id)
	_, _ = s.pool.Exec(ctx, `DELETE FROM threat_alerts WHERE brief_key = $1`, id)
	return nil
}

// ThreatCount is one day of a briefing's trend.
type ThreatCount struct {
	Day        time.Time `json:"day"`
	Vulnerable int       `json:"vulnerable"`
	Present    int       `json:"present"`
}

// RecordThreatCount keeps today's count for a briefing (the last write of
// the day wins).
func (s *Store) RecordThreatCount(ctx context.Context, key string, vulnerable, present int) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO threat_counts (brief_key, day, vulnerable, present) VALUES ($1, current_date, $2, $3)
ON CONFLICT (brief_key, day) DO UPDATE SET vulnerable = EXCLUDED.vulnerable, present = EXCLUDED.present`, key, vulnerable, present)
	if err != nil {
		return fmt.Errorf("record threat count: %w", err)
	}
	return nil
}

// ThreatCounts returns a briefing's daily counts since a day, oldest first.
func (s *Store) ThreatCounts(ctx context.Context, key string, since time.Time) ([]ThreatCount, error) {
	rows, err := s.pool.Query(ctx, `SELECT day, vulnerable, present FROM threat_counts WHERE brief_key = $1 AND day >= $2 ORDER BY day`, key, since)
	if err != nil {
		return nil, fmt.Errorf("threat counts: %w", err)
	}
	defer rows.Close()
	out := []ThreatCount{}
	for rows.Next() {
		var c ThreatCount
		if err := rows.Scan(&c.Day, &c.Vulnerable, &c.Present); err != nil {
			return nil, fmt.Errorf("scan threat count: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PruneThreatCounts drops trend rows older than a day.
func (s *Store) PruneThreatCounts(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM threat_counts WHERE day < $1`, before)
	return err
}

// ThreatAlerted reports whether a briefing has notified.
func (s *Store) ThreatAlerted(ctx context.Context) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT brief_key FROM threat_alerts`)
	if err != nil {
		return nil, fmt.Errorf("threat alerts: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// MarkThreatAlerted records that a briefing notified; clear forgets it,
// so the next exposure notifies again.
func (s *Store) MarkThreatAlerted(ctx context.Context, key string, endpoints int, clear bool) error {
	var err error
	if clear {
		_, err = s.pool.Exec(ctx, `DELETE FROM threat_alerts WHERE brief_key = $1`, key)
	} else {
		_, err = s.pool.Exec(ctx, `INSERT INTO threat_alerts (brief_key, endpoints) VALUES ($1, $2)
ON CONFLICT (brief_key) DO UPDATE SET endpoints = EXCLUDED.endpoints`, key, endpoints)
	}
	return err
}

// VulnScannedSince returns the endpoints whose vulnerability scan ran
// since a time: for those, a package the scan knows and did not flag has
// been checked.
func (s *Store) VulnScannedSince(ctx context.Context, since time.Time) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id FROM vuln_scan_status WHERE scanned_at >= $1`, since)
	if err != nil {
		return nil, fmt.Errorf("vuln scanned since: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ThreatExposure is one endpoint a briefing found vulnerable, with what
// automatic remediation has done about it.
type ThreatExposure struct {
	BriefKey        string
	AgentID         string
	FirstSeen       time.Time
	Attempts        int
	LastAttempt     *time.Time
	LastRunID       string
	GaveUp          bool
	OverdueNotified bool
}

// SyncThreatExposures makes the exposure rows match what the briefings
// find now: current is briefing key → vulnerable agent IDs. New pairs are
// added (first seen now), pairs no longer vulnerable are removed, and the
// rows are returned keyed by briefing then agent.
func (s *Store) SyncThreatExposures(ctx context.Context, current map[string][]string) (map[string]map[string]ThreatExposure, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var keys, agents []string
	for k, ids := range current {
		for _, id := range ids {
			keys = append(keys, k)
			agents = append(agents, id)
		}
	}
	if _, err := tx.Exec(ctx, `
DELETE FROM threat_exposures e
WHERE NOT EXISTS (SELECT 1 FROM unnest($1::text[], $2::text[]) AS c(k, a) WHERE c.k = e.brief_key AND c.a = e.agent_id)`, keys, agents); err != nil {
		return nil, fmt.Errorf("prune threat exposures: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO threat_exposures (brief_key, agent_id)
SELECT k, a FROM unnest($1::text[], $2::text[]) AS c(k, a)
ON CONFLICT (brief_key, agent_id) DO NOTHING`, keys, agents); err != nil {
		return nil, fmt.Errorf("add threat exposures: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT brief_key, agent_id, first_seen, attempts, last_attempt, last_run_id, gave_up, overdue_notified FROM threat_exposures`)
	if err != nil {
		return nil, fmt.Errorf("list threat exposures: %w", err)
	}
	out := map[string]map[string]ThreatExposure{}
	for rows.Next() {
		var e ThreatExposure
		if err := rows.Scan(&e.BriefKey, &e.AgentID, &e.FirstSeen, &e.Attempts, &e.LastAttempt, &e.LastRunID, &e.GaveUp, &e.OverdueNotified); err != nil {
			rows.Close()
			return nil, err
		}
		if out[e.BriefKey] == nil {
			out[e.BriefKey] = map[string]ThreatExposure{}
		}
		out[e.BriefKey][e.AgentID] = e
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// RecordThreatPatchAttempt counts an automatic patch attempt for these
// briefing/endpoint pairs, and marks those that reached maxAttempts as
// given up.
func (s *Store) RecordThreatPatchAttempt(ctx context.Context, keys, agents []string, runID string, maxAttempts int) error {
	_, err := s.pool.Exec(ctx, `
UPDATE threat_exposures e SET attempts = e.attempts + 1, last_attempt = now(), last_run_id = $3,
       gave_up = e.attempts + 1 >= $4
FROM unnest($1::text[], $2::text[]) AS c(k, a)
WHERE e.brief_key = c.k AND e.agent_id = c.a`, keys, agents, runID, maxAttempts)
	return err
}

// MarkThreatOverdueNotified records that these pairs' due date was alerted.
func (s *Store) MarkThreatOverdueNotified(ctx context.Context, keys, agents []string) error {
	_, err := s.pool.Exec(ctx, `
UPDATE threat_exposures e SET overdue_notified = true
FROM unnest($1::text[], $2::text[]) AS c(k, a)
WHERE e.brief_key = c.k AND e.agent_id = c.a`, keys, agents)
	return err
}
