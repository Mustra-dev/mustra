package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mustra-dev/mustra/internal/proto"
)

// RevealRule is what to look for, where, on which endpoints, how often.
// Roots are per OS because the places data lives are: a rule that says
// "every home directory" means /home on Linux, /Users on a Mac and
// C:\Users on Windows, and the console should not make an operator spell
// out all three.
type RevealRule struct {
	ID                 string                `json:"id"`
	Name               string                `json:"name" api:"required"`
	Description        string                `json:"description"`
	Kind               string                `json:"kind"` // rule | quick
	Enabled            bool                  `json:"enabled"`
	GroupIDs           []string              `json:"group_ids"`
	Roots              map[string][]string   `json:"roots" api:"required"` // os -> paths
	Exclude            []string              `json:"exclude"`
	Extensions         []string              `json:"extensions"`
	MaxSizeBytes       int64                 `json:"max_size_bytes"`
	ModifiedWithinDays int                   `json:"modified_within_days"`
	PatternIDs         []string              `json:"pattern_ids"`
	CustomPatterns     []proto.RevealPattern `json:"custom_patterns"`
	MinMatches         int                   `json:"min_matches"`
	// RequirePairs reports a file only when two of the rule's patterns
	// matched near each other; see proto.RevealPair.
	RequirePairs  []proto.RevealPair `json:"require_pairs"`
	IntervalHours int                `json:"interval_hours"`
	Snippets      bool               `json:"snippets"`
	CreatedBy     string             `json:"created_by" api:"readonly"`
	CreatedAt     time.Time          `json:"created_at" api:"readonly"`
	UpdatedAt     time.Time          `json:"updated_at" api:"readonly"`
}

const revealRuleColumns = `id, name, description, kind, enabled, group_ids, roots, exclude, extensions, max_size_bytes,
	modified_within_days, pattern_ids, custom_patterns, min_matches, require_pairs, interval_hours, snippets, created_by, created_at, updated_at`

func scanRevealRule(row interface{ Scan(...any) error }) (RevealRule, error) {
	var r RevealRule
	var roots, custom, pairs []byte
	if err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Kind, &r.Enabled, &r.GroupIDs, &roots, &r.Exclude, &r.Extensions, &r.MaxSizeBytes,
		&r.ModifiedWithinDays, &r.PatternIDs, &custom, &r.MinMatches, &pairs, &r.IntervalHours, &r.Snippets, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return r, err
	}
	_ = json.Unmarshal(roots, &r.Roots)
	_ = json.Unmarshal(custom, &r.CustomPatterns)
	_ = json.Unmarshal(pairs, &r.RequirePairs)
	if r.RequirePairs == nil {
		r.RequirePairs = []proto.RevealPair{}
	}
	if r.Roots == nil {
		r.Roots = map[string][]string{}
	}
	for _, p := range []*[]string{&r.GroupIDs, &r.Exclude, &r.Extensions, &r.PatternIDs} {
		if *p == nil {
			*p = []string{}
		}
	}
	if r.CustomPatterns == nil {
		r.CustomPatterns = []proto.RevealPattern{}
	}
	return r, nil
}

func (s *Store) ListRevealRules(ctx context.Context) ([]RevealRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+revealRuleColumns+` FROM reveal_rules ORDER BY kind, name`)
	if err != nil {
		return nil, fmt.Errorf("list reveal rules: %w", err)
	}
	defer rows.Close()
	out := []RevealRule{}
	for rows.Next() {
		r, err := scanRevealRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan reveal rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRevealRule(ctx context.Context, id string) (*RevealRule, error) {
	r, err := scanRevealRule(s.pool.QueryRow(ctx, `SELECT `+revealRuleColumns+` FROM reveal_rules WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get reveal rule: %w", err)
	}
	return &r, nil
}

func (s *Store) UpsertRevealRule(ctx context.Context, r RevealRule) error {
	roots, _ := json.Marshal(r.Roots)
	custom, _ := json.Marshal(r.CustomPatterns)
	pairs, _ := json.Marshal(r.RequirePairs)
	if r.Kind == "" {
		r.Kind = "rule"
	}
	// A nil slice reaches Postgres as NULL and these columns are NOT NULL,
	// so a caller that simply omitted a field got a 500 about a constraint
	// rather than the empty list it plainly meant.
	for _, p := range []*[]string{&r.GroupIDs, &r.Exclude, &r.Extensions, &r.PatternIDs} {
		if *p == nil {
			*p = []string{}
		}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO reveal_rules (`+revealRuleColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, kind=EXCLUDED.kind, enabled=EXCLUDED.enabled,
		group_ids=EXCLUDED.group_ids, roots=EXCLUDED.roots, exclude=EXCLUDED.exclude, extensions=EXCLUDED.extensions,
		max_size_bytes=EXCLUDED.max_size_bytes, modified_within_days=EXCLUDED.modified_within_days, pattern_ids=EXCLUDED.pattern_ids,
		custom_patterns=EXCLUDED.custom_patterns, min_matches=EXCLUDED.min_matches, require_pairs=EXCLUDED.require_pairs,
		interval_hours=EXCLUDED.interval_hours, snippets=EXCLUDED.snippets, updated_at=now()`,
		r.ID, r.Name, r.Description, r.Kind, r.Enabled, r.GroupIDs, roots, r.Exclude, r.Extensions, r.MaxSizeBytes,
		r.ModifiedWithinDays, r.PatternIDs, custom, r.MinMatches, pairs, r.IntervalHours, r.Snippets, r.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert reveal rule: %w", err)
	}
	return nil
}

func (s *Store) DeleteRevealRule(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM reveal_rules WHERE id = $1`, id)
	return err
}

// RevealScan is one endpoint's latest run of one rule.
type RevealScan struct {
	RuleID       string     `json:"rule_id"`
	AgentID      string     `json:"agent_id"`
	Hostname     string     `json:"hostname,omitempty"`
	ScanID       string     `json:"scan_id"`
	DispatchedAt time.Time  `json:"dispatched_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	FilesSeen    int        `json:"files_seen"`
	FilesScanned int        `json:"files_scanned"`
	FilesMatched int        `json:"files_matched"`
	Skipped      int        `json:"skipped"`
	Truncated    bool       `json:"truncated"`
	Error        string     `json:"error,omitempty"`
}

// MarkRevealDispatched records that a scan was sent, before any report
// exists, so the console can show "running" and the scheduler does not
// send it twice.
func (s *Store) MarkRevealDispatched(ctx context.Context, ruleID, agentID, scanID string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO reveal_scans (rule_id, agent_id, scan_id, dispatched_at, started_at, finished_at, error)
		VALUES ($1,$2,$3,now(),NULL,NULL,'')
		ON CONFLICT (rule_id, agent_id) DO UPDATE SET scan_id=EXCLUDED.scan_id, dispatched_at=now(), started_at=NULL, finished_at=NULL, error=''`,
		ruleID, agentID, scanID)
	return err
}

func (s *Store) ListRevealScans(ctx context.Context, ruleID string) ([]RevealScan, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.rule_id, r.agent_id, coalesce(a.hostname, ''), r.scan_id, r.dispatched_at, r.started_at, r.finished_at,
		r.files_seen, r.files_scanned, r.files_matched, r.skipped, r.truncated, r.error
		FROM reveal_scans r LEFT JOIN agents a ON a.agent_id = r.agent_id WHERE ($1 = '' OR r.rule_id = $1) ORDER BY r.dispatched_at DESC`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("list reveal scans: %w", err)
	}
	defer rows.Close()
	out := []RevealScan{}
	for rows.Next() {
		var r RevealScan
		if err := rows.Scan(&r.RuleID, &r.AgentID, &r.Hostname, &r.ScanID, &r.DispatchedAt, &r.StartedAt, &r.FinishedAt,
			&r.FilesSeen, &r.FilesScanned, &r.FilesMatched, &r.Skipped, &r.Truncated, &r.Error); err != nil {
			return nil, fmt.Errorf("scan reveal scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordRevealReport stores what an endpoint found: the scan's outcome,
// every match upserted with its first_seen preserved, and anything the
// previous run found that this one did not, removed -- a rescan is the
// whole truth about that endpoint for that rule.
func (s *Store) RecordRevealReport(ctx context.Context, rep proto.RevealReport) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	started, _ := time.Parse(time.RFC3339, rep.Started)
	finished, _ := time.Parse(time.RFC3339, rep.Finished)
	if _, err := tx.Exec(ctx, `INSERT INTO reveal_scans (rule_id, agent_id, scan_id, dispatched_at, started_at, finished_at, files_seen, files_scanned, files_matched, skipped, truncated, error)
		SELECT $1,$2,$3,now(),$4,$5,$6,$7,$8,$9,$10,$11 WHERE EXISTS (SELECT 1 FROM reveal_rules WHERE id = $1)
		ON CONFLICT (rule_id, agent_id) DO UPDATE SET scan_id=EXCLUDED.scan_id, started_at=EXCLUDED.started_at, finished_at=EXCLUDED.finished_at,
		files_seen=EXCLUDED.files_seen, files_scanned=EXCLUDED.files_scanned, files_matched=EXCLUDED.files_matched, skipped=EXCLUDED.skipped,
		truncated=EXCLUDED.truncated, error=EXCLUDED.error`,
		rep.RuleID, rep.AgentID, rep.ScanID, started, finished, rep.FilesSeen, rep.FilesScanned, rep.FilesMatched, rep.Skipped, rep.Truncated, rep.Error); err != nil {
		return fmt.Errorf("record reveal scan: %w", err)
	}
	now := time.Now()
	for _, m := range rep.Matches {
		var modified *time.Time
		if t, err := time.Parse(time.RFC3339, m.Modified); err == nil {
			modified = &t
		}
		if _, err := tx.Exec(ctx, `INSERT INTO reveal_matches (rule_id, agent_id, path, pattern_id, count, confirmed, size, modified, snippet, first_seen, last_seen)
			SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10 WHERE EXISTS (SELECT 1 FROM reveal_rules WHERE id = $1)
			ON CONFLICT (rule_id, agent_id, path, pattern_id) DO UPDATE SET count=EXCLUDED.count, confirmed=EXCLUDED.confirmed, size=EXCLUDED.size,
			modified=EXCLUDED.modified, snippet=EXCLUDED.snippet, last_seen=EXCLUDED.last_seen`,
			rep.RuleID, rep.AgentID, m.Path, m.PatternID, m.Count, m.Confirmed, m.Size, modified, m.Snippet, now); err != nil {
			return fmt.Errorf("record reveal match: %w", err)
		}
	}
	// A truncated scan did not see everything, so what it did not report
	// may still be there; only a complete scan retires old matches.
	if !rep.Truncated && rep.Error == "" {
		if _, err := tx.Exec(ctx, `DELETE FROM reveal_matches WHERE rule_id = $1 AND agent_id = $2 AND last_seen < $3`, rep.RuleID, rep.AgentID, now); err != nil {
			return fmt.Errorf("retire reveal matches: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// RevealMatch is one finding as the console lists it.
type RevealMatch struct {
	RuleID    string     `json:"rule_id"`
	RuleName  string     `json:"rule_name,omitempty"`
	AgentID   string     `json:"agent_id"`
	Hostname  string     `json:"hostname,omitempty"`
	OS        string     `json:"os,omitempty"`
	Path      string     `json:"path"`
	PatternID string     `json:"pattern_id"`
	Count     int        `json:"count"`
	Confirmed int        `json:"confirmed"`
	Size      int64      `json:"size"`
	Modified  *time.Time `json:"modified,omitempty"`
	Snippet   string     `json:"snippet,omitempty"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

// RevealMatchFilter narrows a listing; empty fields match everything.
type RevealMatchFilter struct {
	RuleID, AgentID, PatternID string
	ConfirmedOnly              bool
	Limit                      int
}

func (s *Store) ListRevealMatches(ctx context.Context, f RevealMatchFilter) ([]RevealMatch, error) {
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 2000
	}
	rows, err := s.pool.Query(ctx, `SELECT m.rule_id, coalesce(r.name,''), m.agent_id, coalesce(a.hostname,''), coalesce(a.os,''), m.path, m.pattern_id,
		m.count, m.confirmed, m.size, m.modified, m.snippet, m.first_seen, m.last_seen
		FROM reveal_matches m LEFT JOIN reveal_rules r ON r.id = m.rule_id LEFT JOIN agents a ON a.agent_id = m.agent_id
		WHERE ($1 = '' OR m.rule_id = $1) AND ($2 = '' OR m.agent_id = $2) AND ($3 = '' OR m.pattern_id = $3) AND ($4 = false OR m.confirmed > 0)
		ORDER BY m.confirmed DESC, m.last_seen DESC LIMIT $5`, f.RuleID, f.AgentID, f.PatternID, f.ConfirmedOnly, f.Limit)
	if err != nil {
		return nil, fmt.Errorf("list reveal matches: %w", err)
	}
	defer rows.Close()
	out := []RevealMatch{}
	for rows.Next() {
		var m RevealMatch
		if err := rows.Scan(&m.RuleID, &m.RuleName, &m.AgentID, &m.Hostname, &m.OS, &m.Path, &m.PatternID, &m.Count, &m.Confirmed, &m.Size, &m.Modified, &m.Snippet, &m.FirstSeen, &m.LastSeen); err != nil {
			return nil, fmt.Errorf("scan reveal match: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RevealSummary is the overview page's numbers.
type RevealSummary struct {
	EndpointsWithConfirmed   int            `json:"endpoints_with_confirmed"`
	EndpointsWithUnconfirmed int            `json:"endpoints_with_unconfirmed"`
	EndpointsScanned         int            `json:"endpoints_scanned"` // endpoints with a scan that ran to the end, for any rule
	EndpointsRunning         int            `json:"endpoints_running"`
	FilesMatched             int            `json:"files_matched"`
	ConfirmedFiles           int            `json:"confirmed_files"`
	ByPattern                map[string]int `json:"by_pattern"`  // confirmed files per pattern
	ByEndpoint               map[string]int `json:"by_endpoint"` // confirmed files per hostname
}

func (s *Store) RevealSummary(ctx context.Context) (RevealSummary, error) {
	out := RevealSummary{ByPattern: map[string]int{}, ByEndpoint: map[string]int{}}
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(DISTINCT agent_id) FROM reveal_matches WHERE confirmed > 0),
		(SELECT count(DISTINCT agent_id) FROM reveal_matches m WHERE confirmed = 0 AND NOT EXISTS (SELECT 1 FROM reveal_matches c WHERE c.agent_id = m.agent_id AND c.confirmed > 0)),
		-- A scan with an error never ran: the endpoint refused the command
		-- (an agent older than Reveal) or could not compile the patterns.
		-- reveal_scans keeps a deleted endpoint's rows; the tile divides by
		-- the endpoints enrolled now.
		(SELECT count(DISTINCT agent_id) FROM reveal_scans WHERE finished_at IS NOT NULL AND error = ''
		   AND agent_id IN (SELECT agent_id FROM agents)),
		(SELECT count(DISTINCT agent_id) FROM reveal_scans WHERE finished_at IS NULL AND dispatched_at > now() - interval '1 hour'),
		(SELECT count(DISTINCT (agent_id, path)) FROM reveal_matches),
		(SELECT count(DISTINCT (agent_id, path)) FROM reveal_matches WHERE confirmed > 0)`).
		Scan(&out.EndpointsWithConfirmed, &out.EndpointsWithUnconfirmed, &out.EndpointsScanned, &out.EndpointsRunning, &out.FilesMatched, &out.ConfirmedFiles)
	if err != nil {
		return out, fmt.Errorf("reveal summary: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT pattern_id, count(DISTINCT (agent_id, path)) FROM reveal_matches WHERE confirmed > 0 GROUP BY pattern_id`)
	if err == nil {
		for rows.Next() {
			var k string
			var n int
			if rows.Scan(&k, &n) == nil {
				out.ByPattern[k] = n
			}
		}
		rows.Close()
	}
	rows, err = s.pool.Query(ctx, `SELECT coalesce(a.hostname, m.agent_id), count(DISTINCT m.path) FROM reveal_matches m LEFT JOIN agents a ON a.agent_id = m.agent_id WHERE m.confirmed > 0 GROUP BY 1 ORDER BY 2 DESC LIMIT 12`)
	if err == nil {
		for rows.Next() {
			var k string
			var n int
			if rows.Scan(&k, &n) == nil {
				out.ByEndpoint[k] = n
			}
		}
		rows.Close()
	}
	return out, nil
}

// PurgeQuickSearches drops ad-hoc searches older than a day, with their
// results: they were a question, not a policy.
func (s *Store) PurgeQuickSearches(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM reveal_rules WHERE kind = 'quick' AND created_at < now() - $1::interval`, fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevealRuleSet is a compliance regime as an operator works in it: a few
// rules aimed at a few groups, turned on or off as one thing. Rules remain
// the unit of scanning; the set is the unit of deciding.
type RevealRuleSet struct {
	ID          string    `json:"id"`
	Name        string    `json:"name" api:"required"`
	Regime      string    `json:"regime"`
	Description string    `json:"description"`
	RuleIDs     []string  `json:"rule_ids" api:"required"`
	GroupIDs    []string  `json:"group_ids"`
	Enabled     bool      `json:"enabled"`
	CreatedBy   string    `json:"created_by" api:"readonly"`
	CreatedAt   time.Time `json:"created_at" api:"readonly"`
	UpdatedAt   time.Time `json:"updated_at" api:"readonly"`
}

const revealRuleSetColumns = `id, name, regime, description, rule_ids, group_ids, enabled, created_by, created_at, updated_at`

func (s *Store) ListRevealRuleSets(ctx context.Context) ([]RevealRuleSet, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+revealRuleSetColumns+` FROM reveal_rule_sets ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list reveal rule sets: %w", err)
	}
	defer rows.Close()
	out := []RevealRuleSet{}
	for rows.Next() {
		var r RevealRuleSet
		if err := rows.Scan(&r.ID, &r.Name, &r.Regime, &r.Description, &r.RuleIDs, &r.GroupIDs, &r.Enabled, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan reveal rule set: %w", err)
		}
		if r.RuleIDs == nil {
			r.RuleIDs = []string{}
		}
		if r.GroupIDs == nil {
			r.GroupIDs = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRevealRuleSet(ctx context.Context, id string) (*RevealRuleSet, error) {
	list, err := s.ListRevealRuleSets(ctx)
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

func (s *Store) UpsertRevealRuleSet(ctx context.Context, r RevealRuleSet) error {
	if r.RuleIDs == nil {
		r.RuleIDs = []string{}
	}
	if r.GroupIDs == nil {
		r.GroupIDs = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO reveal_rule_sets (`+revealRuleSetColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, regime=EXCLUDED.regime, description=EXCLUDED.description,
		rule_ids=EXCLUDED.rule_ids, group_ids=EXCLUDED.group_ids, enabled=EXCLUDED.enabled, updated_at=now()`,
		r.ID, r.Name, r.Regime, r.Description, r.RuleIDs, r.GroupIDs, r.Enabled, r.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert reveal rule set: %w", err)
	}
	return nil
}

func (s *Store) DeleteRevealRuleSet(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM reveal_rule_sets WHERE id = $1`, id)
	return err
}
