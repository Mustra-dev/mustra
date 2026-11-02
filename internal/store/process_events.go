package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Retention is split, because the two kinds of row are worth different
// amounts. A start that matched an indicator is evidence and is kept for a
// month. Everything else is a timeline: measured on this fleet, a busy
// hypervisor produces around 169 distinct commands a minute even after
// identical invocations are collapsed, which is a quarter of a million rows
// a day from one machine. Two days of that is genuinely useful — "what ran
// the night it started misbehaving" is asked immediately or never — and a
// week of it is a table nobody can query.
const (
	ProcessEventRetention        = 48 * time.Hour
	ProcessEventMatchedRetention = 30 * 24 * time.Hour
)

type ProcessEvent struct {
	ID         int64     `json:"id"`
	AgentID    string    `json:"agent_id"`
	Hostname   string    `json:"hostname"`
	PID        int32     `json:"pid"`
	PPID       int32     `json:"ppid,omitempty"`
	Name       string    `json:"name"`
	Cmdline    string    `json:"cmdline,omitempty"`
	Username   string    `json:"username,omitempty"`
	At         time.Time `json:"at"`
	Source     string    `json:"source"`
	Kind       string    `json:"kind"`
	Count      int       `json:"count"`
	MatchedIOC string    `json:"matched_ioc,omitempty"`
	IOCName    string    `json:"ioc_name,omitempty"` // the indicator's name, or the signal's when a signal matched
}

// InsertProcessEvents writes a batch, merging the unmatched timeline into
// minute buckets as it goes.
//
// Two paths on purpose. A start that matched an indicator is evidence: it
// keeps its own row, its own timestamp and its own PID, and is never folded
// into anybody's count. Everything else is a timeline, and a command that
// runs once a second does not need sixty rows a minute to say so.
func (s *Store) InsertProcessEvents(ctx context.Context, events []ProcessEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range events {
		count := e.Count
		if count <= 0 {
			count = 1
		}
		kind := e.Kind
		if kind == "" {
			kind = "start"
		}
		if kind == "start" && e.MatchedIOC == "" {
			batch.Queue(`
INSERT INTO process_events (agent_id, pid, ppid, name, cmdline, username, at, source, kind, count, matched_ioc,
                            bucket, dedupe_key)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'start',$9,'',
        -- Floored to five minutes, not one.
        --
        -- Measured on this fleet: minute buckets merged 5.3 starts into
        -- each row and projected to 1.6 GB at the 48-hour window — ninety
        -- per cent of the database, for a timeline whose bulk is one
        -- service-management command repeating. A command that runs every
        -- few seconds still earned a row a minute. Five minutes collapses
        -- that further at no cost to what the rows are for: this is the
        -- unmatched timeline, where "what ran the night it went wrong" is
        -- answered fine to five minutes. Anything that matched an
        -- indicator takes the other insert path and keeps its own row and
        -- its exact timestamp, because that is evidence, not timeline.
        to_timestamp(floor(extract(epoch from $7::timestamptz) / 300) * 300),
        -- Separated: md5(name || cmdline || user) makes ("ab", "") and
        -- ("a", "b") the same key, and an empty cmdline is common on the
        -- netlink path when the process exits before /proc can be read.
        -- Unit separator rather than NUL, which Postgres text cannot hold,
        -- and which no command line contains.
        md5($4 || E'\x1f' || $5 || E'\x1f' || $6))
ON CONFLICT (agent_id, bucket, dedupe_key) WHERE kind = 'start' AND matched_ioc = ''
DO UPDATE SET count = process_events.count + EXCLUDED.count,
              at = GREATEST(process_events.at, EXCLUDED.at)`,
				e.AgentID, e.PID, e.PPID, e.Name, e.Cmdline, e.Username, e.At, e.Source, count)
			continue
		}
		batch.Queue(`
INSERT INTO process_events (agent_id, pid, ppid, name, cmdline, username, at, source, kind, count, matched_ioc)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			e.AgentID, e.PID, e.PPID, e.Name, e.Cmdline, e.Username, e.At, e.Source,
			kind, count, e.MatchedIOC)
	}
	results := s.pool.SendBatch(ctx, batch)
	defer results.Close()
	for range events {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("insert process event: %w", err)
		}
	}
	return nil
}

// ListProcessEvents returns the most recent starts, newest first. search
// matches the process name or its command line, because "did anything run
// powershell with -enc" is the question this table exists to answer.
func (s *Store) ListProcessEvents(ctx context.Context, agentID, search string, matchedOnly bool, limit int) ([]ProcessEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
SELECT e.id, e.agent_id, coalesce(a.hostname,''), e.pid, e.ppid, e.name, e.cmdline,
       e.username, e.at, e.source, e.kind, e.count, e.matched_ioc, coalesce(i.name, sg.name, '')
FROM process_events e
LEFT JOIN agents a ON a.agent_id = e.agent_id
LEFT JOIN iocs i ON i.id = e.matched_ioc
-- matched_ioc holds a signal's ID when a signal matched and no
-- indicator did; its name is the signal's (#123).
LEFT JOIN signals sg ON sg.id = e.matched_ioc
WHERE ($1 = '' OR e.agent_id = $1)
  AND (NOT $2 OR e.matched_ioc <> '')
  AND ($3 = '' OR e.name ILIKE '%' || $3 || '%' OR e.cmdline ILIKE '%' || $3 || '%')
ORDER BY e.at DESC, e.id DESC LIMIT $4`, agentID, matchedOnly, search, limit)
	if err != nil {
		return nil, fmt.Errorf("list process events: %w", err)
	}
	defer rows.Close()
	out := []ProcessEvent{}
	for rows.Next() {
		var e ProcessEvent
		if err := rows.Scan(&e.ID, &e.AgentID, &e.Hostname, &e.PID, &e.PPID, &e.Name,
			&e.Cmdline, &e.Username, &e.At, &e.Source, &e.Kind, &e.Count,
			&e.MatchedIOC, &e.IOCName); err != nil {
			return nil, fmt.Errorf("scan process event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ProcessEventSummary is the headline: how much ran, how much was matched,
// and — the one that decides what a quiet feed means — how many endpoints
// are reporting from the kernel rather than from a sampler.
type ProcessEventSummary struct {
	Last24h       int `json:"last_24h"`
	Matched       int `json:"matched_24h"`
	Suppressed    int `json:"suppressed_24h"`
	Unidentified  int `json:"unidentified_24h"`
	Endpoints     int `json:"endpoints_reporting"`
	KernelSourced int `json:"endpoints_kernel_sourced"`
}

func (s *Store) ProcessEventSummary(ctx context.Context) (ProcessEventSummary, error) {
	var out ProcessEventSummary
	err := s.pool.QueryRow(ctx, `
SELECT
  -- count, not 1: identical invocations are collapsed by the agent and
  -- merged again into minute buckets here, so a row is many starts. Summing
  -- rows undercounted by roughly an order of magnitude against a label that
  -- says "starts".
  coalesce(sum(CASE WHEN kind = 'start' THEN count ELSE 0 END), 0),
  coalesce(sum(CASE WHEN matched_ioc <> '' THEN 1 ELSE 0 END), 0),
  coalesce(sum(CASE WHEN kind = 'suppressed' THEN count ELSE 0 END), 0),
  coalesce(sum(CASE WHEN kind = 'unidentified' THEN count ELSE 0 END), 0),
  count(DISTINCT agent_id),
  count(DISTINCT agent_id) FILTER (WHERE source = 'netlink')
FROM process_events WHERE at > now() - interval '24 hours'`).
		Scan(&out.Last24h, &out.Matched, &out.Suppressed, &out.Unidentified,
			&out.Endpoints, &out.KernelSourced)
	if err != nil {
		return out, fmt.Errorf("summarise process events: %w", err)
	}
	return out, nil
}

// PruneProcessEvents drops the timeline past its window while keeping
// anything that matched an indicator for far longer. Deleting evidence on
// the same schedule as noise is how an investigation starting a week later
// finds nothing.
func (s *Store) PruneProcessEvents(ctx context.Context, timeline, matched time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
DELETE FROM process_events
WHERE (matched_ioc = '' AND at < now() - $1::interval)
   OR (matched_ioc <> '' AND at < now() - $2::interval)`,
		fmt.Sprintf("%d seconds", int(timeline.Seconds())),
		fmt.Sprintf("%d seconds", int(matched.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("prune process events: %w", err)
	}
	return tag.RowsAffected(), nil
}
