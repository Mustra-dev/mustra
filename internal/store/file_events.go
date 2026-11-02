package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Real-time file events, server side.
//
// Deliberately a flat append-only table with a short retention rather than
// anything cleverer. These rows are read two ways — "what happened on this
// endpoint just now" and "what has touched anything lately" — and both are
// a plain index scan on time.

// FileEventRetention is how long events are kept. A fortnight: long enough
// to answer "what changed the week the box started misbehaving", short
// enough that the table never becomes something somebody has to truncate
// in a hurry.
const FileEventRetention = 14 * 24 * time.Hour

type FileEvent struct {
	ID         int64     `json:"id"`
	AgentID    string    `json:"agent_id"`
	Hostname   string    `json:"hostname"`
	Path       string    `json:"path"`
	Op         string    `json:"op"`
	At         time.Time `json:"at"`
	Count      int       `json:"count"`
	MatchedIOC string    `json:"matched_ioc,omitempty"`
	IOCName    string    `json:"ioc_name,omitempty"` // the indicator's name, or the signal's when a signal matched
	Labels     []string  `json:"labels,omitempty"`
}

// InsertFileEvents writes one batch. Events arrive already coalesced and
// capped by the agent, so this is a straight insert with no dedupe: two
// identical writes a minute apart are two facts, not one.
func (s *Store) InsertFileEvents(ctx context.Context, events []FileEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range events {
		count := e.Count
		if count <= 0 {
			count = 1
		}
		labels := e.Labels
		if labels == nil {
			labels = []string{}
		}
		batch.Queue(`INSERT INTO file_events (agent_id, path, op, at, count, matched_ioc, labels)
VALUES ($1,$2,$3,$4,$5,$6,$7)`, e.AgentID, e.Path, e.Op, e.At, count, e.MatchedIOC, labels)
	}
	results := s.pool.SendBatch(ctx, batch)
	defer results.Close()
	for range events {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("insert file event: %w", err)
		}
	}
	return nil
}

// ListFileEvents returns the most recent events, newest first, optionally
// for one endpoint or only those that matched an indicator.
func (s *Store) ListFileEvents(ctx context.Context, agentID string, matchedOnly bool, limit int) ([]FileEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
SELECT e.id, e.agent_id, coalesce(a.hostname,''), e.path, e.op, e.at, e.count,
       e.matched_ioc, coalesce(i.name, sg.name, ''), e.labels
FROM file_events e
LEFT JOIN agents a ON a.agent_id = e.agent_id
LEFT JOIN iocs i ON i.id = e.matched_ioc
-- matched_ioc holds a signal's ID when a signal matched and no
-- indicator did; its name is the signal's (#123).
LEFT JOIN signals sg ON sg.id = e.matched_ioc
WHERE ($1 = '' OR e.agent_id = $1) AND (NOT $2 OR e.matched_ioc <> '')
ORDER BY e.at DESC, e.id DESC LIMIT $3`, agentID, matchedOnly, limit)
	if err != nil {
		return nil, fmt.Errorf("list file events: %w", err)
	}
	defer rows.Close()
	out := []FileEvent{}
	for rows.Next() {
		var e FileEvent
		if err := rows.Scan(&e.ID, &e.AgentID, &e.Hostname, &e.Path, &e.Op, &e.At,
			&e.Count, &e.MatchedIOC, &e.IOCName, &e.Labels); err != nil {
			return nil, fmt.Errorf("scan file event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// FileEventSummary is the headline the console shows: how much has moved
// lately, and how many endpoints are actually reporting in real time.
type FileEventSummary struct {
	Last24h    int `json:"last_24h"`
	Suppressed int `json:"suppressed_24h"`
	Matched    int `json:"matched_24h"`
	Endpoints  int `json:"endpoints_reporting"`
}

func (s *Store) FileEventSummary(ctx context.Context) (FileEventSummary, error) {
	var out FileEventSummary
	err := s.pool.QueryRow(ctx, `
SELECT
  coalesce(sum(CASE WHEN op <> 'suppressed' THEN 1 ELSE 0 END), 0),
  coalesce(sum(CASE WHEN op = 'suppressed' THEN count ELSE 0 END), 0),
  coalesce(sum(CASE WHEN matched_ioc <> '' THEN 1 ELSE 0 END), 0),
  count(DISTINCT agent_id)
FROM file_events WHERE at > now() - interval '24 hours'`).
		Scan(&out.Last24h, &out.Suppressed, &out.Matched, &out.Endpoints)
	if err != nil {
		return out, fmt.Errorf("summarise file events: %w", err)
	}
	return out, nil
}

func (s *Store) PruneFileEvents(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM file_events WHERE at < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("prune file events: %w", err)
	}
	return tag.RowsAffected(), nil
}
