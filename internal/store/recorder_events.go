package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Retention mirrors process events: the timeline is short because it is
// large, a match is evidence and is kept for a month.
const (
	RecorderEventRetention        = 48 * time.Hour
	RecorderEventMatchedRetention = 30 * 24 * time.Hour
)

type RecorderEvent struct {
	ID            int64             `json:"id"`
	AgentID       string            `json:"agent_id"`
	Hostname      string            `json:"hostname"`
	Kind          string            `json:"kind"`
	At            time.Time         `json:"at"`
	Count         int               `json:"count"`
	PID           int32             `json:"pid,omitempty"`
	Process       string            `json:"process,omitempty"`
	Username      string            `json:"username,omitempty"`
	Op            string            `json:"op,omitempty"`
	Summary       string            `json:"summary"`
	Fields        map[string]string `json:"fields"`
	Source        string            `json:"source"`
	MatchedSignal string            `json:"matched_signal,omitempty"`
	SignalName    string            `json:"signal_name,omitempty"`
}

func (s *Store) InsertRecorderEvents(ctx context.Context, events []RecorderEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range events {
		count := e.Count
		if count <= 0 {
			count = 1
		}
		fields, _ := json.Marshal(e.Fields)
		if e.Fields == nil {
			fields = []byte("{}")
		}
		batch.Queue(`INSERT INTO recorder_events (agent_id, kind, at, count, pid, process, username, op, summary, fields, source, matched_signal)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			e.AgentID, e.Kind, e.At, count, e.PID, e.Process, e.Username, e.Op, e.Summary, fields, e.Source, e.MatchedSignal)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range events {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert recorder event: %w", err)
		}
	}
	return nil
}

// ListRecorderEvents returns the newest events of one kind (or all), with
// a free-text search over the summary, process and user.
func (s *Store) ListRecorderEvents(ctx context.Context, kind, agentID, search string, matchedOnly bool, limit int) ([]RecorderEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
SELECT e.id, e.agent_id, coalesce(a.hostname,''), e.kind, e.at, e.count, e.pid, e.process, e.username, e.op,
       e.summary, e.fields, e.source, e.matched_signal, coalesce(sg.name,'')
FROM recorder_events e
LEFT JOIN agents a ON a.agent_id = e.agent_id
LEFT JOIN signals sg ON sg.id = e.matched_signal
WHERE ($1 = '' OR e.kind = $1 OR ($1 <> 'suppressed' AND e.kind = 'suppressed' AND e.op = $1))
  AND ($2 = '' OR e.agent_id = $2)
  AND (NOT $3 OR e.matched_signal <> '')
  AND ($4 = '' OR e.summary ILIKE '%' || $4 || '%' OR e.process ILIKE '%' || $4 || '%' OR e.username ILIKE '%' || $4 || '%')
ORDER BY e.at DESC, e.id DESC LIMIT $5`, kind, agentID, matchedOnly, search, limit)
	if err != nil {
		return nil, fmt.Errorf("list recorder events: %w", err)
	}
	defer rows.Close()
	out := []RecorderEvent{}
	for rows.Next() {
		var e RecorderEvent
		var fields []byte
		if err := rows.Scan(&e.ID, &e.AgentID, &e.Hostname, &e.Kind, &e.At, &e.Count, &e.PID, &e.Process, &e.Username, &e.Op,
			&e.Summary, &fields, &e.Source, &e.MatchedSignal, &e.SignalName); err != nil {
			return nil, fmt.Errorf("scan recorder event: %w", err)
		}
		_ = json.Unmarshal(fields, &e.Fields)
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecorderKindSummary is the last-24h picture for one event kind.
type RecorderKindSummary struct {
	Events     int            `json:"events"`
	Matched    int            `json:"matched"`
	Suppressed int            `json:"suppressed"`
	Endpoints  int            `json:"endpoints"`
	Sources    map[string]int `json:"sources"`
}

// RecorderEventSummary is the last 24 hours per kind. Endpoints counts
// each endpoint once per kind, however many sources it reported through
// (its network events and a suppressed row, say); Sources counts the
// endpoints per named source.
func (s *Store) RecorderEventSummary(ctx context.Context) (map[string]RecorderKindSummary, error) {
	rows, err := s.pool.Query(ctx, `
SELECT CASE WHEN kind = 'suppressed' THEN op ELSE kind END AS k, coalesce(source, ''), GROUPING(source),
       coalesce(sum(CASE WHEN kind <> 'suppressed' THEN count ELSE 0 END), 0),
       coalesce(sum(CASE WHEN matched_signal <> '' THEN 1 ELSE 0 END), 0),
       coalesce(sum(CASE WHEN kind = 'suppressed' THEN count ELSE 0 END), 0),
       count(DISTINCT agent_id)
FROM recorder_events WHERE at > now() - interval '24 hours'
GROUP BY GROUPING SETS ((CASE WHEN kind = 'suppressed' THEN op ELSE kind END, source), (CASE WHEN kind = 'suppressed' THEN op ELSE kind END))`)
	if err != nil {
		return nil, fmt.Errorf("summarise recorder events: %w", err)
	}
	defer rows.Close()
	out := map[string]RecorderKindSummary{}
	for rows.Next() {
		var k, source string
		var perKind int
		var events, matched, suppressed, endpoints int
		if err := rows.Scan(&k, &source, &perKind, &events, &matched, &suppressed, &endpoints); err != nil {
			return nil, fmt.Errorf("scan recorder summary: %w", err)
		}
		cur := out[k]
		if cur.Sources == nil {
			cur.Sources = map[string]int{}
		}
		if perKind == 1 {
			// The kind's own row: totals and distinct endpoints.
			cur.Events, cur.Matched, cur.Suppressed, cur.Endpoints = events, matched, suppressed, endpoints
		} else if source != "" {
			cur.Sources[source] = endpoints
		}
		out[k] = cur
	}
	return out, rows.Err()
}

func (s *Store) PruneRecorderEvents(ctx context.Context, timeline, matched time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
DELETE FROM recorder_events
WHERE (matched_signal = '' AND at < now() - $1::interval)
   OR (matched_signal <> '' AND at < now() - $2::interval)`,
		fmt.Sprintf("%d seconds", int(timeline.Seconds())),
		fmt.Sprintf("%d seconds", int(matched.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("prune recorder events: %w", err)
	}
	return tag.RowsAffected(), nil
}

// --- signals ---------------------------------------------------------------

type Signal struct {
	ID          string    `json:"id"`
	Name        string    `json:"name" api:"required"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Expression  string    `json:"expression" api:"required"`
	Objects     []string  `json:"objects" api:"readonly"`
	Enabled     bool      `json:"enabled"`
	CreatedBy   string    `json:"created_by" api:"readonly"`
	CreatedAt   time.Time `json:"created_at" api:"readonly"`
	UpdatedAt   time.Time `json:"updated_at" api:"readonly"`
}

const signalColumns = `id, name, description, severity, expression, objects, enabled, created_by, created_at, updated_at`

func (s *Store) ListSignals(ctx context.Context) ([]Signal, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+signalColumns+` FROM signals ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list signals: %w", err)
	}
	defer rows.Close()
	out := []Signal{}
	for rows.Next() {
		var sg Signal
		if err := rows.Scan(&sg.ID, &sg.Name, &sg.Description, &sg.Severity, &sg.Expression, &sg.Objects, &sg.Enabled, &sg.CreatedBy, &sg.CreatedAt, &sg.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan signal: %w", err)
		}
		if sg.Objects == nil {
			sg.Objects = []string{}
		}
		out = append(out, sg)
	}
	return out, rows.Err()
}

func (s *Store) UpsertSignal(ctx context.Context, sg Signal) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO signals (`+signalColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, severity=EXCLUDED.severity,
		expression=EXCLUDED.expression, objects=EXCLUDED.objects, enabled=EXCLUDED.enabled, updated_at=now()`,
		sg.ID, sg.Name, sg.Description, sg.Severity, sg.Expression, sg.Objects, sg.Enabled, sg.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert signal: %w", err)
	}
	return nil
}

func (s *Store) DeleteSignal(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM signals WHERE id = $1`, id)
	return err
}

type SignalFinding struct {
	ID             string    `json:"id"`
	SignalID       string    `json:"signal_id"`
	SignalName     string    `json:"signal_name,omitempty"`
	SignalSeverity string    `json:"signal_severity,omitempty"`
	AgentID        string    `json:"agent_id"`
	Hostname       string    `json:"hostname,omitempty"`
	Kind           string    `json:"kind"`
	Summary        string    `json:"summary"`
	Count          int       `json:"count"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	Acknowledged   bool      `json:"acknowledged"`
}

// RecordSignalFinding counts one more hit of a signal on an endpoint and
// reports whether it is the first. A finding that was acknowledged and
// fires again is un-acknowledged: the operator said "seen" about the last
// occurrence, not about the next.
func (s *Store) RecordSignalFinding(ctx context.Context, f SignalFinding) (bool, error) {
	var inserted bool
	err := s.pool.QueryRow(ctx, `INSERT INTO signal_findings (id, signal_id, agent_id, kind, summary, count)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (signal_id, agent_id) DO UPDATE SET last_seen = now(), summary = EXCLUDED.summary, kind = EXCLUDED.kind,
		  count = signal_findings.count + EXCLUDED.count, acknowledged = false
		RETURNING (xmax = 0)`, f.ID, f.SignalID, f.AgentID, f.Kind, f.Summary, max(f.Count, 1)).Scan(&inserted)
	if err != nil {
		return false, fmt.Errorf("record signal finding: %w", err)
	}
	return inserted, nil
}

func (s *Store) ListSignalFindings(ctx context.Context, limit int) ([]SignalFinding, error) {
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	rows, err := s.pool.Query(ctx, `
SELECT f.id, f.signal_id, coalesce(sg.name,''), coalesce(sg.severity,''), f.agent_id, coalesce(a.hostname,''),
       f.kind, f.summary, f.count, f.first_seen, f.last_seen, f.acknowledged
FROM signal_findings f
LEFT JOIN signals sg ON sg.id = f.signal_id
LEFT JOIN agents a ON a.agent_id = f.agent_id
ORDER BY f.acknowledged, f.last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list signal findings: %w", err)
	}
	defer rows.Close()
	out := []SignalFinding{}
	for rows.Next() {
		var f SignalFinding
		if err := rows.Scan(&f.ID, &f.SignalID, &f.SignalName, &f.SignalSeverity, &f.AgentID, &f.Hostname, &f.Kind, &f.Summary, &f.Count, &f.FirstSeen, &f.LastSeen, &f.Acknowledged); err != nil {
			return nil, fmt.Errorf("scan signal finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) AcknowledgeSignalFinding(ctx context.Context, id string, ack bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE signal_findings SET acknowledged = $2 WHERE id = $1`, id, ack)
	return err
}
