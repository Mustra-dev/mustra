package store

import (
	"context"
	"fmt"
	"time"
)

// RecordHealthSamples writes one health score per endpoint at one moment.
// The score already existed; nothing kept yesterday's, so "did this
// deployment make these machines worse" had no way to be answered.
func (s *Store) RecordHealthSamples(ctx context.Context, at time.Time, scores map[string]int) error {
	if len(scores) == 0 {
		return nil
	}
	ids := make([]string, 0, len(scores))
	vals := make([]int, 0, len(scores))
	for id, v := range scores {
		ids = append(ids, id)
		vals = append(vals, v)
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO endpoint_health (agent_id, at, score)
SELECT id, $1, v FROM unnest($2::text[], $3::int[]) AS t(id, v)
ON CONFLICT (agent_id, at) DO UPDATE SET score = EXCLUDED.score`, at, ids, vals)
	if err != nil {
		return fmt.Errorf("record health samples: %w", err)
	}
	return nil
}

func (s *Store) PruneHealthSamples(ctx context.Context, keep time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM endpoint_health WHERE at < $1`, time.Now().Add(-keep))
	if err != nil {
		return 0, fmt.Errorf("prune health samples: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeployOutcome is one package's record across the fleet: how often it was
// attempted, how often it worked, and what it did to the health of the
// machines it landed on.
type DeployOutcome struct {
	Attempts     int        `json:"attempts"`
	Succeeded    int        `json:"succeeded"`
	Failed       int        `json:"failed"`
	Endpoints    int        `json:"endpoints"`
	HealthN      int        `json:"health_samples"`
	HealthBefore *float64   `json:"health_before,omitempty"`
	HealthAfter  *float64   `json:"health_after,omitempty"`
	FirstSeen    *time.Time `json:"first_seen,omitempty"`
	LastSeen     *time.Time `json:"last_seen,omitempty"`
}

// DeployOutcomeFor summarises every finished attempt whose summary matches
// a package, by name. Matching on the summary rather than a package id
// because that is what agent_actions has recorded all along; a column
// added now would answer for nothing that already happened, and the point
// of a confidence score is the history.
// DeployOutcomeFor totals what happened when any of summaries ran.
//
// It matches on exact summaries rather than a substring because
// deploymentLabel produces a closed set of them ("Install jq", "Update
// mustra agent", a bare action-package name). A LIKE '%jq%' would count
// any run whose label happened to contain those two letters, and — worse —
// would fold "Cancel Reboot Computer" into Reboot Computer's success rate,
// scoring a package by how often somebody called it off.
func (s *Store) DeployOutcomeFor(ctx context.Context, summaries []string, window time.Duration) (DeployOutcome, error) {
	var o DeployOutcome
	err := s.pool.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE status IN ('succeeded','failed')),
       count(*) FILTER (WHERE status = 'succeeded'),
       count(*) FILTER (WHERE status = 'failed'),
       count(DISTINCT agent_id),
       min(started_at), max(started_at)
FROM agent_actions
WHERE summary = ANY($1) AND started_at >= $2`,
		summaries, time.Now().Add(-window)).Scan(&o.Attempts, &o.Succeeded, &o.Failed, &o.Endpoints, &o.FirstSeen, &o.LastSeen)
	if err != nil {
		return o, fmt.Errorf("deploy outcome: %w", err)
	}
	if o.Attempts == 0 {
		return o, nil
	}
	// Health on the machines this landed on, in the day either side of the
	// attempt. Same endpoints on both sides, so this is a change in those
	// machines rather than a comparison of two different populations.
	var before, after *float64
	var n int
	err = s.pool.QueryRow(ctx, `
WITH landed AS (
    SELECT agent_id, max(started_at) AS at
    FROM agent_actions
    WHERE summary = ANY($1) AND status = 'succeeded' AND started_at >= $2
    GROUP BY agent_id
)
SELECT avg(h.score) FILTER (WHERE h.at <  l.at AND h.at >= l.at - interval '24 hours'),
       avg(h.score) FILTER (WHERE h.at >= l.at AND h.at <= l.at + interval '24 hours'),
       count(DISTINCT l.agent_id)
FROM landed l JOIN endpoint_health h ON h.agent_id = l.agent_id
WHERE h.at BETWEEN l.at - interval '24 hours' AND l.at + interval '24 hours'`,
		summaries, time.Now().Add(-window)).Scan(&before, &after, &n)
	if err != nil {
		return o, fmt.Errorf("deploy health delta: %w", err)
	}
	o.HealthBefore, o.HealthAfter, o.HealthN = before, after, n
	return o, nil
}
