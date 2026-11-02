package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mustra-dev/mustra/internal/patchpolicy"
)

// PatchPolicy is a patch list (Kind "allow") or a block list (Kind
// "block"); see internal/patchpolicy for how the rules resolve.
type PatchPolicy struct {
	ID          string            `json:"id" api:"readonly"`
	Name        string            `json:"name" api:"required"`
	Kind        string            `json:"kind" api:"required"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
	GroupIDs    []string          `json:"group_ids"`
	Rules       patchpolicy.Rules `json:"rules"`
	CreatedBy   string            `json:"created_by" api:"readonly"`
	CreatedAt   time.Time         `json:"created_at" api:"readonly"`
	UpdatedAt   time.Time         `json:"updated_at" api:"readonly"`
}

const patchPolicyColumns = `id, name, kind, description, enabled, group_ids, rules, created_by, created_at, updated_at`

func scanPatchPolicy(row interface{ Scan(...any) error }) (PatchPolicy, error) {
	var p PatchPolicy
	var rules []byte
	if err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.Description, &p.Enabled, &p.GroupIDs, &rules, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	_ = json.Unmarshal(rules, &p.Rules)
	if p.GroupIDs == nil {
		p.GroupIDs = []string{}
	}
	return p, nil
}

func (s *Store) ListPatchPolicies(ctx context.Context) ([]PatchPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+patchPolicyColumns+` FROM patch_policies ORDER BY kind, name`)
	if err != nil {
		return nil, fmt.Errorf("list patch policies: %w", err)
	}
	defer rows.Close()
	out := []PatchPolicy{}
	for rows.Next() {
		p, err := scanPatchPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan patch policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPatchPolicy(ctx context.Context, id string) (*PatchPolicy, error) {
	p, err := scanPatchPolicy(s.pool.QueryRow(ctx, `SELECT `+patchPolicyColumns+` FROM patch_policies WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get patch policy: %w", err)
	}
	return &p, nil
}

func (s *Store) UpsertPatchPolicy(ctx context.Context, p PatchPolicy) error {
	rules, _ := json.Marshal(p.Rules)
	_, err := s.pool.Exec(ctx, `INSERT INTO patch_policies (`+patchPolicyColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, kind=EXCLUDED.kind, description=EXCLUDED.description, enabled=EXCLUDED.enabled,
		group_ids=EXCLUDED.group_ids, rules=EXCLUDED.rules, updated_at=now()`,
		p.ID, p.Name, p.Kind, p.Description, p.Enabled, p.GroupIDs, rules, p.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert patch policy: %w", err)
	}
	return nil
}

func (s *Store) DeletePatchPolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM patch_policies WHERE id = $1`, id)
	return err
}

// PatchObservation is when the fleet first and last saw a patch pending.
type PatchObservation struct {
	OS         string
	Name       string
	NewVersion string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// PatchObservationKey identifies an observation the way the table does.
type PatchObservationKey struct{ OS, Name, NewVersion string }

// RecordPatchObservations notes every patch in a snapshot, keeping the
// first time each was seen. One statement per snapshot rather than per
// patch: a Windows box can report a hundred pending updates.
func (s *Store) RecordPatchObservations(ctx context.Context, os string, names, versions []string, at time.Time) error {
	if len(names) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO patch_observations (os, name, new_version, first_seen, last_seen)
		SELECT $1, n, v, $4, $4 FROM unnest($2::text[], $3::text[]) AS t(n, v)
		ON CONFLICT (os, name, new_version) DO UPDATE SET last_seen = GREATEST(patch_observations.last_seen, EXCLUDED.last_seen)`,
		os, names, versions, at)
	if err != nil {
		return fmt.Errorf("record patch observations: %w", err)
	}
	return nil
}

func (s *Store) ListPatchObservations(ctx context.Context) (map[PatchObservationKey]PatchObservation, error) {
	rows, err := s.pool.Query(ctx, `SELECT os, name, new_version, first_seen, last_seen FROM patch_observations`)
	if err != nil {
		return nil, fmt.Errorf("list patch observations: %w", err)
	}
	defer rows.Close()
	out := map[PatchObservationKey]PatchObservation{}
	for rows.Next() {
		var o PatchObservation
		if err := rows.Scan(&o.OS, &o.Name, &o.NewVersion, &o.FirstSeen, &o.LastSeen); err != nil {
			return nil, fmt.Errorf("scan patch observation: %w", err)
		}
		out[PatchObservationKey{o.OS, o.Name, o.NewVersion}] = o
	}
	return out, rows.Err()
}

// PurgePatchObservations forgets patches nobody has reported for a while,
// so the table tracks what is pending rather than everything that ever was.
func (s *Store) PurgePatchObservations(ctx context.Context, olderThan time.Duration) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM patch_observations WHERE last_seen < now() - $1::interval`, olderThan.String())
	return err
}

// --- action status transitions used by the patch taxonomy ---

// StartAgentActionWithStatus records an action in a non-default initial
// state: 'waiting' for one held until its maintenance window opens.
func (s *Store) StartAgentActionWithStatus(ctx context.Context, a AgentAction, status, detail string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO agent_actions (id, agent_id, kind, summary, status, detail, requested_by, run_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, a.ID, a.AgentID, a.Kind, a.Summary, status, detail, a.RequestedBy, a.RunID)
	if err != nil {
		return fmt.Errorf("start agent action: %w", err)
	}
	return nil
}

// SetAgentActionProgress moves an open action between non-terminal states
// (waiting → started → downloading → installing). It never touches a
// finished action: a late progress report must not reopen a result.
func (s *Store) SetAgentActionProgress(ctx context.Context, agentID, id, status, detail string) error {
	// agentID scopes the update (see FinishAgentAction): a progress report
	// is attributed to its sender, and must not touch another agent's action.
	_, err := s.pool.Exec(ctx, `UPDATE agent_actions SET status = $2, detail = $3
WHERE id = $1 AND finished_at IS NULL AND ($4 = '' OR agent_id = $4)`, id, status, detail, agentID)
	if err != nil {
		return fmt.Errorf("set agent action progress: %w", err)
	}
	return nil
}

// WaitingAgentActions lists actions held for a maintenance window, with
// the fields the dispatcher needs to release them.
func (s *Store) WaitingAgentActions(ctx context.Context, kind string) ([]AgentAction, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, coalesce(run_id,''), agent_id, kind, summary, status, detail, requested_by, started_at, finished_at
		FROM agent_actions WHERE status = 'waiting' AND kind = $1 ORDER BY started_at`, kind)
	if err != nil {
		return nil, fmt.Errorf("waiting agent actions: %w", err)
	}
	defer rows.Close()
	var out []AgentAction
	for rows.Next() {
		var a AgentAction
		if err := rows.Scan(&a.ID, &a.RunID, &a.AgentID, &a.Kind, &a.Summary, &a.Status, &a.Detail, &a.RequestedBy, &a.StartedAt, &a.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan waiting action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SweepAbandonedActions closes actions still open long after any job could
// still be running: the agent restarted mid-job (an update, a reboot) and
// the result never came. Left open they showed as running forever in the
// endpoint's Self Service window while the console called the run
// stalled. Held ("waiting") actions are not touched; patchWaitLoop expires
// those on its own terms.
func (s *Store) SweepAbandonedActions(ctx context.Context, olderThan time.Duration, why string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_actions
SET status = 'timed_out', finished_at = now(),
    detail = CASE WHEN coalesce(detail, '') = '' THEN $2 ELSE detail || E'\n' || $2 END
WHERE finished_at IS NULL
  AND status IN ('started', 'running', 'pending', 'downloading', 'installing')
  AND started_at < now() - make_interval(secs => $1)`, olderThan.Seconds(), why)
	if err != nil {
		return 0, fmt.Errorf("sweep abandoned actions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// OpenPatchJob is a patch job an endpoint has not finished: its status
// ("started", "downloading", "installing", "waiting") and when it began.
type OpenPatchJob struct {
	Status    string
	StartedAt time.Time
}

// OpenPatchJobs maps each endpoint with an unfinished patch job to the
// newest one. A second job for the same endpoint is refused while one is
// open; the abandoned-action sweep closes any that never report. A macOS
// install handed to the MDM counts too: the agent's job has finished, but
// the Mac is still downloading and installing, and a new job would only
// send the same update again. Its status reads "installing macOS".
func (s *Store) OpenPatchJobs(ctx context.Context) (map[string]OpenPatchJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ON (agent_id) agent_id,
  CASE WHEN kind = 'macos_mdm_update' THEN 'installing macOS' ELSE status END, started_at
FROM agent_actions WHERE kind IN ('patch_apply', 'macos_mdm_update') AND finished_at IS NULL
ORDER BY agent_id, started_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("open patch jobs: %w", err)
	}
	defer rows.Close()
	out := map[string]OpenPatchJob{}
	for rows.Next() {
		var id string
		var j OpenPatchJob
		if err := rows.Scan(&id, &j.Status, &j.StartedAt); err != nil {
			return nil, fmt.Errorf("open patch jobs: %w", err)
		}
		out[id] = j
	}
	return out, rows.Err()
}

// AgentActionExists says whether a run already has an action of this kind
// for an endpoint, so a step triggered by a redelivered result runs once.
func (s *Store) AgentActionExists(ctx context.Context, runID, agentID, kind string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM agent_actions WHERE run_id = $1 AND agent_id = $2 AND kind = $3`,
		runID, agentID, kind).Scan(&n)
	return n > 0, err
}

// ActionOrigin returns who asked for an action and the restart they chose.
func (s *Store) ActionOrigin(ctx context.Context, id string) (requestedBy, restartMode string, err error) {
	err = s.pool.QueryRow(ctx, `SELECT requested_by, restart_mode FROM agent_actions WHERE id = $1`, id).Scan(&requestedBy, &restartMode)
	return requestedBy, restartMode, err
}

// SetActionSummary renames an open action once it is known what it does.
func (s *Store) SetActionSummary(ctx context.Context, id, summary string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_actions SET summary = $2 WHERE id = $1 AND finished_at IS NULL`, id, summary)
	return err
}

// OpenAgentActions lists the unfinished actions of one kind.
func (s *Store) OpenAgentActions(ctx context.Context, kind string) ([]AgentAction, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, coalesce(run_id,''), agent_id, kind, summary, status, detail, requested_by, started_at, finished_at
		FROM agent_actions WHERE finished_at IS NULL AND kind = $1 ORDER BY started_at`, kind)
	if err != nil {
		return nil, fmt.Errorf("open agent actions: %w", err)
	}
	defer rows.Close()
	var out []AgentAction
	for rows.Next() {
		var a AgentAction
		if err := rows.Scan(&a.ID, &a.RunID, &a.AgentID, &a.Kind, &a.Summary, &a.Status, &a.Detail, &a.RequestedBy, &a.StartedAt, &a.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan open action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// InterruptAgentActions closes the actions an agent was still running
// when it restarted (an agent update, a crash, a reboot mid-install): the
// process that would have reported their outcome is gone, so left alone
// they would read "installing" forever. Waiting states (pending_restart,
// waiting) and server-driven work (a macOS update through MDM) are not
// the agent's to lose. Actions started in the last half minute are left
// too, in case one was dispatched as the agent came back.
func (s *Store) InterruptAgentActions(ctx context.Context, agentID string) ([]AgentAction, error) {
	rows, err := s.pool.Query(ctx, `UPDATE agent_actions SET status = 'interrupted', finished_at = now(),
			detail = CASE WHEN detail = '' THEN '' ELSE detail || E'\n' END ||
				'Interrupted: the agent restarted (an agent update or a reboot) before this finished. Run it again.'
		WHERE agent_id = $1 AND status IN ('started', 'running', 'downloading', 'installing')
		  AND kind <> 'macos_mdm_update' AND started_at < now() - interval '30 seconds'
		RETURNING id, kind, run_id`, agentID)
	if err != nil {
		return nil, fmt.Errorf("interrupt agent actions: %w", err)
	}
	defer rows.Close()
	var out []AgentAction
	for rows.Next() {
		var a AgentAction
		if err := rows.Scan(&a.ID, &a.Kind, &a.RunID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
