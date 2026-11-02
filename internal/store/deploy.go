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

func scanDeployRevision(row pgx.Row) (*proto.DeployRevision, error) {
	var r proto.DeployRevision
	var raw []byte
	e := row.Scan(&r.ID, &r.PackageID, &r.Label, &raw, &r.Published, &r.CreatedBy, &r.CreatedAt, &r.Retired, &r.RetiredNote, &r.RetiredBy, &r.RetiredAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(raw, &r.Definition); e != nil {
		return nil, e
	}
	return &r, nil
}

const deployRevisionColumns = `id,package_id,label,definition,published,created_by,created_at,retired,retired_note,retired_by,retired_at`

func (s *Store) GetDeployRevision(ctx context.Context, id string) (*proto.DeployRevision, error) {
	return scanDeployRevision(s.pool.QueryRow(ctx, `SELECT `+deployRevisionColumns+` FROM deploy_revisions WHERE id=$1`, id))
}
func (s *Store) ListDeployRevisions(ctx context.Context, packageID string) ([]proto.DeployRevision, error) {
	rows, e := s.pool.Query(ctx, `SELECT `+deployRevisionColumns+` FROM deploy_revisions WHERE ($1='' OR package_id=$1) ORDER BY created_at DESC`, packageID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []proto.DeployRevision{}
	for rows.Next() {
		r, e := scanDeployRevision(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}
func (s *Store) SaveDeployDraft(ctx context.Context, r proto.DeployRevision) (*proto.DeployRevision, error) {
	raw, e := json.Marshal(r.Definition)
	if e != nil {
		return nil, e
	}
	return scanDeployRevision(s.pool.QueryRow(ctx, `INSERT INTO deploy_revisions(id,package_id,label,definition,created_by) VALUES($1,$2,$3,$4,$5) RETURNING `+deployRevisionColumns, r.ID, r.PackageID, r.Label, raw, r.CreatedBy))
}

// DeleteDeployDraft removes an unpublished revision and everything that
// exists only to describe it: the jobs from any test dispatch, and any
// installation rows pinned to it. Reports how many job records went.
//
// Only drafts. A published revision is what deployments, schedules and
// playbook steps were pinned to, so it is retired rather than deleted --
// deleting it would rewrite what an endpoint was actually sent.
//
// Taking the test-run records with it is deliberate. A draft is something an
// operator is still iterating on, and its test results are scaffolding; what
// must not disappear is the fact that a dispatch happened at all, and that
// lives in the audit log, which this does not touch.
func (s *Store) DeleteDeployDraft(ctx context.Context, id string) (jobs int64, deleted bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback(ctx)

	// Guarded inside the transaction, not just by the caller: published is
	// the one state this must never remove, and checking it here means a
	// concurrent publish cannot slip between the check and the delete.
	var published bool
	if err := tx.QueryRow(ctx,
		`SELECT published FROM deploy_revisions WHERE id = $1 FOR UPDATE`, id).Scan(&published); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("read deploy draft: %w", err)
	}
	if published {
		return 0, false, nil
	}

	tag, err := tx.Exec(ctx, `DELETE FROM deploy_jobs WHERE revision_id = $1`, id)
	if err != nil {
		return 0, false, fmt.Errorf("delete draft jobs: %w", err)
	}
	jobs = tag.RowsAffected()

	// No foreign key on this one, so a row here would otherwise be left
	// pointing at a revision that no longer exists.
	if _, err := tx.Exec(ctx, `DELETE FROM deploy_installations WHERE revision_id = $1`, id); err != nil {
		return 0, false, fmt.Errorf("delete draft installations: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM deploy_revisions WHERE id = $1`, id); err != nil {
		return 0, false, fmt.Errorf("delete deploy draft: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, false, fmt.Errorf("commit draft delete: %w", err)
	}
	return jobs, true, nil
}

// UpdateDeployDraft rewrites an unpublished revision in place. Reports nil
// when there is no such draft, which includes "it has since been published".
//
// This is what stops a package accumulating a revision per keystroke-save.
// Every save used to mint a new one, so iterating on a single version left a
// row of identical labels behind and nothing to do about them.
func (s *Store) UpdateDeployDraft(ctx context.Context, r proto.DeployRevision) (*proto.DeployRevision, error) {
	raw, e := json.Marshal(r.Definition)
	if e != nil {
		return nil, e
	}
	// scanDeployRevision reports a miss as (nil, nil), which is exactly the
	// "no such draft" answer this promises.
	return scanDeployRevision(s.pool.QueryRow(ctx,
		`UPDATE deploy_revisions SET label = $2, definition = $3
		 WHERE id = $1 AND package_id = $4 AND published = false
		 RETURNING `+deployRevisionColumns, r.ID, r.Label, raw, r.PackageID))
}

func (s *Store) PublishDeployRevision(ctx context.Context, r proto.DeployRevision) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var packageID, kind string
	if e = tx.QueryRow(ctx, `SELECT id,kind FROM software_packages WHERE id=$1 FOR UPDATE`, r.PackageID).Scan(&packageID, &kind); e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deploy_revisions WHERE package_id=$1 AND label=$2 AND published)`, r.PackageID, r.Label).Scan(&exists); e != nil {
		return e
	}
	if exists && kind == KindAction {
		return fmt.Errorf("published version label already exists; choose a new label")
	}
	raw, e := json.Marshal(r.Definition)
	if e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE deploy_revisions SET definition=$2,published=true WHERE id=$1 AND published=false`, r.ID, raw)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("revision is already published or missing")
	}
	_, e = tx.Exec(ctx, `UPDATE software_packages SET deploy_revision=$2,self_service_revision=CASE WHEN self_service_revision='' THEN $2 ELSE self_service_revision END,enabled=true,updated_at=now() WHERE id=$1`, r.PackageID, r.ID)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

type DeployJobRecord struct {
	Job             proto.DeployJob `json:"job"`
	Status          string          `json:"status"`
	Detail          string          `json:"detail"`
	CancelRequested bool            `json:"cancel_requested"`
	ForceCancel     bool            `json:"force_cancel"`
	// LastHeartbeat is when the target endpoint was last heard from, nil if
	// never. Carried alongside the job because a job that is still "running"
	// on an endpoint that stopped checking in the moment it was dispatched is
	// not running at all -- it is what an agent update looks like when it
	// takes the agent with it. Whether that gap counts as stalled is the
	// server's call, so only the fact is reported here.
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
}

func (s *Store) CreateDeployJob(ctx context.Context, j proto.DeployJob) error {
	raw, e := json.Marshal(j)
	if e != nil {
		return e
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO deploy_jobs(id,run_id,agent_id,package_id,revision_id,job) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING`, j.ID, j.RunID, j.AgentID, j.PackageID, j.RevisionID, raw)
	return e
}
func (s *Store) ListDeployJobs(ctx context.Context, active bool, runID string) ([]DeployJobRecord, error) {
	// LEFT JOIN: deploy_jobs deliberately has no foreign key to agents (the
	// constraint is dropped in schema.sql), so an endpoint can be removed
	// from inventory while its job records remain.
	rows, e := s.pool.Query(ctx, `SELECT j.job,j.status,j.detail,j.cancel_requested,j.force_cancel,a.last_heartbeat FROM deploy_jobs j LEFT JOIN agents a ON a.agent_id = j.agent_id WHERE ($1=false OR j.status NOT IN ('succeeded','failed','timed_out','cancelled','interrupted','expired','skipped','unsupported')) AND ($2='' OR j.run_id=$2) ORDER BY j.created_at DESC LIMIT 1000`, active, runID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DeployJobRecord{}
	for rows.Next() {
		var r DeployJobRecord
		var raw []byte
		if e = rows.Scan(&raw, &r.Status, &r.Detail, &r.CancelRequested, &r.ForceCancel, &r.LastHeartbeat); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &r.Job); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) GetDeployJob(ctx context.Context, id string) (*DeployJobRecord, error) {
	var r DeployJobRecord
	var raw []byte
	e := s.pool.QueryRow(ctx, `SELECT job,status,detail,cancel_requested,force_cancel FROM deploy_jobs WHERE id=$1`, id).Scan(&raw, &r.Status, &r.Detail, &r.CancelRequested, &r.ForceCancel)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(raw, &r.Job); e != nil {
		return nil, e
	}
	return &r, nil
}
func (s *Store) UpdateDeployJob(ctx context.Context, id, agentID, status, detail string) error {
	_, e := s.pool.Exec(ctx, `UPDATE deploy_jobs SET status=$3,detail=$4,updated_at=now() WHERE id=$1 AND agent_id=$2 AND ($3<>'accepted' OR status='queued') AND status NOT IN ('succeeded','failed','timed_out','cancelled','interrupted','expired','skipped','unsupported')`, id, agentID, status, detail)
	return e
}
func (s *Store) CancelDeployJob(ctx context.Context, id string, force bool) error {
	_, e := s.pool.Exec(ctx, `UPDATE deploy_jobs SET cancel_requested=true,force_cancel=$2 WHERE id=$1`, id, force)
	return e
}
func (s *Store) DeployDependents(ctx context.Context, agentID, packageID string) ([]string, error) {
	rows, e := s.pool.Query(ctx, `SELECT package_id FROM deploy_installations WHERE agent_id=$1 AND $2=ANY(dependencies)`, agentID, packageID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
func (s *Store) RecordDeployInstallation(ctx context.Context, agentID string, p proto.DeployPackagePlan) error {
	if p.Operation == "run" {
		return nil
	}
	if p.Operation == "remove" {
		_, e := s.pool.Exec(ctx, `DELETE FROM deploy_installations WHERE agent_id=$1 AND package_id=$2`, agentID, p.PackageID)
		return e
	}
	deps := []string{}
	for _, d := range p.Variant.Actions[p.Operation].Dependencies {
		deps = append(deps, d.PackageID)
	}
	_, e := s.pool.Exec(ctx, `INSERT INTO deploy_installations(agent_id,package_id,revision_id,dependencies) VALUES($1,$2,$3,$4) ON CONFLICT(agent_id,package_id) DO UPDATE SET revision_id=EXCLUDED.revision_id,dependencies=EXCLUDED.dependencies,updated_at=now()`, agentID, p.PackageID, p.RevisionID, deps)
	return e
}

// CreateDeployRun commits the run, all target actions, and their frozen jobs as
// one dispatchable set. The worker cannot observe a partially recorded rollout.
func (s *Store) CreateDeployRun(ctx context.Context, run PatchJobRun, jobs []proto.DeployJob, held ...bool) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `INSERT INTO patch_job_runs(id,schedule_name,target_desc,agent_count,triggered_by,notify_on_finish) VALUES($1,$2,$3,$4,$5,$6)`, run.ID, run.ScheduleName, run.TargetDesc, len(jobs), run.TriggeredBy, run.NotifyOnFinish); e != nil {
		return e
	}
	for _, j := range jobs {
		raw, e := json.Marshal(j)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO agent_actions(id,agent_id,kind,summary,status,requested_by,run_id) VALUES($1,$2,$3,$4,'started',$5,$6)`, j.ID, j.AgentID, "software_"+j.Operation, run.ScheduleName, run.TriggeredBy, run.ID); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO deploy_jobs(id,run_id,agent_id,package_id,revision_id,job,status) VALUES($1,$2,$3,$4,$5,$6,$7)`, j.ID, run.ID, j.AgentID, j.PackageID, j.RevisionID, raw, initialDeployStatus(held)); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}

func initialDeployStatus(held []bool) string {
	if len(held) > 0 && held[0] {
		return "held"
	}
	return "queued"
}
func (s *Store) ReleaseDeployJob(ctx context.Context, id string) error {
	_, e := s.pool.Exec(ctx, `UPDATE deploy_jobs SET status='queued',updated_at=now() WHERE id=$1 AND status='held' AND cancel_requested=false`, id)
	return e
}
func (s *Store) CancelHeldDeployJobs(ctx context.Context, runID, detail string) error {
	_, e := s.pool.Exec(ctx, `WITH cancelled AS (UPDATE deploy_jobs SET status='cancelled',detail=$2,updated_at=now() WHERE run_id=$1 AND status='held' RETURNING id) UPDATE agent_actions SET status='cancelled',detail=$2,finished_at=now() WHERE id IN (SELECT id FROM cancelled)`, runID, detail)
	return e
}

// deployFinalStatuses are the deploy job states nothing moves on from; the
// same list as deploy.Terminal, which the store cannot import.
var deployFinalStatuses = []string{"succeeded", "failed", "timed_out", "cancelled", "interrupted", "expired", "skipped", "unsupported"}

// ClaimFinishedRun reports, exactly once, that a run which asked to be
// told has finished: every one of its jobs is in a final state. It returns
// the run and a count of its jobs by status, or nil when the run did not
// ask, has jobs still going, or was already reported. The claim and the
// check are one statement, so two job results landing together cannot both
// claim it.
func (s *Store) ClaimFinishedRun(ctx context.Context, runID string) (*PatchJobRun, map[string]int, error) {
	var r PatchJobRun
	e := s.pool.QueryRow(ctx, `
UPDATE patch_job_runs SET notified_at = now()
WHERE id = $1 AND notify_on_finish AND notified_at IS NULL
  AND EXISTS (SELECT 1 FROM deploy_jobs WHERE run_id = $1)
  AND NOT EXISTS (SELECT 1 FROM deploy_jobs WHERE run_id = $1 AND NOT (status = ANY($2)))
RETURNING id, schedule_name, target_desc, agent_count, triggered_by, started_at`, runID, deployFinalStatuses).
		Scan(&r.ID, &r.ScheduleName, &r.TargetDesc, &r.AgentCount, &r.TriggeredBy, &r.StartedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if e != nil {
		return nil, nil, e
	}
	counts := map[string]int{}
	rows, e := s.pool.Query(ctx, `SELECT status, count(*) FROM deploy_jobs WHERE run_id = $1 GROUP BY status`, runID)
	if e != nil {
		return &r, counts, e
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if e := rows.Scan(&st, &n); e != nil {
			return &r, counts, e
		}
		counts[st] = n
	}
	return &r, counts, rows.Err()
}
