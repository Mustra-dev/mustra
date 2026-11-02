package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CatalogRequest is somebody asking for an item their machine isn't
// entitled to.
type CatalogRequest struct {
	ID          string     `json:"id"`
	ItemID      string     `json:"item_id"`
	ItemName    string     `json:"item_name"` // joined for display
	AgentID     string     `json:"agent_id"`
	Hostname    string     `json:"hostname"` // joined for display
	RequestedBy string     `json:"requested_by"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	DecidedAt   *time.Time `json:"decided_at"`
	DecidedBy   string     `json:"decided_by"`
}

func (s *Store) CreateCatalogRequest(ctx context.Context, r CatalogRequest) error {
	const q = `
INSERT INTO catalog_requests (id, item_id, agent_id, requested_by, reason)
VALUES ($1, $2, $3, $4, $5)`
	if _, err := s.pool.Exec(ctx, q, r.ID, r.ItemID, r.AgentID, r.RequestedBy, r.Reason); err != nil {
		return fmt.Errorf("create catalog request: %w", err)
	}
	return nil
}

func (s *Store) ListCatalogRequests(ctx context.Context) ([]CatalogRequest, error) {
	const q = `
SELECT r.id, r.item_id, i.name, r.agent_id, a.hostname, r.requested_by, r.reason,
       r.status, r.requested_at, r.decided_at, r.decided_by
FROM catalog_requests r
-- software_packages, not catalog_items: a request names a package, and
-- joining the superseded table meant the approval queue read names from a
-- place the requested item usually is not.
JOIN software_packages i ON i.id = r.item_id
JOIN agents a ON a.agent_id = r.agent_id
ORDER BY r.requested_at DESC LIMIT 200`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list catalog requests: %w", err)
	}
	defer rows.Close()
	var out []CatalogRequest
	for rows.Next() {
		var r CatalogRequest
		if err := rows.Scan(&r.ID, &r.ItemID, &r.ItemName, &r.AgentID, &r.Hostname, &r.RequestedBy,
			&r.Reason, &r.Status, &r.RequestedAt, &r.DecidedAt, &r.DecidedBy); err != nil {
			return nil, fmt.Errorf("scan catalog request: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetCatalogRequest returns one request, or nil when there is none. The
// joins are LEFT: a request whose package or endpoint is gone still exists.
func (s *Store) GetCatalogRequest(ctx context.Context, id string) (*CatalogRequest, error) {
	const q = `
SELECT r.id, r.item_id, COALESCE(i.name, ''), r.agent_id, COALESCE(a.hostname, ''), r.requested_by, r.reason,
       r.status, r.requested_at, r.decided_at, r.decided_by
FROM catalog_requests r
LEFT JOIN software_packages i ON i.id = r.item_id
LEFT JOIN agents a ON a.agent_id = r.agent_id
WHERE r.id = $1`
	var r CatalogRequest
	err := s.pool.QueryRow(ctx, q, id).Scan(&r.ID, &r.ItemID, &r.ItemName, &r.AgentID, &r.Hostname, &r.RequestedBy,
		&r.Reason, &r.Status, &r.RequestedAt, &r.DecidedAt, &r.DecidedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get catalog request: %w", err)
	}
	return &r, nil
}

// ApprovedRequestExists is how an approval becomes an entitlement: the
// device is offered the item because someone said yes, without having to
// be moved into a group.
func (s *Store) ApprovedRequestExists(ctx context.Context, itemID, agentID string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
SELECT count(*) FROM catalog_requests
WHERE item_id = $1 AND agent_id = $2 AND status = 'approved'`, itemID, agentID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check approved request: %w", err)
	}
	return n > 0, nil
}

// ErrNoSuchCatalogRequest and ErrCatalogRequestDecided are why
// DecideCatalogRequest changed nothing.
var (
	ErrNoSuchCatalogRequest  = errors.New("no such catalog request")
	ErrCatalogRequestDecided = errors.New("that request has already been decided")
)

// DecideCatalogRequest decides a pending request and returns it, with the
// item and endpoint names for the audit record. Only a pending one: an
// approval is an entitlement, so turning a denial into one later, or
// overwriting who decided, would lose the first decision.
func (s *Store) DecideCatalogRequest(ctx context.Context, id, status, decidedBy string) (*CatalogRequest, error) {
	const q = `
WITH d AS (
  UPDATE catalog_requests SET status = $2, decided_at = now(), decided_by = $3
  WHERE id = $1 AND status = 'pending'
  RETURNING id, item_id, agent_id, requested_by, reason, status, requested_at, decided_at, decided_by
)
SELECT d.id, d.item_id, COALESCE(i.name, ''), d.agent_id, COALESCE(a.hostname, ''), d.requested_by,
       d.reason, d.status, d.requested_at, d.decided_at, d.decided_by
FROM d
LEFT JOIN software_packages i ON i.id = d.item_id
LEFT JOIN agents a ON a.agent_id = d.agent_id`
	var r CatalogRequest
	err := s.pool.QueryRow(ctx, q, id, status, decidedBy).Scan(&r.ID, &r.ItemID, &r.ItemName, &r.AgentID,
		&r.Hostname, &r.RequestedBy, &r.Reason, &r.Status, &r.RequestedAt, &r.DecidedAt, &r.DecidedBy)
	if err == nil {
		return &r, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("decide catalog request: %w", err)
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM catalog_requests WHERE id = $1)`, id).Scan(&exists); err != nil {
		return nil, fmt.Errorf("decide catalog request: %w", err)
	}
	if exists {
		return nil, ErrCatalogRequestDecided
	}
	return nil, ErrNoSuchCatalogRequest
}

// PendingRequestFor reports whether this device already has an undecided
// request for an item, so Self Service can say "pending" instead of
// offering the button again.
func (s *Store) PendingRequestFor(ctx context.Context, itemID, agentID string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
SELECT count(*) FROM catalog_requests
WHERE item_id = $1 AND agent_id = $2 AND status = 'pending'`, itemID, agentID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check pending request: %w", err)
	}
	return n > 0, nil
}

// AgentAction is one thing mustra did to a device.
type AgentAction struct {
	ID          string     `json:"id"`
	RunID       string     `json:"run_id"`
	AgentID     string     `json:"agent_id"`
	Kind        string     `json:"kind"`
	Summary     string     `json:"summary"`
	Status      string     `json:"status"`
	Detail      string     `json:"detail"`
	RequestedBy string     `json:"requested_by"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
}

// SetActionRestart records how a patch job should restart the endpoint
// afterwards; ActionRestart reads it back when a held job is dispatched.
func (s *Store) SetActionRestart(ctx context.Context, id, mode string, warnMinutes int) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_actions SET restart_mode = $2, restart_warn_minutes = $3 WHERE id = $1`, id, mode, warnMinutes)
	return err
}

func (s *Store) ActionRestart(ctx context.Context, id string) (mode string, warnMinutes int, err error) {
	err = s.pool.QueryRow(ctx, `SELECT restart_mode, restart_warn_minutes FROM agent_actions WHERE id = $1`, id).Scan(&mode, &warnMinutes)
	return mode, warnMinutes, err
}

// SetActionPatchOnly records the packages a patch job is narrowed to.
func (s *Store) SetActionPatchOnly(ctx context.Context, id string, packages []string) error {
	raw, err := json.Marshal(packages)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE agent_actions SET patch_only = $2 WHERE id = $1`, id, raw)
	return err
}

// ActionPatchOnly returns the packages a patch job is narrowed to, or nil
// when it applies everything pending.
func (s *Store) ActionPatchOnly(ctx context.Context, id string) ([]string, error) {
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT patch_only FROM agent_actions WHERE id = $1`, id).Scan(&raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func (s *Store) StartAgentAction(ctx context.Context, a AgentAction) error {
	const q = `
INSERT INTO agent_actions (id, agent_id, kind, summary, status, requested_by, run_id)
VALUES ($1, $2, $3, $4, 'started', $5, $6)`
	if _, err := s.pool.Exec(ctx, q, a.ID, a.AgentID, a.Kind, a.Summary, a.RequestedBy, a.RunID); err != nil {
		return fmt.Errorf("start agent action: %w", err)
	}
	return nil
}

// FinishAgentAction closes an action. agentID scopes the update as defence
// in depth: an action id names one agent's action, and a result is
// attributed to an agent from its subject, so a result from one agent must
// never close another's action. Pass "" only from server-internal callers
// that are not acting on an agent-reported id.
func (s *Store) FinishAgentAction(ctx context.Context, agentID, id, status, detail string) error {
	const q = `UPDATE agent_actions SET status = $2, detail = $3, finished_at = now()
WHERE id = $1 AND ($4 = '' OR agent_id = $4)`
	if _, err := s.pool.Exec(ctx, q, id, status, detail, agentID); err != nil {
		return fmt.Errorf("finish agent action: %w", err)
	}
	return nil
}

// VerifyPendingRestart closes an action left at "pending restart" with the
// agent's check after the restart, adding that check to its transcript.
// It reports false, changing nothing, when the action has moved on since
// (cancelled, or already closed by an earlier report).
func (s *Store) VerifyPendingRestart(ctx context.Context, agentID, id, status, note string) (bool, error) {
	const q = `UPDATE agent_actions SET status = $3, detail = $4 || E'\n\n' || detail, finished_at = now()
WHERE id = $1 AND agent_id = $2 AND status = 'pending_restart'`
	tag, err := s.pool.Exec(ctx, q, id, agentID, status, note)
	if err != nil {
		return false, fmt.Errorf("verify pending restart: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) ListAgentActions(ctx context.Context, agentID string, limit int) ([]AgentAction, error) {
	const q = `
SELECT id, coalesce(run_id, ''), agent_id, kind, summary, status, detail, requested_by, started_at, finished_at
FROM agent_actions WHERE agent_id = $1 ORDER BY started_at DESC LIMIT $2`
	rows, err := s.pool.Query(ctx, q, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("list agent actions: %w", err)
	}
	defer rows.Close()
	var out []AgentAction
	for rows.Next() {
		var a AgentAction
		if err := rows.Scan(&a.ID, &a.RunID, &a.AgentID, &a.Kind, &a.Summary, &a.Status, &a.Detail,
			&a.RequestedBy, &a.StartedAt, &a.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan agent action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ActionsForRun returns the per-device rows belonging to one deployment,
// joined with hostnames so a detail view doesn't need a second lookup.
func (s *Store) ActionsForRun(ctx context.Context, runID string) ([]AgentActionWithHost, error) {
	const q = `
SELECT act.id, coalesce(act.run_id, ''), act.agent_id, a.hostname, act.kind, act.summary,
       act.status, act.detail, act.requested_by, act.started_at, act.finished_at
FROM agent_actions act
JOIN agents a ON a.agent_id = act.agent_id
WHERE act.run_id = $1 ORDER BY a.hostname`
	rows, err := s.pool.Query(ctx, q, runID)
	if err != nil {
		return nil, fmt.Errorf("actions for run: %w", err)
	}
	defer rows.Close()
	var out []AgentActionWithHost
	for rows.Next() {
		var a AgentActionWithHost
		if err := rows.Scan(&a.ID, &a.RunID, &a.AgentID, &a.Hostname, &a.Kind, &a.Summary,
			&a.Status, &a.Detail, &a.RequestedBy, &a.StartedAt, &a.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan run action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AgentActionWithHost is an action carrying its device's hostname.
type AgentActionWithHost struct {
	AgentAction
	Hostname string `json:"hostname"`
}

// RunOutcomeCounts summarises a deployment's per-device results.
func (s *Store) RunOutcomeCounts(ctx context.Context, runIDs []string) (map[string]map[string]int, error) {
	out := map[string]map[string]int{}
	if len(runIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT run_id, status, count(*) FROM agent_actions
WHERE run_id = ANY($1) GROUP BY run_id, status`, runIDs)
	if err != nil {
		return nil, fmt.Errorf("run outcome counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var runID, status string
		var n int
		if err := rows.Scan(&runID, &status, &n); err != nil {
			return nil, fmt.Errorf("scan run outcome: %w", err)
		}
		if out[runID] == nil {
			out[runID] = map[string]int{}
		}
		out[runID][status] = n
	}
	return out, rows.Err()
}

// GetAgentAction reads one action's current state. Used by the playbook
// engine, which dispatches an asynchronous job (a patch apply acknowledges
// immediately and reports its real outcome minutes later) and then has to
// wait for the answer before deciding whether the next step still applies.
func (s *Store) GetAgentAction(ctx context.Context, id string) (*AgentAction, error) {
	var a AgentAction
	err := s.pool.QueryRow(ctx, `
SELECT id, coalesce(run_id,''), agent_id, kind, summary, status, detail, requested_by, started_at, finished_at
FROM agent_actions WHERE id = $1`, id).
		Scan(&a.ID, &a.RunID, &a.AgentID, &a.Kind, &a.Summary, &a.Status, &a.Detail,
			&a.RequestedBy, &a.StartedAt, &a.FinishedAt)
	if err != nil {
		return nil, fmt.Errorf("get agent action: %w", err)
	}
	return &a, nil
}

// RunActionKinds returns, per run, the kinds of work it dispatched: the
// agent action kinds, plus "deploy_job" for a run that queued catalog
// deploy jobs. A job held for a maintenance window has no agent action
// yet, so the jobs are what say a run like that is software.
func (s *Store) RunActionKinds(ctx context.Context, runIDs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(runIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT DISTINCT run_id, kind FROM agent_actions WHERE run_id = ANY($1)
UNION
SELECT DISTINCT run_id, 'deploy_job' FROM deploy_jobs WHERE run_id = ANY($1)`, runIDs)
	if err != nil {
		return nil, fmt.Errorf("run action kinds: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var runID, kind string
		if err := rows.Scan(&runID, &kind); err != nil {
			return nil, fmt.Errorf("scan run action kind: %w", err)
		}
		out[runID] = append(out[runID], kind)
	}
	return out, rows.Err()
}
