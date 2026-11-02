package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ContentSet is a named collection of content ids by kind. A role holding
// no content set may use everything, so adding the feature takes nothing
// away from a console that was working yesterday.
type ContentSet struct {
	ID          string              `json:"id"`
	Name        string              `json:"name" api:"required"`
	Description string              `json:"description"`
	Contents    map[string][]string `json:"contents"`
	CreatedBy   string              `json:"created_by" api:"readonly"`
	CreatedAt   time.Time           `json:"created_at" api:"readonly"`
	UpdatedAt   time.Time           `json:"updated_at" api:"readonly"`
}

func scanContentSet(row interface{ Scan(...any) error }) (ContentSet, error) {
	var c ContentSet
	var raw []byte
	if err := row.Scan(&c.ID, &c.Name, &c.Description, &raw, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	c.Contents = map[string][]string{}
	_ = json.Unmarshal(raw, &c.Contents)
	return c, nil
}

const contentSetColumns = `id, name, description, contents, created_by, created_at, updated_at`

func (s *Store) ListContentSets(ctx context.Context) ([]ContentSet, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+contentSetColumns+` FROM content_sets ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list content sets: %w", err)
	}
	defer rows.Close()
	out := []ContentSet{}
	for rows.Next() {
		c, err := scanContentSet(rows)
		if err != nil {
			return nil, fmt.Errorf("scan content set: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetContentSet(ctx context.Context, id string) (*ContentSet, error) {
	c, err := scanContentSet(s.pool.QueryRow(ctx, `SELECT `+contentSetColumns+` FROM content_sets WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get content set: %w", err)
	}
	return &c, nil
}

func (s *Store) UpsertContentSet(ctx context.Context, c ContentSet) error {
	raw, _ := json.Marshal(c.Contents)
	_, err := s.pool.Exec(ctx, `INSERT INTO content_sets (id, name, description, contents, created_by, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, contents=EXCLUDED.contents, updated_at=now()`,
		c.ID, c.Name, c.Description, raw, c.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert content set: %w", err)
	}
	return nil
}

func (s *Store) DeleteContentSet(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM content_sets WHERE id = $1`, id)
	return err
}

// ActionGroup is a module's ceiling: the computer groups whose endpoints
// may receive actions from that module, whoever is asking. Disabled or
// absent means the whole fleet.
type ActionGroup struct {
	Module    string    `json:"module" api:"required"`
	GroupIDs  []string  `json:"group_ids"`
	Enabled   bool      `json:"enabled"`
	UpdatedBy string    `json:"updated_by" api:"readonly"`
	UpdatedAt time.Time `json:"updated_at" api:"readonly"`
}

func (s *Store) ListActionGroups(ctx context.Context) ([]ActionGroup, error) {
	rows, err := s.pool.Query(ctx, `SELECT module, group_ids, enabled, updated_by, updated_at FROM action_groups ORDER BY module`)
	if err != nil {
		return nil, fmt.Errorf("list action groups: %w", err)
	}
	defer rows.Close()
	out := []ActionGroup{}
	for rows.Next() {
		var a ActionGroup
		if err := rows.Scan(&a.Module, &a.GroupIDs, &a.Enabled, &a.UpdatedBy, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan action group: %w", err)
		}
		if a.GroupIDs == nil {
			a.GroupIDs = []string{}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpsertActionGroup saves a module's ceiling and answers it as stored,
// with the time the database stamped.
func (s *Store) UpsertActionGroup(ctx context.Context, a ActionGroup) (ActionGroup, error) {
	if a.GroupIDs == nil {
		a.GroupIDs = []string{}
	}
	err := s.pool.QueryRow(ctx, `INSERT INTO action_groups (module, group_ids, enabled, updated_by, updated_at) VALUES ($1,$2,$3,$4,now())
		ON CONFLICT (module) DO UPDATE SET group_ids=EXCLUDED.group_ids, enabled=EXCLUDED.enabled, updated_by=EXCLUDED.updated_by, updated_at=now()
		RETURNING updated_at`,
		a.Module, a.GroupIDs, a.Enabled, a.UpdatedBy).Scan(&a.UpdatedAt)
	if err != nil {
		return ActionGroup{}, fmt.Errorf("upsert action group: %w", err)
	}
	return a, nil
}

func (s *Store) DeleteActionGroup(ctx context.Context, module string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM action_groups WHERE module = $1`, module)
	return err
}

// ApprovalPolicy says which operations wait for somebody else.
type ApprovalPolicy struct {
	ID         string    `json:"id"`
	Name       string    `json:"name" api:"required"`
	Module     string    `json:"module" api:"required"`
	GroupIDs   []string  `json:"group_ids"`
	MinDevices int       `json:"min_devices"`
	Enabled    bool      `json:"enabled"`
	CreatedBy  string    `json:"created_by" api:"readonly"`
	CreatedAt  time.Time `json:"created_at" api:"readonly"`
	UpdatedAt  time.Time `json:"updated_at" api:"readonly"`
}

const approvalPolicyColumns = `id, name, module, group_ids, min_devices, enabled, created_by, created_at, updated_at`

func (s *Store) ListApprovalPolicies(ctx context.Context) ([]ApprovalPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+approvalPolicyColumns+` FROM approval_policies ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list approval policies: %w", err)
	}
	defer rows.Close()
	out := []ApprovalPolicy{}
	for rows.Next() {
		var p ApprovalPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Module, &p.GroupIDs, &p.MinDevices, &p.Enabled, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan approval policy: %w", err)
		}
		if p.GroupIDs == nil {
			p.GroupIDs = []string{}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetApprovalPolicy(ctx context.Context, id string) (*ApprovalPolicy, error) {
	list, err := s.ListApprovalPolicies(ctx)
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

func (s *Store) UpsertApprovalPolicy(ctx context.Context, p ApprovalPolicy) error {
	if p.GroupIDs == nil {
		p.GroupIDs = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO approval_policies (`+approvalPolicyColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,now(),now())
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, module=EXCLUDED.module, group_ids=EXCLUDED.group_ids,
		min_devices=EXCLUDED.min_devices, enabled=EXCLUDED.enabled, updated_at=now()`,
		p.ID, p.Name, p.Module, p.GroupIDs, p.MinDevices, p.Enabled, p.CreatedBy)
	if err != nil {
		return fmt.Errorf("upsert approval policy: %w", err)
	}
	return nil
}

func (s *Store) DeleteApprovalPolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM approval_policies WHERE id = $1`, id)
	return err
}

// ApprovalRequest is one operation parked for a decision. It carries the
// request verbatim so approving replays what was actually asked for.
type ApprovalRequest struct {
	ID           string     `json:"id"`
	PolicyID     string     `json:"policy_id"`
	PolicyName   string     `json:"policy_name"`
	Module       string     `json:"module"`
	Summary      string     `json:"summary"`
	Method       string     `json:"method"`
	Path         string     `json:"path"`
	Body         []byte     `json:"-"`
	AgentIDs     []string   `json:"agent_ids"`
	DeviceCount  int        `json:"device_count"`
	RequestedBy  string     `json:"requested_by"`
	RequestedAt  time.Time  `json:"requested_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	State        string     `json:"state"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`
	Outcome      string     `json:"outcome,omitempty"`
}

const approvalRequestColumns = `id, policy_id, policy_name, module, summary, method, path, body, agent_ids, device_count,
	requested_by, requested_at, expires_at, state, decided_by, decided_at, decision_note, outcome`

func scanApprovalRequest(row interface{ Scan(...any) error }) (ApprovalRequest, error) {
	var a ApprovalRequest
	err := row.Scan(&a.ID, &a.PolicyID, &a.PolicyName, &a.Module, &a.Summary, &a.Method, &a.Path, &a.Body, &a.AgentIDs, &a.DeviceCount,
		&a.RequestedBy, &a.RequestedAt, &a.ExpiresAt, &a.State, &a.DecidedBy, &a.DecidedAt, &a.DecisionNote, &a.Outcome)
	if a.AgentIDs == nil {
		a.AgentIDs = []string{}
	}
	return a, err
}

func (s *Store) CreateApprovalRequest(ctx context.Context, a ApprovalRequest) error {
	if a.AgentIDs == nil {
		a.AgentIDs = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO approval_requests (id, policy_id, policy_name, module, summary, method, path, body,
		agent_ids, device_count, requested_by, requested_at, expires_at, state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now(),$12,'pending')`,
		a.ID, a.PolicyID, a.PolicyName, a.Module, a.Summary, a.Method, a.Path, a.Body, a.AgentIDs, a.DeviceCount, a.RequestedBy, a.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create approval request: %w", err)
	}
	return nil
}

func (s *Store) ListApprovalRequests(ctx context.Context, state string, limit int) ([]ApprovalRequest, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+approvalRequestColumns+` FROM approval_requests
		WHERE ($1 = '' OR state = $1) ORDER BY requested_at DESC LIMIT $2`, state, limit)
	if err != nil {
		return nil, fmt.Errorf("list approval requests: %w", err)
	}
	defer rows.Close()
	out := []ApprovalRequest{}
	for rows.Next() {
		a, err := scanApprovalRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("scan approval request: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetApprovalRequest(ctx context.Context, id string) (*ApprovalRequest, error) {
	a, err := scanApprovalRequest(s.pool.QueryRow(ctx, `SELECT `+approvalRequestColumns+` FROM approval_requests WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get approval request: %w", err)
	}
	return &a, nil
}

// DecideApprovalRequest moves a request out of pending, but only from
// pending: two approvers clicking at once must not both replay the
// operation, so the state change is the lock.
func (s *Store) DecideApprovalRequest(ctx context.Context, id, state, who, note string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE approval_requests SET state = $2, decided_by = $3, decided_at = now(), decision_note = $4
		WHERE id = $1 AND state = 'pending'`, id, state, who, note)
	if err != nil {
		return false, fmt.Errorf("decide approval request: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) SetApprovalOutcome(ctx context.Context, id, state, outcome string) error {
	_, err := s.pool.Exec(ctx, `UPDATE approval_requests SET state = $2, outcome = $3 WHERE id = $1`, id, state, outcome)
	return err
}

// ExpirePendingApprovals marks requests nobody decided in time. An
// approval that sat for a day is not an approval any more: the fleet it
// described has moved on.
func (s *Store) ExpirePendingApprovals(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE approval_requests SET state = 'expired'
		WHERE state = 'pending' AND expires_at IS NOT NULL AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("expire approvals: %w", err)
	}
	return tag.RowsAffected(), nil
}
