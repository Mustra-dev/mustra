package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	bgroups "github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Access control beyond permissions.
//
// A permission answers "may this person deploy software". These answer
// three more questions that a fleet tool needs and a permission key
// cannot express:
//
//   management rights   which endpoints may *this person* act on
//   action groups       which endpoints may *this module* act on at all,
//                       whoever is asking — the ceiling that keeps Deploy
//                       away from the domain controllers even for an admin
//   approvals           which operations wait for somebody else first
//
// The three compose in that order, and all three default to "everything",
// so a console that never configures them behaves exactly as before.

// Modules that can be scoped and gated. Keys are stable: they appear in
// action_groups.module and approval_policies.module.
var accessModules = []string{"deploy", "patches", "playbooks", "shell", "enforce", "reveal"}

func validModule(m string) bool {
	for _, v := range accessModules {
		if v == m {
			return true
		}
	}
	return false
}

// --- group membership cache -----------------------------------------------

// Resolving a computer group means matching every device against its
// rules, so the answer is cached briefly: a dispatch to two hundred
// endpoints asks the same question once per endpoint otherwise.
type accessCache struct {
	mu       sync.Mutex
	at       time.Time
	members  map[string]map[string]bool // group id -> agent ids
	actionGs []store.ActionGroup
}

func (s *Server) invalidateAccess() {
	s.access.mu.Lock()
	s.access.at = time.Time{}
	s.access.members = nil
	s.access.actionGs = nil
	s.access.mu.Unlock()
}

func (s *Server) accessSnapshot(ctx context.Context) (map[string]map[string]bool, []store.ActionGroup, error) {
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	if time.Since(s.access.at) < 30*time.Second && s.access.members != nil {
		return s.access.members, s.access.actionGs, nil
	}
	groups, err := s.store.ListComputerGroups(ctx)
	if err != nil {
		return nil, nil, err
	}
	// Loading the devices decodes every endpoint's cached sensor data,
	// which only rule matching needs. Every endpoint action asks for this
	// snapshot — an install with no dynamic group paid that decode (60% of
	// a 2,000-endpoint deployment's dispatch time) for nothing.
	var devices []bgroups.Device
	if anyDynamicGroup(groups) {
		if devices, _, err = s.devicesForMatching(ctx); err != nil {
			return nil, nil, err
		}
	}
	members := map[string]map[string]bool{}
	for _, g := range groups {
		m := map[string]bool{}
		// Same rule as agentsInGroups: a static group is its member list,
		// a dynamic one is whatever matches right now.
		if g.Kind == "static" {
			for _, id := range g.MemberIDs {
				m[id] = true
			}
		} else {
			for _, d := range devices {
				if bgroups.Matches(d, g.Rules, g.MatchMode != "any") {
					m[d.AgentID] = true
				}
			}
		}
		members[g.ID] = m
	}
	ags, err := s.store.ListActionGroups(ctx)
	if err != nil {
		return nil, nil, err
	}
	s.access.members, s.access.actionGs, s.access.at = members, ags, time.Now()
	return members, ags, nil
}

// anyDynamicGroup reports whether resolving groups needs the devices: only
// a group that is not static is decided by matching rules against them.
func anyDynamicGroup(groups []store.ComputerGroup) bool {
	for _, g := range groups {
		if g.Kind != "static" {
			return true
		}
	}
	return false
}

// agentSet unions the membership of several groups.
func agentSet(members map[string]map[string]bool, groupIDs []string) map[string]bool {
	out := map[string]bool{}
	for _, id := range groupIDs {
		for a := range members[id] {
			out[a] = true
		}
	}
	return out
}

// --- management rights -----------------------------------------------------

// accessPrincipal is whose management rights and content sets apply to a
// request: the signed-in user, or — for an API token — the user who
// created it. A token is never wider than its creator.
func accessPrincipal(ctx context.Context) (userID string, isAdmin bool, ok bool) {
	if t, isToken := auth.Token(ctx); isToken {
		return t.CreatorID, t.CreatorAdmin, t.CreatorID != ""
	}
	if _, isToken := auth.TokenPermissions(ctx); isToken {
		// A token context without an identity is not one RequireAuth
		// produced; give it nothing.
		return "", false, false
	}
	u := auth.CurrentUser(ctx)
	if u == nil {
		return "", false, false
	}
	return u.ID, u.IsAdmin, true
}

// noEndpoints is the scope of a caller who may act on nothing.
var noEndpoints = map[string]bool{}

// endpointScope returns the agent ids the caller may act on, or nil when
// they are unrestricted. An API token carries its creator's management
// rights.
func (s *Server) endpointScope(ctx context.Context) (map[string]bool, error) {
	if auth.CurrentUser(ctx) == nil {
		return noEndpoints, nil
	}
	principal, isAdmin, ok := accessPrincipal(ctx)
	if !ok {
		return noEndpoints, nil
	}
	if isAdmin {
		return nil, nil
	}
	groupIDs, unrestricted, err := s.store.ManagementGroupsForUser(ctx, principal)
	if err != nil {
		return nil, err
	}
	if unrestricted {
		return nil, nil
	}
	members, _, err := s.accessSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return agentSet(members, groupIDs), nil
}

// actionCeiling returns the agent ids a module may act on at all, or nil
// when it has no action group. This is not about who is asking: an admin
// is subject to it too, which is the whole point of having it.
func (s *Server) actionCeiling(ctx context.Context, module string) (map[string]bool, error) {
	members, ags, err := s.accessSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range ags {
		if a.Module != module || !a.Enabled || len(a.GroupIDs) == 0 {
			continue
		}
		return agentSet(members, a.GroupIDs), nil
	}
	return nil, nil
}

// checkTargets refuses the operation unless every named endpoint is inside
// both the caller's management rights and the module's action group. It
// refuses rather than silently narrowing: an operator who asked to act on
// forty endpoints and was quietly given thirty has been told something
// untrue about their own fleet.
//
// Returns false and writes the response when the caller must stop.
func (s *Server) checkTargets(w http.ResponseWriter, r *http.Request, module string, agentIDs []string) bool {
	scope, err := s.endpointScope(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	ceiling, err := s.actionCeiling(r.Context(), module)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if scope == nil && ceiling == nil {
		return true
	}
	var outsideScope, outsideCeiling []string
	for _, id := range agentIDs {
		if scope != nil && !scope[id] {
			outsideScope = append(outsideScope, id)
		}
		if ceiling != nil && !ceiling[id] {
			outsideCeiling = append(outsideCeiling, id)
		}
	}
	if len(outsideScope) > 0 {
		s.audit(r.Context(), auditEvent{Action: module + ".denied", Actor: auth.CurrentUser(r.Context()).Username,
			Target: fmt.Sprintf("%d endpoint(s) outside management rights", len(outsideScope)), Outcome: "denied", Severity: "warning"})
		http.Error(w, fmt.Sprintf("%d of those endpoints are outside your management rights (%s)", len(outsideScope), s.hostnamesFor(r.Context(), outsideScope)), http.StatusForbidden)
		return false
	}
	if len(outsideCeiling) > 0 {
		s.audit(r.Context(), auditEvent{Action: module + ".denied", Actor: auth.CurrentUser(r.Context()).Username,
			Target: fmt.Sprintf("%d endpoint(s) outside the %s action group", len(outsideCeiling), module), Outcome: "denied", Severity: "warning"})
		http.Error(w, fmt.Sprintf("%d of those endpoints are outside the %s action group (%s)", len(outsideCeiling), module, s.hostnamesFor(r.Context(), outsideCeiling)), http.StatusForbidden)
		return false
	}
	return true
}

// narrowTargets is checkTargets for a fleet-wide operation, where there is
// no explicit list to refuse: what falls outside the scope is dropped, and
// the caller is told how many. Used where "every eligible endpoint" is the
// target rather than a selection.
func (s *Server) narrowTargets(ctx context.Context, module string, agentIDs []string) (kept []string, dropped int, err error) {
	scope, err := s.endpointScope(ctx)
	if err != nil {
		return nil, 0, err
	}
	ceiling, err := s.actionCeiling(ctx, module)
	if err != nil {
		return nil, 0, err
	}
	if scope == nil && ceiling == nil {
		return agentIDs, 0, nil
	}
	for _, id := range agentIDs {
		if scope != nil && !scope[id] {
			dropped++
			continue
		}
		if ceiling != nil && !ceiling[id] {
			dropped++
			continue
		}
		kept = append(kept, id)
	}
	return kept, dropped, nil
}

func (s *Server) hostnamesFor(ctx context.Context, agentIDs []string) string {
	if s.store == nil {
		return ""
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return ""
	}
	byID := map[string]string{}
	for _, a := range agents {
		byID[a.AgentID] = a.Hostname
	}
	var names []string
	for _, id := range agentIDs {
		if n := byID[id]; n != "" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(" and %d more", len(names)-5)
	}
	return strings.Join(names, ", ")
}

// --- content sets ----------------------------------------------------------

// contentAllowed says whether the caller's roles let them use one piece of
// content. A caller whose roles hold no content set may use everything.
func (s *Server) contentAllowed(ctx context.Context, kind, id string) (bool, error) {
	if auth.CurrentUser(ctx) == nil {
		return false, nil
	}
	principal, isAdmin, ok := accessPrincipal(ctx)
	if !ok {
		return false, nil
	}
	if isAdmin {
		return true, nil
	}
	setIDs, unrestricted, err := s.store.ContentSetIDsForUser(ctx, principal)
	if err != nil || unrestricted {
		return true, err
	}
	for _, sid := range setIDs {
		cs, err := s.store.GetContentSet(ctx, sid)
		if err != nil || cs == nil {
			continue
		}
		for _, allowed := range cs.Contents[kind] {
			if allowed == id {
				return true, nil
			}
		}
	}
	return false, nil
}

// contentFilter answers contentAllowed for many ids of one kind with one
// read of the caller's content sets: the function it returns says whether
// an id may be used. Unrestricted callers get a function that says yes.
func (s *Server) contentFilter(ctx context.Context, kind string) (func(id string) bool, error) {
	yes := func(string) bool { return true }
	no := func(string) bool { return false }
	if auth.CurrentUser(ctx) == nil {
		return no, nil
	}
	principal, isAdmin, ok := accessPrincipal(ctx)
	if !ok {
		return no, nil
	}
	if isAdmin {
		return yes, nil
	}
	setIDs, unrestricted, err := s.store.ContentSetIDsForUser(ctx, principal)
	if err != nil {
		return no, err
	}
	if unrestricted {
		return yes, nil
	}
	allowed := map[string]bool{}
	for _, sid := range setIDs {
		cs, err := s.store.GetContentSet(ctx, sid)
		if err != nil || cs == nil {
			continue
		}
		for _, id := range cs.Contents[kind] {
			allowed[id] = true
		}
	}
	return func(id string) bool { return allowed[id] }, nil
}

// sensorFilter is contentFilter for sensors, with one difference: a
// caller is restricted only when one of their content sets lists sensors.
// Sets that name only packages, dashboards or questions leave sensors
// open, so the roles that predate sensor enforcement keep reading
// inventory; a set that lists sensors means exactly those.
func (s *Server) sensorFilter(ctx context.Context) (func(kind string) bool, error) {
	yes := func(string) bool { return true }
	no := func(string) bool { return false }
	if auth.CurrentUser(ctx) == nil {
		return no, nil
	}
	principal, isAdmin, ok := accessPrincipal(ctx)
	if !ok {
		return no, nil
	}
	if isAdmin {
		return yes, nil
	}
	setIDs, unrestricted, err := s.store.ContentSetIDsForUser(ctx, principal)
	if err != nil {
		return no, err
	}
	if unrestricted {
		return yes, nil
	}
	allowed, listed := map[string]bool{}, false
	for _, sid := range setIDs {
		cs, err := s.store.GetContentSet(ctx, sid)
		if err != nil || cs == nil {
			continue
		}
		for _, kind := range cs.Contents["sensors"] {
			allowed[kind], listed = true, true
		}
	}
	if !listed {
		return yes, nil
	}
	return func(kind string) bool { return kind == "" || allowed[kind] }, nil
}

// sensorOfField is the sensor a query field reads: the part before the
// dot ("installed_apps.name" reads installed_apps). Top-level fields
// (hostname, os, ip, online…) are the endpoint's own identity, which
// every query needs to say whose answer it is, and belong to no sensor.
func sensorOfField(field string) string {
	f, _, _ := splitGetFilter(field)
	kind, _, ok := strings.Cut(f, ".")
	if !ok {
		return ""
	}
	return kind
}

// errSensorNotGranted names the first sensor a request reads that the
// caller's content sets do not grant.
type errSensorNotGranted struct{ kind string }

func (e errSensorNotGranted) Error() string {
	return "the " + e.kind + " sensor is not in a content set your roles grant"
}

// checkSensorFields refuses a question or group rule that reads a sensor
// outside the caller's content sets: what it gets, and what it filters on,
// since a filter on a sensor answers questions about it just as well.
func (s *Server) checkSensorFields(ctx context.Context, get []string, rules []bgroups.Rule) error {
	allowed, err := s.sensorFilter(ctx)
	if err != nil {
		return err
	}
	fields := append([]string(nil), get...)
	var walk func([]bgroups.Rule)
	walk = func(rs []bgroups.Rule) {
		for _, r := range rs {
			if r.Op == "same_row" {
				var children []bgroups.Rule
				_ = json.Unmarshal([]byte(r.Value), &children)
				walk(children)
				continue
			}
			fields = append(fields, r.Field)
		}
	}
	leaves, err := bgroups.ExpandGroups(rules)
	if err != nil {
		return err
	}
	walk(leaves)
	for _, f := range fields {
		if kind := sensorOfField(f); !allowed(kind) {
			return errSensorNotGranted{kind}
		}
	}
	return nil
}

// requireSensor writes a 403 and returns false when kind is out of the
// caller's content sets.
func (s *Server) requireSensor(w http.ResponseWriter, r *http.Request, kind string) bool {
	allowed, err := s.sensorFilter(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if !allowed(kind) {
		http.Error(w, errSensorNotGranted{kind}.Error(), http.StatusForbidden)
		return false
	}
	return true
}

// writeSensorFieldsError answers a checkSensorFields failure: 403 for a
// sensor not granted, 400 for a malformed rule, 500 otherwise.
func writeSensorFieldsError(w http.ResponseWriter, err error) {
	var denied errSensorNotGranted
	switch {
	case errors.As(err, &denied):
		http.Error(w, err.Error(), http.StatusForbidden)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// requireContent writes a 403 and returns false when the content is out of
// the caller's content sets.
func (s *Server) requireContent(w http.ResponseWriter, r *http.Request, kind, id, name string) bool {
	ok, err := s.contentAllowed(r.Context(), kind, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if !ok {
		http.Error(w, name+" is not in a content set your roles grant", http.StatusForbidden)
		return false
	}
	return true
}

// --- approvals -------------------------------------------------------------

// approvalWindow is how long a parked operation stays decidable. An
// approval that sat overnight is not an approval of today's fleet.
const approvalWindow = 8 * time.Hour

// approvedCtxKey marks a request that is being replayed after a decision,
// so the gate lets it through instead of parking it a second time.
type approvedCtxKey struct{}

func withApproval(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, approvedCtxKey{}, id)
}

func approvalGranted(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(approvedCtxKey{}).(string)
	return id, ok
}

// parkedRequest is an operation held for a decision, stored whole so that
// approving it runs what was actually asked for rather than something
// rebuilt from a summary.
type parkedRequest struct {
	Handler    string            `json:"handler"`
	Body       json.RawMessage   `json:"body"`
	PathValues map[string]string `json:"path_values,omitempty"`
}

// replayable is the set of operations an approval can run. A handler has
// to be registered here to be gateable: an operation nobody can replay
// must not be parked, because parking it would silently drop it.
func (s *Server) replayable() map[string]http.HandlerFunc {
	// Each behind the permission its route demands (httpapi.go): the
	// requester may have lost it while the request waited, and the approver
	// needs only approvals.decide.
	perm := func(p string, h http.HandlerFunc) http.HandlerFunc {
		return s.auth.RequirePermission(p)(h).ServeHTTP
	}
	m := map[string]http.HandlerFunc{
		"software.deploy": perm(auth.PermDeployManage, s.handleDeploySoftware),
		"patches.deploy":  perm(auth.PermPatchesManage, s.handleDeployPatchesBulk),
		"playbooks.run":   perm(auth.PermDeployManage, s.handleRunPlaybook),
		"deploy.run":      perm(auth.PermDeployManage, s.handleDeployRun),
	}
	// Every gated route is replayable through its permission check and its
	// gate, so the access checks run again — as the requester — when an
	// approval is decided.
	for key, g := range s.gatedRoutes {
		m[key] = g.replay
	}
	return m
}

// matchApprovalPolicy finds the first enabled policy that covers this
// operation, or nil when none does.
func (s *Server) matchApprovalPolicy(ctx context.Context, module string, agentIDs []string) (*store.ApprovalPolicy, error) {
	policies, err := s.store.ListApprovalPolicies(ctx)
	if err != nil {
		return nil, err
	}
	var members map[string]map[string]bool
	for i := range policies {
		p := policies[i]
		if !p.Enabled || p.Module != module {
			continue
		}
		if p.MinDevices > 0 && len(agentIDs) < p.MinDevices {
			continue
		}
		if len(p.GroupIDs) > 0 {
			if members == nil {
				members, _, err = s.accessSnapshot(ctx)
				if err != nil {
					return nil, err
				}
			}
			if !policyTouches(agentIDs, agentSet(members, p.GroupIDs)) {
				continue
			}
		}
		return &p, nil
	}
	return nil, nil
}

// requireApproval parks the operation when a policy covers it. It returns
// true when the caller must stop — the response has been written and the
// work will happen later, if somebody approves it.
//
// The caller passes the decoded request back as body, which is what gets
// replayed. Anything the handler derived before calling this (targets,
// applicability) is recomputed at replay time on purpose: approving a
// deployment approves the operation, and the fleet it lands on is the
// fleet that exists when it runs.
func (s *Server) requireApproval(w http.ResponseWriter, r *http.Request, module, handler, summary string, agentIDs []string, body any) bool {
	if _, replaying := approvalGranted(r.Context()); replaying {
		return false
	}
	policy, err := s.matchApprovalPolicy(r.Context(), module, agentIDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	if policy == nil {
		return false
	}
	// A token cannot wait for somebody to decide, and running anyway is
	// exactly what the policy exists to prevent. Only a token an
	// administrator explicitly marked approval-exempt goes through.
	if tok, isToken := auth.Token(r.Context()); isToken || auth.CurrentUser(r.Context()).ID == auth.APITokenUserID {
		if tok != nil && tok.ApprovalExempt {
			s.audit(r.Context(), auditEvent{Action: module + ".approval_bypassed", Actor: auth.CurrentUser(r.Context()).Username,
				Target: summary, Severity: "warning", Detail: map[string]any{"policy": policy.Name, "token": tok.ID}})
			return false
		}
		s.audit(r.Context(), auditEvent{Action: module + ".denied", Actor: auth.CurrentUser(r.Context()).Username,
			Target: summary, Outcome: "denied", Severity: "warning", Detail: map[string]any{"policy": policy.Name, "reason": "api token, approval required"}})
		http.Error(w, "the approval policy \""+policy.Name+"\" covers this operation and API tokens cannot wait for approval; run it from the console or use an approval-exempt token", http.StatusForbidden)
		return true
	}
	if _, ok := s.replayable()[handler]; !ok {
		// Fail closed: an operation nobody can replay must not be parked
		// (it would be dropped) and must not run unapproved either.
		s.logger.Error("approval policy matched an operation that cannot be replayed; refusing it",
			"module", module, "handler", handler, "policy", policy.Name)
		http.Error(w, "the approval policy \""+policy.Name+"\" covers this operation, which cannot be parked for approval", http.StatusForbidden)
		return true
	}
	raw, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	pv := map[string]string{}
	for _, k := range []string{"id", "key", "agent"} {
		if v := r.PathValue(k); v != "" {
			pv[k] = v
		}
	}
	parked, _ := json.Marshal(parkedRequest{Handler: handler, Body: raw, PathValues: pv})
	u := auth.CurrentUser(r.Context())
	expires := time.Now().Add(approvalWindow)
	req := store.ApprovalRequest{
		ID: idgen.New("apr-"), PolicyID: policy.ID, PolicyName: policy.Name, Module: module,
		Summary: summary, Method: r.Method, Path: r.URL.Path, Body: parked,
		AgentIDs: agentIDs, DeviceCount: len(agentIDs), RequestedBy: u.Username, ExpiresAt: &expires,
	}
	if err := s.store.CreateApprovalRequest(r.Context(), req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	s.audit(r.Context(), auditEvent{Action: module + ".approval_requested", Actor: u.Username, Target: summary,
		Severity: "notice", Detail: map[string]any{"request_id": req.ID, "policy": policy.Name, "devices": len(agentIDs)}})
	s.notifyRequest(r.Context(), "notice", "Approvals", u.Username+" is asking for approval: "+summary,
		fmt.Sprintf("%s · %d endpoint(s) · policy %s", module, len(agentIDs), policy.Name), "/access#approvals", "approval", req.ID, true)
	w.WriteHeader(http.StatusAccepted)
	writeJSONResponse(w, map[string]any{
		"approval_required": true, "request_id": req.ID, "policy": policy.Name,
		"summary": summary, "devices": len(agentIDs), "expires_at": expires,
		"message": "Parked for approval: " + policy.Name + ". It runs once somebody with approvals.decide approves it.",
	})
	return true
}

// runApproved replays a decided request under the identity of whoever
// asked for it, and records what happened.
func (s *Server) runApproved(ctx context.Context, req store.ApprovalRequest) {
	var parked parkedRequest
	if err := json.Unmarshal(req.Body, &parked); err != nil {
		_ = s.store.SetApprovalOutcome(ctx, req.ID, "failed", "stored request is unreadable: "+err.Error())
		return
	}
	h, ok := s.replayable()[parked.Handler]
	if !ok {
		_ = s.store.SetApprovalOutcome(ctx, req.ID, "failed", "no handler for "+parked.Handler)
		return
	}
	requester, err := s.store.GetUserByUsername(ctx, req.RequestedBy)
	if err != nil || requester == nil {
		_ = s.store.SetApprovalOutcome(ctx, req.ID, "failed", "the requester no longer exists")
		return
	}
	// A disabled account's authority lapses, as it does for its API tokens
	// and its stored work (endpointActionPrincipal): approval does not
	// revive it.
	if !requester.Active {
		_ = s.store.SetApprovalOutcome(ctx, req.ID, "failed", "the requester's account is disabled")
		return
	}
	hr, err := http.NewRequest(req.Method, req.Path, strings.NewReader(string(parked.Body)))
	if err != nil {
		_ = s.store.SetApprovalOutcome(ctx, req.ID, "failed", err.Error())
		return
	}
	hr.Header.Set("Content-Type", "application/json")
	for k, v := range parked.PathValues {
		hr.SetPathValue(k, v)
	}
	hr = hr.WithContext(withApproval(auth.WithUser(ctx, requester), req.ID))
	rec := &captureWriter{header: http.Header{}}
	h(rec, hr)
	outcome := strings.TrimSpace(rec.body.String())
	if len(outcome) > 800 {
		outcome = outcome[:800]
	}
	state := "approved"
	if rec.status >= 400 {
		state = "failed"
		outcome = fmt.Sprintf("HTTP %d: %s", rec.status, outcome)
	}
	if err := s.store.SetApprovalOutcome(ctx, req.ID, state, outcome); err != nil {
		s.logger.Warn("recording approval outcome failed", "request", req.ID, "error", err)
	}
	s.logger.Info("approved operation replayed", "request", req.ID, "module", req.Module,
		"requested_by", req.RequestedBy, "state", state)
}

// captureWriter collects a replayed handler's response so the outcome can
// be shown next to the decision instead of vanishing.
type captureWriter struct {
	header http.Header
	body   strings.Builder
	status int
}

func (c *captureWriter) Header() http.Header { return c.header }
func (c *captureWriter) WriteHeader(s int)   { c.status = s }
func (c *captureWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = 200
	}
	return c.body.Write(p)
}

// approvalExpiryLoop retires requests nobody decided in time.
func (s *Server) approvalExpiryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if n, err := s.store.ExpirePendingApprovals(ctx); err != nil {
			s.logger.Warn("expiring approvals failed", "error", err)
		} else if n > 0 {
			s.logger.Info("approval requests expired", "count", n)
		}
	}
}

// policyTouches reports whether an operation reaches any endpoint a
// group-scoped policy covers. One is enough: a deployment that includes a
// domain controller among fifty laptops is a deployment that touches a
// domain controller.
func policyTouches(agentIDs []string, covered map[string]bool) bool {
	for _, id := range agentIDs {
		if covered[id] {
			return true
		}
	}
	return false
}
