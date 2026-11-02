package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// --- content sets ----------------------------------------------------------

// contentKinds are what a content set can hold. Each maps to something the
// console already has ids for, so a set is a list of real things rather
// than a new naming scheme.
var contentKinds = []string{"sensors", "packages", "dashboards", "questions"}

// listContentSetsResponse is what GET /api/content-sets answers.
type listContentSetsResponse struct {
	Available   map[string][]map[string]string `json:"available"`
	ContentSets []store.ContentSet             `json:"content_sets"`
	Kinds       []string                       `json:"kinds"`
}

func (s *Server) handleListContentSets(w http.ResponseWriter, r *http.Request) {
	sets, err := s.store.ListContentSets(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The pickers need the available content, and it is small enough to
	// send with the list rather than making the page assemble it.
	pkgs, _ := s.store.ListSoftwarePackages(r.Context())
	dashboards, _ := s.store.ListDashboards(r.Context())
	questions, _ := s.store.ListSavedQuestions(r.Context())
	available := map[string][]map[string]string{"sensors": {}, "packages": {}, "dashboards": {}, "questions": {}}
	for _, k := range sensorCatalog() {
		available["sensors"] = append(available["sensors"], map[string]string{"id": k.Kind, "name": k.Name})
	}
	// Custom sensors are listed by the kind their fields carry
	// ("custom_…"), which is what enforcement compares.
	if customs, err := s.store.ListCustomSensors(r.Context()); err == nil {
		for _, c := range customs {
			available["sensors"] = append(available["sensors"], map[string]string{"id": c.SensorKind(), "name": c.Name + " (custom)"})
		}
	}
	for _, p := range pkgs {
		available["packages"] = append(available["packages"], map[string]string{"id": p.ID, "name": p.Name})
	}
	for _, d := range dashboards {
		available["dashboards"] = append(available["dashboards"], map[string]string{"id": d.ID, "name": d.Name})
	}
	for _, q := range questions {
		available["questions"] = append(available["questions"], map[string]string{"id": q.ID, "name": q.Name})
	}
	writeJSONResponse(w, listContentSetsResponse{ContentSets: sets, Kinds: contentKinds, Available: available})
}

func (s *Server) handleSaveContentSet(w http.ResponseWriter, r *http.Request) {
	var in store.ContentSet
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	clean := map[string][]string{}
	for _, k := range contentKinds {
		for _, v := range in.Contents[k] {
			if v = strings.TrimSpace(v); v != "" {
				clean[k] = append(clean[k], v)
			}
		}
	}
	for k := range in.Contents {
		if _, ok := clean[k]; !ok && !contains(contentKinds, k) {
			http.Error(w, "unknown content kind: "+k, http.StatusBadRequest)
			return
		}
	}
	in.Contents = clean
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetContentSet(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such content set", http.StatusNotFound)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		in.ID, in.CreatedBy = idgen.New("cs-"), u.Username
	}
	if err := s.store.UpsertContentSet(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "content_set.save", Actor: u.Username, Target: in.Name, Severity: "notice"})
	out, _ := s.store.GetContentSet(r.Context(), in.ID)
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteContentSet(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetContentSet(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such content set", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteContentSet(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "content_set.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// --- action groups ---------------------------------------------------------

// listActionGroupsResponse is what GET /api/action-groups answers.
type listActionGroupsResponse struct {
	ActionGroups   []store.ActionGroup `json:"action_groups"`
	Modules        []string            `json:"modules"`
	Resolved       map[string]int      `json:"resolved"`
	TotalEndpoints int                 `json:"total_endpoints"`
}

func (s *Server) handleListActionGroups(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListActionGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Show what each ceiling currently resolves to, because "these three
	// groups" is not an answer to "so which machines is that".
	members, _, err := s.accessSnapshot(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts := map[string]int{}
	for _, a := range list {
		if a.Enabled && len(a.GroupIDs) > 0 {
			counts[a.Module] = len(agentSet(members, a.GroupIDs))
		}
	}
	total := 0
	for range members {
		break
	}
	if agents, err := s.store.ListAgents(r.Context(), s.staleAfter()); err == nil {
		total = len(agents)
	}
	writeJSONResponse(w, listActionGroupsResponse{ActionGroups: list, Modules: accessModules, Resolved: counts, TotalEndpoints: total})
}

func (s *Server) handleSaveActionGroup(w http.ResponseWriter, r *http.Request) {
	var in store.ActionGroup
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validModule(in.Module) {
		http.Error(w, "module must be one of "+strings.Join(accessModules, ", "), http.StatusBadRequest)
		return
	}
	in.UpdatedBy = auth.CurrentUser(r.Context()).Username
	in, err := s.store.UpsertActionGroup(r.Context(), in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateAccess()
	s.audit(r.Context(), auditEvent{Action: "action_group.save", Actor: in.UpdatedBy, Target: in.Module, Severity: "notice",
		Detail: map[string]any{"groups": len(in.GroupIDs), "enabled": in.Enabled}})
	writeJSONResponse(w, in)
}

func (s *Server) handleDeleteActionGroup(w http.ResponseWriter, r *http.Request) {
	module := r.PathValue("module")
	if err := s.store.DeleteActionGroup(r.Context(), module); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateAccess()
	s.audit(r.Context(), auditEvent{Action: "action_group.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: module, Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

// --- approval policies -----------------------------------------------------

// listApprovalPoliciesResponse is what GET /api/approval-policies answers.
type listApprovalPoliciesResponse struct {
	Modules  []string               `json:"modules"`
	Policies []store.ApprovalPolicy `json:"policies"`
}

func (s *Server) handleListApprovalPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListApprovalPolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listApprovalPoliciesResponse{Policies: list, Modules: []string{"deploy", "patches", "playbooks"}})
}

// saveApprovalPolicyRequest is the body of POST /api/approval-policies and
// PUT /api/approval-policies/{id}. A PUT replaces the whole policy: a
// field it leaves out takes its empty value, and enabled left out
// switches the policy off. Send every field, as read from GET
// /api/approval-policies.
type saveApprovalPolicyRequest struct {
	store.ApprovalPolicy
	// Enabled is true when a create leaves it out. On a PUT, left out is
	// false.
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleSaveApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	var req saveApprovalPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in := req.ApprovalPolicy
	in.Enabled = req.Enabled != nil && *req.Enabled
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	// Only operations that can be replayed may be gated: parking one that
	// cannot be resumed would be a way to lose work quietly.
	gateable := map[string]bool{"deploy": true, "patches": true, "playbooks": true}
	if !gateable[in.Module] {
		http.Error(w, "approvals cover deploy, patches and playbooks; the others cannot be paused and resumed", http.StatusBadRequest)
		return
	}
	if in.MinDevices < 0 {
		in.MinDevices = 0
	}
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetApprovalPolicy(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such policy", http.StatusNotFound)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		in.ID, in.CreatedBy = idgen.New("ap-"), u.Username
		if req.Enabled == nil {
			in.Enabled = true
		}
	}
	if err := s.store.UpsertApprovalPolicy(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "approval_policy.save", Actor: u.Username, Target: in.Name, Severity: "notice",
		Detail: map[string]any{"module": in.Module, "min_devices": in.MinDevices, "enabled": in.Enabled}})
	out, _ := s.store.GetApprovalPolicy(r.Context(), in.ID)
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetApprovalPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such policy", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteApprovalPolicy(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "approval_policy.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

// --- approval requests -----------------------------------------------------

// listApprovalRequestsResponse is what GET /api/approvals answers.
type listApprovalRequestsResponse struct {
	CanDecide bool                    `json:"can_decide"`
	Me        string                  `json:"me"`
	Pending   int                     `json:"pending"`
	Requests  []store.ApprovalRequest `json:"requests"`
}

func (s *Server) handleListApprovalRequests(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListApprovalRequests(r.Context(), r.URL.Query().Get("state"), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	can, _ := s.auth.HasPermission(r.Context(), auth.CurrentUser(r.Context()), auth.PermApprovalsDecide)
	pending := 0
	for _, a := range list {
		if a.State == "pending" {
			pending++
		}
	}
	writeJSONResponse(w, listApprovalRequestsResponse{Requests: list, Pending: pending, CanDecide: can,
		Me: auth.CurrentUser(r.Context()).Username})
}

// decideApprovalRequest is the body of POST /api/approvals/{id}/decide.
type decideApprovalRequest struct {
	Decision string `json:"decision" api:"required"`
	Note     string `json:"note"`
}

// decideApprovalResponse is what POST /api/approvals/{id}/decide answers.
type decideApprovalResponse struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// POST /api/approvals/{id}/decide {"decision":"approve"|"deny","note":""}
func (s *Server) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	var body decideApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.Decision != "approve" && body.Decision != "deny" {
		http.Error(w, `decision must be "approve" or "deny"`, http.StatusBadRequest)
		return
	}
	req, err := s.store.GetApprovalRequest(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req == nil {
		http.Error(w, "no such approval request", http.StatusNotFound)
		return
	}
	if req.State != "pending" {
		http.Error(w, "that request is already "+req.State, http.StatusConflict)
		return
	}
	u := auth.CurrentUser(r.Context())
	// The point of an approval is a second person. Approving your own
	// request would make the policy a speed bump with a log entry.
	if req.RequestedBy == u.Username {
		http.Error(w, "you asked for this one; somebody else has to approve it", http.StatusForbidden)
		return
	}
	state := "approved"
	if body.Decision == "deny" {
		state = "denied"
	}
	ok, err := s.store.DecideApprovalRequest(r.Context(), req.ID, state, u.Username, body.Note)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "somebody decided that one first", http.StatusConflict)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "approval." + body.Decision, Actor: u.Username, Target: req.Summary,
		Severity: "notice", Detail: map[string]any{"request_id": req.ID, "requested_by": req.RequestedBy, "devices": req.DeviceCount}})
	if state == "approved" {
		go s.runApproved(context.WithoutCancel(r.Context()), *req)
	}
	writeJSONResponse(w, decideApprovalResponse{ID: req.ID, State: state})
}

// myAccessResponse is what GET /api/access/me answers. endpoints and
// hostnames are there only when the caller's reach is limited.
type myAccessResponse struct {
	ActionGroupEndpoints map[string]int `json:"action_group_endpoints"`
	ContentSets          []string       `json:"content_sets"`
	ContentUnrestricted  bool           `json:"content_unrestricted"`
	Endpoints            *int           `json:"endpoints,omitempty"`
	Hostnames            *[]string      `json:"hostnames,omitempty"`
	TotalEndpoints       int            `json:"total_endpoints"`
	Unrestricted         bool           `json:"unrestricted"`
}

// GET /api/access/me — what the signed-in user's scope actually is, so the
// console can say so rather than letting an operator find out by being
// refused.
func (s *Server) handleMyAccess(w http.ResponseWriter, r *http.Request) {
	scope, err := s.endpointScope(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agents, _ := s.store.ListAgents(r.Context(), s.staleAfter())
	out := myAccessResponse{Unrestricted: scope == nil, TotalEndpoints: len(agents)}
	if scope != nil {
		names := []string{}
		for _, a := range agents {
			if scope[a.AgentID] {
				names = append(names, a.Hostname)
			}
		}
		n := len(names)
		out.Endpoints, out.Hostnames = &n, &names
	}
	ceilings := map[string]int{}
	for _, m := range accessModules {
		if c, err := s.actionCeiling(r.Context(), m); err == nil && c != nil {
			ceilings[m] = len(c)
		}
	}
	out.ActionGroupEndpoints = ceilings
	setIDs, unrestrictedContent, _ := s.store.ContentSetIDsForUser(r.Context(), auth.CurrentUser(r.Context()).ID)
	out.ContentUnrestricted = unrestrictedContent || auth.CurrentUser(r.Context()).IsAdmin
	out.ContentSets = setIDs
	writeJSONResponse(w, out)
}
