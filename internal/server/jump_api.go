package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Jump Gate on Direct Connect: just-in-time, just-enough endpoint access.
//
// Direct Connect already required a permission, already wrote every
// command to the log before sending it, and since 0.60.0 already honoured
// management rights and the shell action group. What it lacked was the
// other half of privileged access: a reason, somebody else agreeing, a
// clock, and a way for a person who may *not* open sessions to read what
// happened in them.
//
//	policy   what reaching this endpoint costs
//	grant    one person's time-boxed permission to reach one endpoint
//	session  the recorded thing, now carrying why it existed
//	auditor  sessions.audit reads transcripts without deploy.manage
//
// No new ports and no new agent code: the gate is entirely in front of the
// session object that already existed.

// jumpSettingWebhook and jumpSettingStyle point access requests at a chat
// channel. Optional — the console notification is always raised.
const (
	jumpSettingWebhook = "jump.webhook_url"
	jumpSettingStyle   = "jump.webhook_style"
)

// effectiveJumpPolicy returns the highest-priority enabled policy covering
// an endpoint, or nil when none does.
func (s *Server) effectiveJumpPolicy(ctx context.Context, agentID string) (*store.JumpPolicy, error) {
	policies, err := s.store.ListJumpPolicies(ctx)
	if err != nil {
		return nil, err
	}
	members, _, err := s.accessSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	for i := range policies {
		p := policies[i]
		if !p.Enabled {
			continue
		}
		if len(p.GroupIDs) == 0 {
			return &p, nil // covers every endpoint
		}
		if agentSet(members, p.GroupIDs)[agentID] {
			return &p, nil
		}
	}
	return nil, nil
}

// jumpGate decides whether this person may open a session on this endpoint
// right now. It returns the policy that applied, the grant being spent (if
// any), and the session's deadline.
//
// Returns false and writes the response when the caller must stop.
func (s *Server) jumpGate(w http.ResponseWriter, r *http.Request, agentID, hostname, reason string) (ok bool, grantID string, expires *time.Time) {
	policy, err := s.effectiveJumpPolicy(r.Context(), agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false, "", nil
	}
	if policy == nil {
		return true, "", nil
	}
	u := auth.CurrentUser(r.Context())
	if policy.RequireReason && strings.TrimSpace(reason) == "" {
		writeJSONError(w, http.StatusBadRequest, map[string]any{
			"error": "this endpoint needs a reason for access", "policy": policy.Name,
			"require_reason": true, "require_approval": policy.RequireApproval, "max_minutes": policy.MaxMinutes,
		})
		return false, "", nil
	}
	if !policy.RequireApproval {
		if policy.MaxMinutes > 0 {
			t := time.Now().Add(time.Duration(policy.MaxMinutes) * time.Minute)
			expires = &t
		}
		return true, "", expires
	}
	grant, err := s.store.ActiveJumpGrant(r.Context(), u.Username, agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false, "", nil
	}
	if grant == nil {
		s.audit(r.Context(), auditEvent{Action: "jump.denied", Actor: u.Username, Target: hostname, AgentID: agentID,
			Outcome: "denied", Severity: "notice", Detail: map[string]any{"policy": policy.Name}})
		writeJSONError(w, http.StatusForbidden, map[string]any{
			"error":            fmt.Sprintf("%s needs approved access before a session can open", hostname),
			"policy":           policy.Name,
			"request_access":   true,
			"require_reason":   policy.RequireReason,
			"require_approval": true,
			"max_minutes":      policy.MaxMinutes,
		})
		return false, "", nil
	}
	// The session ends when the grant does, never later.
	expires = grant.ExpiresAt
	return true, grant.ID, expires
}

// writeJSONError sends a structured refusal. The console needs to tell the
// difference between "you may not" and "you may, once somebody agrees",
// and a bare string cannot carry that.
func writeJSONError(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// --- access requests -------------------------------------------------------

// requestJumpAccessRequest is the body of POST /api/jump/requests.
type requestJumpAccessRequest struct {
	AgentID string `json:"agent_id" api:"required"`
	Reason  string `json:"reason"`
}

// requestJumpAccessResponse is what POST /api/jump/requests answers.
type requestJumpAccessResponse struct {
	Grant   store.JumpGrant `json:"grant"`
	Message string          `json:"message"`
}

// jumpAlreadyGrantedResponse is what POST /api/jump/requests answers when
// the caller already holds a live grant for the endpoint.
type jumpAlreadyGrantedResponse struct {
	AlreadyGranted bool             `json:"already_granted"`
	Grant          *store.JumpGrant `json:"grant"`
}

// POST /api/jump/requests {"agent_id":"","reason":""}
func (s *Server) handleRequestJumpAccess(w http.ResponseWriter, r *http.Request) {
	var body requestJumpAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	// The endpoint still has to be one you could reach at all: a request
	// for access you could never be granted is noise aimed at an approver.
	if !s.checkTargets(w, r, "shell", []string{body.AgentID}) {
		return
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hostname := ""
	for _, a := range agents {
		if a.AgentID == body.AgentID {
			hostname = a.Hostname
		}
	}
	if hostname == "" {
		http.Error(w, "no such endpoint", http.StatusNotFound)
		return
	}
	policy, err := s.effectiveJumpPolicy(r.Context(), body.AgentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policy == nil || !policy.RequireApproval {
		http.Error(w, hostname+" does not need approved access; open a session directly", http.StatusBadRequest)
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if policy.RequireReason && reason == "" {
		http.Error(w, "a reason is required for "+hostname, http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	if existing, _ := s.store.ActiveJumpGrant(r.Context(), u.Username, body.AgentID); existing != nil {
		writeJSONResponse(w, jumpAlreadyGrantedResponse{AlreadyGranted: true, Grant: existing})
		return
	}
	g := store.JumpGrant{
		ID: idgen.New("jg-"), AgentID: body.AgentID, Hostname: hostname,
		PolicyID: policy.ID, PolicyName: policy.Name, RequestedBy: u.Username,
		Reason: reason, MaxMinutes: policy.MaxMinutes, State: "pending",
	}
	g, err = s.store.CreateJumpGrant(r.Context(), g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "jump.requested", Actor: u.Username, Target: hostname, AgentID: body.AgentID,
		Severity: "notice", Detail: map[string]any{"grant_id": g.ID, "policy": policy.Name, "reason": reason}})
	s.notifyRequest(r.Context(), "warning", "jump",
		fmt.Sprintf("%s is asking for access to %s", u.Username, hostname),
		reason, "/access#jump", "jump", g.ID, true)
	go s.notifyJumpWebhook(context.WithoutCancel(r.Context()), g)
	writeJSONResponse(w, requestJumpAccessResponse{Grant: g, Message: "Access requested. It opens once somebody with jump.approve agrees."})
}

// notifyJumpWebhook posts an access request to a chat channel when one is
// configured. Best effort: a webhook that is down must not stop somebody
// asking for access.
func (s *Server) notifyJumpWebhook(ctx context.Context, g store.JumpGrant) {
	url, _ := s.store.GetSetting(ctx, jumpSettingWebhook)
	if strings.TrimSpace(url) == "" {
		return
	}
	style, _ := s.store.GetSetting(ctx, jumpSettingStyle)
	if style == "" {
		style = "discord"
	}
	decide := "/approve?kind=jump&id=" + g.ID
	if base, _ := s.agentPublicURLOrEmpty(ctx); base != "" {
		decide = strings.TrimRight(base, "/") + decide
	}
	text := fmt.Sprintf("%s is asking for access to %s\nPolicy: %s\nReason: %s\nWindow: %d minutes\nDecide: %s",
		g.RequestedBy, g.Hostname, g.PolicyName, g.Reason, g.MaxMinutes, decide)
	field := "content"
	if style == "slack" {
		field = "text"
	}
	payload, _ := json.Marshal(map[string]string{field: text})
	client, allowed := s.webhookClient(ctx)
	if err := checkWebhookURL(url, allowed); err != nil {
		s.logger.Warn("jump webhook refused", "error", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mustra-jump/1.0")
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Warn("jump webhook failed", "error", err)
		return
	}
	resp.Body.Close()
}

// listJumpGrantsResponse is what GET /api/jump/grants answers.
type listJumpGrantsResponse struct {
	CanApprove bool              `json:"can_approve"`
	Grants     []store.JumpGrant `json:"grants"`
	Me         string            `json:"me"`
	Pending    int               `json:"pending"`
}

func (s *Server) handleListJumpGrants(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListJumpGrants(r.Context(), r.URL.Query().Get("state"), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := auth.CurrentUser(r.Context())
	can, _ := s.auth.HasPermission(r.Context(), u, auth.PermJumpApprove)
	pending := 0
	for _, g := range list {
		if g.State == "pending" {
			pending++
		}
	}
	writeJSONResponse(w, listJumpGrantsResponse{Grants: list, Pending: pending, CanApprove: can, Me: u.Username})
}

// decideJumpGrantRequest is the body of POST /api/jump/grants/{id}/decide.
type decideJumpGrantRequest struct {
	Decision string `json:"decision" api:"required"`
	Note     string `json:"note"`
	Minutes  int    `json:"minutes"`
}

// decideJumpGrantResponse is what POST /api/jump/grants/{id}/decide
// answers.
type decideJumpGrantResponse struct {
	ID      string `json:"id"`
	Minutes int    `json:"minutes"`
	State   string `json:"state"`
}

// POST /api/jump/grants/{id}/decide
func (s *Server) handleDecideJumpGrant(w http.ResponseWriter, r *http.Request) {
	var body decideJumpGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.Decision != "approve" && body.Decision != "deny" {
		http.Error(w, `decision must be "approve" or "deny"`, http.StatusBadRequest)
		return
	}
	g, err := s.store.GetJumpGrant(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if g == nil {
		http.Error(w, "no such access request", http.StatusNotFound)
		return
	}
	if g.State != "pending" {
		http.Error(w, "that request is already "+g.State, http.StatusConflict)
		return
	}
	u := auth.CurrentUser(r.Context())
	if g.RequestedBy == u.Username {
		http.Error(w, "you asked for this one; somebody else has to approve it", http.StatusForbidden)
		return
	}
	minutes := body.Minutes
	if minutes <= 0 || minutes > g.MaxMinutes {
		minutes = g.MaxMinutes // an approver may shorten the window, never extend it
	}
	state := "approved"
	if body.Decision == "deny" {
		state = "denied"
	}
	ok, err := s.store.DecideJumpGrant(r.Context(), g.ID, state, u.Username, body.Note, minutes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "somebody decided that one first", http.StatusConflict)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "jump." + body.Decision, Actor: u.Username, Target: g.Hostname, AgentID: g.AgentID,
		Severity: "notice", Detail: map[string]any{"grant_id": g.ID, "requested_by": g.RequestedBy, "minutes": minutes}})
	s.notify(r.Context(), "info", "jump",
		fmt.Sprintf("Access to %s %s", g.Hostname, state),
		fmt.Sprintf("%s %s %s's request%s", u.Username, state, g.RequestedBy,
			map[bool]string{true: fmt.Sprintf(" for %d minutes", minutes), false: ""}[state == "approved"]), "/access#jump")
	writeJSONResponse(w, decideJumpGrantResponse{ID: g.ID, State: state, Minutes: minutes})
}

// revokeJumpGrantResponse is what POST /api/jump/grants/{id}/revoke
// answers.
type revokeJumpGrantResponse struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// POST /api/jump/grants/{id}/revoke — end a window early.
func (s *Server) handleRevokeJumpGrant(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetJumpGrant(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if g == nil {
		http.Error(w, "no such access request", http.StatusNotFound)
		return
	}
	ok, err := s.store.RevokeJumpGrant(r.Context(), g.ID, auth.CurrentUser(r.Context()).Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "that grant is not active", http.StatusConflict)
		return
	}
	// Revoking access that is being used should end the session too, not
	// wait for the clock it was just taken off.
	if n, err := s.store.CloseSessionsForGrant(r.Context(), g.ID); err == nil && n > 0 {
		s.logger.Info("closed sessions on revoked grant", "grant", g.ID, "sessions", n)
	}
	s.audit(r.Context(), auditEvent{Action: "jump.revoked", Actor: auth.CurrentUser(r.Context()).Username,
		Target: g.Hostname, AgentID: g.AgentID, Severity: "notice", Detail: map[string]any{"grant_id": g.ID, "requested_by": g.RequestedBy}})
	writeJSONResponse(w, revokeJumpGrantResponse{ID: g.ID, State: "revoked"})
}

// --- policies --------------------------------------------------------------

// listJumpPoliciesResponse is what GET /api/jump/policies answers.
type listJumpPoliciesResponse struct {
	Policies     []store.JumpPolicy `json:"policies"`
	WebhookSet   bool               `json:"webhook_set"`
	WebhookStyle string             `json:"webhook_style"`
}

func (s *Server) handleListJumpPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListJumpPolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	url, _ := s.store.GetSetting(r.Context(), jumpSettingWebhook)
	style, _ := s.store.GetSetting(r.Context(), jumpSettingStyle)
	writeJSONResponse(w, listJumpPoliciesResponse{Policies: list, WebhookSet: strings.TrimSpace(url) != "", WebhookStyle: style})
}

func (s *Server) handleSaveJumpPolicy(w http.ResponseWriter, r *http.Request) {
	var in store.JumpPolicy
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if in.MaxMinutes <= 0 {
		in.MaxMinutes = 30
	}
	if in.MaxMinutes > 480 {
		http.Error(w, "a window longer than eight hours is not just-in-time access; use a shorter one", http.StatusBadRequest)
		return
	}
	if !s.requireKnownGroups(w, r, in.GroupIDs) {
		return
	}
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetJumpPolicy(r.Context(), id)
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
		in.ID, in.CreatedBy = idgen.New("jp-"), u.Username
	}
	if err := s.store.UpsertJumpPolicy(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "jump_policy.save", Actor: u.Username, Target: in.Name, Severity: "notice",
		Detail: map[string]any{"approval": in.RequireApproval, "reason": in.RequireReason, "minutes": in.MaxMinutes, "groups": len(in.GroupIDs)}})
	out, _ := s.store.GetJumpPolicy(r.Context(), in.ID)
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteJumpPolicy(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetJumpPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such policy", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteJumpPolicy(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "jump_policy.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

// --- auditor view ----------------------------------------------------------

// listTranscriptsResponse is what GET /api/sessions answers.
type listTranscriptsResponse struct {
	Sessions []store.SessionTranscript `json:"sessions"`
}

func (s *Server) handleListTranscripts(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListSessionTranscripts(r.Context(), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listTranscriptsResponse{Sessions: list})
}

func (s *Server) handleGetTranscript(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetSessionTranscript(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if t == nil {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	// Reading a transcript is itself worth recording: the whole point of
	// an auditor role is that somebody is accountable for looking.
	s.audit(r.Context(), auditEvent{Action: "session.transcript_view", Actor: auth.CurrentUser(r.Context()).Username,
		Target: t.Hostname, AgentID: t.AgentID, Severity: "info", Detail: map[string]any{"session_id": t.ID, "commands": t.CommandN}})
	writeJSONResponse(w, t)
}

// jumpExpiryLoop closes windows and the sessions inside them.
func (s *Server) jumpExpiryLoop(ctx context.Context) {
	// Often enough that a remote desktop outlives its window by seconds,
	// not a minute; each pass is a few indexed queries.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if n, err := s.store.ExpireJumpGrants(ctx); err != nil {
			s.logger.Warn("expiring jump grants failed", "error", err)
		} else if n > 0 {
			s.logger.Info("jump grants expired", "count", n)
		}
		if n, err := s.store.CloseExpiredSessions(ctx); err != nil {
			s.logger.Warn("closing expired sessions failed", "error", err)
		} else if n > 0 {
			s.logger.Info("expired Direct Connect sessions closed", "count", n)
		}
		s.endRemoteSessions(ctx)
	}
}
