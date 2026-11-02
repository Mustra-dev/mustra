package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/enforcekinds"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// HTTP surface for Enforce. Reading is open to any signed-in user, like
// every other reporting view; authoring and running are gated on
// deploy.manage, because a policy is operator-written code that runs on
// every targeted endpoint with the agent's rights.

// listEnforcePoliciesResponse is what GET /api/enforce/policies answers.
type listEnforcePoliciesResponse struct {
	IntervalMinutes int               `json:"interval_minutes"`
	MaxAttempts     int               `json:"max_attempts"`
	Policies        []enforceOverview `json:"policies"`
}

func (s *Server) handleListEnforcePolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListEnforcePolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	results, err := s.store.ListEnforceResults(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listEnforcePoliciesResponse{
		Policies:        summariseEnforce(policies, results),
		MaxAttempts:     store.MaxRemediationAttempts,
		IntervalMinutes: int(enforceInterval.Minutes()),
	})
}

// getEnforcePolicyResponse is what GET /api/enforce/policies/{id} answers.
type getEnforcePolicyResponse struct {
	Policy  *store.EnforcePolicy  `json:"policy"`
	Results []store.EnforceResult `json:"results"`
}

func (s *Server) handleGetEnforcePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := s.lookupEnforcePolicy(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	results, err := s.store.ListEnforceResults(r.Context(), p.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, getEnforcePolicyResponse{Policy: p, Results: results})
}

// listEnforceResultsResponse is what GET /api/enforce/results answers.
type listEnforceResultsResponse struct {
	Results []store.EnforceResult `json:"results"`
}

func (s *Server) handleListEnforceResults(w http.ResponseWriter, r *http.Request) {
	results, err := s.store.ListEnforceResults(r.Context(), r.URL.Query().Get("policy"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listEnforceResultsResponse{Results: results})
}

type enforcePolicyRequest struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name" api:"required"`
	Description string                 `json:"description"`
	OS          string                 `json:"os"`
	GroupID     string                 `json:"group_id"`
	Mode        string                 `json:"mode"`
	Enabled     *bool                  `json:"enabled"`
	Settings    []proto.EnforceSetting `json:"settings"`
	// Kind and Config describe a typed policy (internal/enforcekinds);
	// when Kind is set the settings are compiled from Config and whatever
	// arrived in Settings is ignored.
	Kind   string          `json:"kind"`
	Config json.RawMessage `json:"config"`
}

// settingsDiffer answers "did the author actually change anything", which
// is not the same question as "are these bytes identical".
func settingsDiffer(stored json.RawMessage, incoming []proto.EnforceSetting) bool {
	var previous []proto.EnforceSetting
	if err := json.Unmarshal(stored, &previous); err != nil {
		// Unreadable stored settings: treat it as a change, because the
		// safe direction here is clearing history that might be stale
		// rather than keeping counters that might describe other rules.
		return true
	}
	was, err1 := json.Marshal(previous)
	now, err2 := json.Marshal(incoming)
	if err1 != nil || err2 != nil {
		return true
	}
	return !bytes.Equal(was, now)
}

var enforcePlatforms = map[string]bool{"": true, "linux": true, "windows": true, "darwin": true}

// saveEnforcePolicyResponse is what POST /api/enforce/policies and PUT
// /api/enforce/policies/{id} answer.
type saveEnforcePolicyResponse struct {
	Policy *store.EnforcePolicy `json:"policy"`
}

func (s *Server) handleSaveEnforcePolicy(w http.ResponseWriter, r *http.Request) {
	var req enforcePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// The path wins when there is one. PUT /…/{id} with an id-less body used
	// to mint a fresh object rather than update the one addressed, and with
	// a mismatched body id it updated a different one.
	if id := r.PathValue("id"); id != "" {
		req.ID = id
	}
	if err := checkClientID("policy", req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "a policy needs a name", http.StatusBadRequest)
		return
	}
	if !enforcePlatforms[req.OS] {
		http.Error(w, "platform must be blank, linux, windows or darwin", http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		req.Mode = "report"
	}
	if req.Mode != "report" && req.Mode != "enforce" {
		http.Error(w, `mode must be "report" or "enforce"`, http.StatusBadRequest)
		return
	}
	req.Kind = strings.TrimSpace(req.Kind)
	if !enforcekinds.Valid(enforcekinds.Kind(req.Kind)) {
		http.Error(w, "unknown policy kind", http.StatusBadRequest)
		return
	}
	if req.Kind != "" {
		// A typed policy is its form, compiled. The kinds are all Windows
		// today, and the platform follows the kind rather than the form.
		compiled, err := enforcekinds.Compile(enforcekinds.Kind(req.Kind), req.Config)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Settings = compiled
		for _, k := range enforcekinds.Kinds() {
			if string(k.Kind) == req.Kind {
				req.OS = k.OS
			}
		}
	} else {
		req.Config = json.RawMessage("{}")
	}
	settings, err := validateEnforceSettings(req.Settings, req.Mode, req.OS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.GroupID != "" {
		g, err := s.store.GetComputerGroup(r.Context(), req.GroupID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if g == nil {
			http.Error(w, "no such computer group", http.StatusBadRequest)
			return
		}
	}

	encoded, err := json.Marshal(settings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// A failed read is not "new": taken as one, an update audited itself as
	// a create and kept the old settings' failure counters.
	var existing *store.EnforcePolicy
	if req.ID != "" {
		if existing, err = s.store.GetEnforcePolicy(r.Context(), req.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		req.ID = idgen.New("enf-")
	}
	policy := store.EnforcePolicy{
		ID: req.ID, Name: req.Name, Description: strings.TrimSpace(req.Description),
		OS: req.OS, GroupID: req.GroupID, Mode: req.Mode, Enabled: enabled,
		Settings: encoded, UpdatedBy: who, Kind: req.Kind, Config: req.Config,
	}
	if err := s.store.UpsertEnforcePolicy(r.Context(), policy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Editing the settings invalidates the history — including, crucially,
	// the failure counters. Somebody who has just fixed a broken remediation
	// command must not find mustra still refusing to run it because the old
	// one failed three times.
	//
	// Compared as decoded settings, not as bytes: Postgres hands jsonb back
	// reserialized — spaces after separators, keys reordered — so a byte
	// compare against Go's compact output was never equal, and *every* save
	// cleared the history. Renaming a policy was enough to make mustra
	// forget it had given up on a remediation and start running it again.
	if existing != nil && settingsDiffer(existing.Settings, settings) {
		if err := s.store.ClearEnforceResultsForPolicy(r.Context(), policy.ID); err != nil {
			s.logger.Warn("enforce: could not clear results after an edit", "policy", policy.Name, "error", err)
		}
	}

	action := "enforce.policy.update"
	if existing == nil {
		action = "enforce.policy.create"
	}
	severity := "info"
	if req.Mode == "enforce" && (existing == nil || existing.Mode != "enforce") {
		// Switching a policy from describing the fleet to changing it is
		// the single most consequential click in this module.
		severity = "warning"
	}
	s.audit(r.Context(), auditEvent{
		Action: action, Actor: who, Target: policy.Name, Severity: severity,
		Detail: map[string]any{"mode": policy.Mode, "settings": len(settings),
			"platform": policy.OS, "group": policy.GroupID, "enabled": enabled, "kind": policy.Kind},
	})
	// The write is done and audited; name the policy, so a client that
	// sees the 500 updates it rather than creating another.
	saved, err := s.store.GetEnforcePolicy(r.Context(), policy.ID)
	if err != nil || saved == nil {
		msg := fmt.Sprintf("policy %s was saved but could not be read back", policy.ID)
		if err != nil {
			msg += ": " + err.Error()
		}
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, saveEnforcePolicyResponse{Policy: saved})
}

// lookupEnforcePolicy reads the policy a route names. A missing one is a
// 404; a database error is a 500, not "no such policy".
func (s *Server) lookupEnforcePolicy(w http.ResponseWriter, r *http.Request, id string) (*store.EnforcePolicy, bool) {
	p, err := s.store.GetEnforcePolicy(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	if p == nil {
		http.Error(w, "no such policy", http.StatusNotFound)
		return nil, false
	}
	return p, true
}

// validateEnforceSettings rejects the shapes that would misbehave at 3am
// rather than at save time.
func validateEnforceSettings(settings []proto.EnforceSetting, mode, os string) ([]proto.EnforceSetting, error) {
	if len(settings) == 0 {
		return nil, fmt.Errorf("a policy needs at least one setting")
	}
	seen := map[string]bool{}
	fixable := 0
	for i := range settings {
		s := &settings[i]
		s.Name = strings.TrimSpace(s.Name)
		if s.Name == "" {
			return nil, fmt.Errorf("setting %d needs a name", i+1)
		}
		var rules []string
		for _, rule := range s.Rules {
			if rule = strings.TrimSpace(rule); rule != "" {
				rules = append(rules, rule)
			}
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("%q defines no rules, so there is nothing to check", s.Name)
		}
		s.Rules = rules
		switch strings.ToLower(strings.TrimSpace(s.Condition)) {
		case "", "all", "any", "none":
		default:
			return nil, fmt.Errorf("%q: condition must be all, any or none", s.Name)
		}
		if s.ID == "" {
			s.ID = idgen.New("set-")
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("two settings share the id %q", s.ID)
		}
		seen[s.ID] = true
		// Enforce is the server's decision at dispatch time, never the
		// author's. Clear whatever arrived.
		s.Enforce = false

		s.RemediateLinux = strings.TrimSpace(s.RemediateLinux)
		s.RemediateWindows = strings.TrimSpace(s.RemediateWindows)
		s.RemediateDarwin = strings.TrimSpace(s.RemediateDarwin)
		if remediationForPlatform(*s, os) != "" {
			fixable++
		}
	}
	if mode == "enforce" && fixable == 0 {
		where := "any platform"
		if os != "" {
			where = os
		}
		return nil, fmt.Errorf("this policy is set to enforce but no setting has a remediation command for %s, "+
			"so it can only ever report drift — add one, or save it in report mode", where)
	}
	return settings, nil
}

// remediationForPlatform answers "could this setting ever fix anything on
// the platform this policy targets". A policy scoped to one OS is judged on
// that OS alone; an any-platform policy passes if it can fix anything
// anywhere.
func remediationForPlatform(s proto.EnforceSetting, os string) string {
	switch os {
	case "linux":
		return s.RemediateLinux
	case "windows":
		return s.RemediateWindows
	case "darwin":
		return s.RemediateDarwin
	default:
		return s.RemediateLinux + s.RemediateWindows + s.RemediateDarwin
	}
}

// deleteEnforcePolicyResponse is what DELETE /api/enforce/policies/{id}
// answers.
type deleteEnforcePolicyResponse struct {
	Deleted string `json:"deleted"`
}

func (s *Server) handleDeleteEnforcePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, ok := s.lookupEnforcePolicy(w, r, id)
	if !ok {
		return
	}
	if err := s.store.DeleteEnforcePolicy(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "enforce.policy.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: p.Name, Severity: "notice",
	})
	writeJSONResponse(w, deleteEnforcePolicyResponse{Deleted: p.Name})
}

// runEnforcePolicyRequest is the body of POST /api/enforce/policies/{id}/run.
type runEnforcePolicyRequest struct {
	DryRun bool `json:"dry_run"`
}

// handleRunEnforcePolicy runs one policy now.
//
// dry_run forces report mode for this pass whatever the policy says, which
// is how you find out what an enforcing policy would do before letting it
// loose on a timer.
func (s *Server) handleRunEnforcePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := s.lookupEnforcePolicy(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var body runEnforcePolicyRequest
	if r.ContentLength != 0 {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.DryRun {
		// Not plain "report": that also told runEnforceOn nothing was ever
		// suppressed, so a dry run erased the record of what mustra had
		// given up on. See dryRunMode.
		p.Mode = dryRunMode
	}

	who := auth.CurrentUser(r.Context()).Username
	s.audit(r.Context(), auditEvent{
		Action: "enforce.run", Actor: who, Target: p.Name,
		Severity: map[bool]string{true: "info", false: "notice"}[p.Mode == "report"],
		Detail:   map[string]any{"mode": p.Mode, "dry_run": body.DryRun},
	})

	summary, err := s.runEnforcePolicy(context.WithoutCancel(r.Context()), *p, who)
	if err != nil {
		if strings.Contains(err.Error(), "already running") {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONResponse(w, summary)
}

// resetEnforcePolicyResponse is what POST /api/enforce/policies/{id}/reset
// answers.
type resetEnforcePolicyResponse struct {
	Reset string `json:"reset"`
}

// handleResetEnforcePolicy clears a policy's history, and with it the
// failure counters that stopped it retrying. The button for "I fixed the
// thing that was breaking it, try again".
func (s *Server) handleResetEnforcePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := s.lookupEnforcePolicy(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if err := s.store.ClearEnforceResultsForPolicy(r.Context(), p.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "enforce.reset", Actor: auth.CurrentUser(r.Context()).Username,
		Target: p.Name, Severity: "notice",
	})
	writeJSONResponse(w, resetEnforcePolicyResponse{Reset: p.Name})
}
