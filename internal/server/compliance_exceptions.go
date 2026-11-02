package server

// Hardening exceptions: a benchmark check the operator has decided not to
// apply, for the whole fleet or one group, with a reason. Some CIS checks
// conflict with how a site works (root SSH by key for fleet tooling, a
// default-deny firewall on a hypervisor) or need a reinstall (separate
// partitions); without exceptions those fail forever and the score can
// never say "done". The stored result keeps its real state; an exception
// only marks it "excepted", which the score leaves out.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const stateExcepted = "excepted"

// exceptionKey matches a check by title across benchmark versions, which
// word the same check identically but number it differently.
func exceptionKey(title string) string {
	return strings.TrimRight(strings.Join(strings.Fields(strings.ToLower(title)), " "), ".")
}

// exceptionSet answers "is this check excepted on this endpoint".
type exceptionSet struct {
	fleet   map[string]bool            // key → excepted everywhere
	byAgent map[string]map[string]bool // agent → key → excepted
}

func (x exceptionSet) excepted(agentID, title string) bool {
	k := exceptionKey(title)
	return x.fleet[k] || x.byAgent[agentID][k]
}

// apply marks excepted results in place.
func (x exceptionSet) apply(results []store.ComplianceResult) {
	for i := range results {
		if x.excepted(results[i].AgentID, results[i].Title) {
			results[i].State = stateExcepted
		}
	}
}

// buildExceptionSet resolves exceptions against group membership. Expired
// exceptions are skipped; members maps a group ID to its agents, and a
// group missing from it (deleted) matches nobody.
func buildExceptionSet(excs []store.ComplianceException, members map[string]map[string]bool, now time.Time) exceptionSet {
	x := exceptionSet{fleet: map[string]bool{}, byAgent: map[string]map[string]bool{}}
	for _, e := range excs {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue
		}
		k := exceptionKey(e.Title)
		if e.GroupID == "" {
			x.fleet[k] = true
			continue
		}
		for id := range members[e.GroupID] {
			if x.byAgent[id] == nil {
				x.byAgent[id] = map[string]bool{}
			}
			x.byAgent[id][k] = true
		}
	}
	return x
}

func (s *Server) loadExceptions(ctx context.Context) exceptionSet {
	excs, err := s.store.ListComplianceExceptions(ctx)
	if err != nil {
		s.logger.Warn("compliance exceptions unavailable", "error", err)
		return exceptionSet{}
	}
	members := map[string]map[string]bool{}
	for _, e := range excs {
		if e.GroupID == "" || members[e.GroupID] != nil {
			continue
		}
		// agentsInGroups returns an empty set for a deleted group, so its
		// exceptions apply to nobody rather than everybody.
		set, err := s.agentsInGroups(ctx, []string{e.GroupID})
		if err != nil {
			s.logger.Warn("compliance exception group unavailable", "group", e.GroupID, "error", err)
			set = map[string]bool{}
		}
		members[e.GroupID] = set
	}
	return buildExceptionSet(excs, members, time.Now())
}

// rescoreAll records today's score for every endpoint and benchmark with
// results, so adding or removing an exception shows in the trend at once
// rather than after the next scan.
func (s *Server) rescoreAll(ctx context.Context) {
	results, err := s.store.ListComplianceResults(ctx)
	if err != nil {
		return
	}
	x := s.loadExceptions(ctx)
	byKey := map[[2]string][]store.ComplianceResult{}
	for _, r := range results {
		k := [2]string{r.AgentID, r.PolicyID}
		byKey[k] = append(byKey[k], r)
	}
	for k, res := range byKey {
		s.storeScore(ctx, k[0], k[1], res, x)
	}
}

// listComplianceExceptionsResponse is what GET /api/compliance/exceptions
// answers.
type listComplianceExceptionsResponse struct {
	Exceptions []store.ComplianceException `json:"exceptions"`
}

// GET /api/compliance/exceptions
func (s *Server) handleListComplianceExceptions(w http.ResponseWriter, r *http.Request) {
	excs, err := s.store.ListComplianceExceptions(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listComplianceExceptionsResponse{Exceptions: excs})
}

// createComplianceExceptionRequest is the body of POST /api/compliance/exceptions.
type createComplianceExceptionRequest struct {
	Title   string `json:"title" api:"required"`
	GroupID string `json:"group_id"`
	Reason  string `json:"reason" api:"required"`
	Expires string `json:"expires"`
}

// POST /api/compliance/exceptions {"title","group_id","reason","expires"}
// expires is a date (2027-01-31) or empty for no end.
func (s *Server) handleCreateComplianceException(w http.ResponseWriter, r *http.Request) {
	var body createComplianceExceptionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	body.Title, body.Reason = strings.TrimSpace(body.Title), strings.TrimSpace(body.Reason)
	if body.Title == "" || len(body.Title) > 500 {
		http.Error(w, "title is required (the check's title, as the benchmark words it)", http.StatusBadRequest)
		return
	}
	// A reason is the point: an exception nobody can explain later is just
	// a hidden failure.
	if body.Reason == "" || len(body.Reason) > 2000 {
		http.Error(w, "reason is required", http.StatusBadRequest)
		return
	}
	e := store.ComplianceException{ID: idgen.New("cex-"), Title: body.Title, GroupID: body.GroupID, Reason: body.Reason,
		CreatedBy: auth.CurrentUser(r.Context()).Username}
	if body.Expires != "" {
		t, err := time.Parse("2006-01-02", body.Expires)
		if err != nil {
			http.Error(w, "expires must be a date like 2027-01-31", http.StatusBadRequest)
			return
		}
		t = t.Add(24 * time.Hour) // through the end of that day
		if !t.After(time.Now()) {
			http.Error(w, "expires is in the past", http.StatusBadRequest)
			return
		}
		e.ExpiresAt = &t
	}
	if e.GroupID != "" {
		g, err := s.store.GetComputerGroup(r.Context(), e.GroupID)
		if err != nil || g == nil {
			http.Error(w, "no such group", http.StatusBadRequest)
			return
		}
	}
	e, err := s.store.CreateComplianceException(r.Context(), e)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scope := "every endpoint"
	if e.GroupID != "" {
		scope = "group " + e.GroupID
	}
	s.audit(r.Context(), auditEvent{Action: "compliance.exception.create", Actor: e.CreatedBy, Target: e.Title, Severity: "notice",
		Detail: map[string]any{"id": e.ID, "scope": scope, "reason": e.Reason, "expires": body.Expires}})
	go s.rescoreAll(context.WithoutCancel(r.Context()))
	writeJSONResponse(w, e)
}

// DELETE /api/compliance/exceptions/{id}
func (s *Server) handleDeleteComplianceException(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.DeleteComplianceException(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if e == nil {
		http.Error(w, "no such exception", http.StatusNotFound)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "compliance.exception.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: e.Title, Severity: "notice", Detail: map[string]any{"id": e.ID, "group_id": e.GroupID, "reason": e.Reason}})
	go s.rescoreAll(context.WithoutCancel(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}
