package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Compliance: run a benchmark against the fleet and show what fails.
//
// mustra ships a short starter policy and reads Wazuh's published SCA
// policies, which is where the real CIS content lives. Those files are
// imported by the operator rather than bundled here — Wazuh is GPLv2 and
// this project is AGPL-3.0, and redistributing their content would raise a
// licensing question that importing simply doesn't.

const starterPolicyID = "builtin-linux-baseline"

// ensureStarterPolicy seeds the built-in policy, so the module has
// something to run on first open rather than an empty page and a manual,
// and rewrites it when this release's definition differs: it is not
// editable, so the stored copy is only ever an older version of this one.
func (s *Server) ensureStarterPolicy(ctx context.Context) {
	checks, err := json.Marshal(starterLinuxPolicy)
	if err != nil {
		return
	}
	existing, err := s.store.GetCompliancePolicy(ctx, starterPolicyID)
	if err == nil && existing != nil {
		var stored []proto.ComplianceCheck
		if json.Unmarshal(existing.Checks, &stored) == nil {
			if again, err := json.Marshal(stored); err == nil && string(again) == string(checks) {
				return
			}
		}
	}
	if err := s.store.UpsertCompliancePolicy(ctx, store.CompliancePolicy{
		ID: starterPolicyID, Name: "Linux baseline (built in)", OS: "linux",
		Source: "builtin", Checks: checks, CreatedBy: "mustra",
	}); err != nil {
		s.logger.Warn("seeding the starter compliance policy failed", "error", err)
	}
}

// listPoliciesResponse is what GET /api/compliance/policies answers.
type listPoliciesResponse struct {
	Policies []store.CompliancePolicy `json:"policies"`
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	s.ensureStarterPolicy(r.Context())
	policies, err := s.store.ListCompliancePolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policies == nil {
		policies = []store.CompliancePolicy{}
	}
	writeJSONResponse(w, listPoliciesResponse{Policies: policies})
}

// complianceResultsResponse is what GET /api/compliance/results answers.
type complianceResultsResponse struct {
	Checks             []map[string]any         `json:"checks"`
	EndpointsReporting int                      `json:"endpoints_reporting"`
	Results            []store.ComplianceResult `json:"results"`
	States             map[string]int           `json:"states"`
}

func (s *Server) handleComplianceResults(w http.ResponseWriter, r *http.Request) {
	results, err := s.store.ListComplianceResults(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []store.ComplianceResult{}
	}
	s.loadExceptions(r.Context()).apply(results)

	// Counts by state, and per-check failure counts — the two summaries
	// worth having without scrolling: how bad is it, and which check is
	// failing most widely.
	states := map[string]int{"pass": 0, "fail": 0, "unknown": 0, stateExcepted: 0}
	byCheck := map[string]map[string]any{}
	hosts := map[string]bool{}
	for _, r := range results {
		states[r.State]++
		hosts[r.AgentID] = true
		c, ok := byCheck[r.CheckID]
		if !ok {
			c = map[string]any{"check_id": r.CheckID, "title": r.Title,
				"severity": r.Severity, "fail": 0, "pass": 0, "unknown": 0, stateExcepted: 0}
			byCheck[r.CheckID] = c
		}
		c[r.State] = c[r.State].(int) + 1
	}
	checks := make([]map[string]any, 0, len(byCheck))
	for _, c := range byCheck {
		checks = append(checks, c)
	}

	writeJSONResponse(w, complianceResultsResponse{
		Results: results, States: states, Checks: checks,
		EndpointsReporting: len(hosts),
	})
}

// runComplianceResponse is what POST /api/compliance/policies/{id}/run
// answers.
type runComplianceResponse struct {
	Checks    int    `json:"checks"`
	Endpoints int    `json:"endpoints"`
	Policy    string `json:"policy"`
}

// handleRunCompliance evaluates a policy across the fleet. Runs in the
// background: a policy with shell-based rules against thirty endpoints is
// minutes of work.
func (s *Server) handleRunCompliance(w http.ResponseWriter, r *http.Request) {
	policyID := r.PathValue("id")
	policy, err := s.store.GetCompliancePolicy(r.Context(), policyID)
	if err != nil || policy == nil {
		http.Error(w, "no such policy", http.StatusNotFound)
		return
	}
	var checks []proto.ComplianceCheck
	if err := json.Unmarshal(policy.Checks, &checks); err != nil || len(checks) == 0 {
		http.Error(w, "that policy has no usable checks", http.StatusBadRequest)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// A benchmark written for one OS version runs where it is the
	// endpoint's matching benchmark ("CIS Debian 13" not on Ubuntu or
	// Debian 12); a general policy runs on its whole platform.
	policies, _ := s.store.ListCompliancePolicies(r.Context())
	_, _, isBenchmark := policyBenchmark(policy.Name)
	var targets []store.AgentRecord
	for _, a := range agents {
		if !a.Online {
			continue
		}
		if isBenchmark {
			if p, _, ok := pickBenchmark(a, policies); !ok || p.ID != policy.ID {
				continue
			}
		} else if policy.OS != "" && a.OS != policy.OS {
			continue
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		http.Error(w, "no online endpoint matches this policy's platform", http.StatusBadRequest)
		return
	}

	who := auth.CurrentUser(r.Context()).Username
	s.logger.Info("compliance run starting", "policy", policy.Name,
		"checks", len(checks), "endpoints", len(targets), "by", who)
	s.audit(r.Context(), auditEvent{
		Action: "compliance.run", Actor: who, Target: policy.Name,
		Detail: map[string]any{"checks": len(checks), "endpoints": len(targets)},
	})
	go s.runCompliance(context.WithoutCancel(r.Context()), *policy, checks, targets)

	writeJSONResponse(w, runComplianceResponse{
		Policy: policy.Name, Checks: len(checks), Endpoints: len(targets),
	})
}

func (s *Server) runCompliance(ctx context.Context, policy store.CompliancePolicy,
	checks []proto.ComplianceCheck, targets []store.AgentRecord) {

	exceptions := s.loadExceptions(ctx)
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(target store.AgentRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			payload, err := json.Marshal(proto.AgentCommand{Cmd: "run_compliance", Checks: checks})
			if err != nil {
				return
			}
			// Generous: every rule may shell out, and the agent bounds each
			// command at 20 seconds.
			rctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()
			msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(target.AgentID), payload)
			if err != nil {
				s.logger.Warn("compliance run failed on endpoint",
					"hostname", target.Hostname, "error", err)
				return
			}
			var result proto.AgentCommandResult
			if err := json.Unmarshal(msg.Data, &result); err != nil {
				s.logger.Warn("compliance reply was unreadable",
					"hostname", target.Hostname, "error", err)
				return
			}
			if !result.OK {
				// Discarding this silently is how a run "completes" in five
				// milliseconds having stored nothing — which is exactly what
				// happened when the fleet was a version behind and every
				// agent answered "unknown command".
				s.logger.Warn("endpoint refused the compliance run",
					"hostname", target.Hostname, "reason", result.Error)
				return
			}

			rows := make([]store.ComplianceResult, 0, len(result.Results))
			byID := map[string]proto.ComplianceCheck{}
			for _, c := range checks {
				byID[c.ID] = c
			}
			for _, res := range result.Results {
				rows = append(rows, store.ComplianceResult{
					AgentID: target.AgentID, PolicyID: policy.ID, CheckID: res.ID,
					Title: byID[res.ID].Title, Severity: byID[res.ID].Severity,
					State: res.State, Detail: res.Detail,
				})
			}
			prev, _ := s.store.ComplianceResultsFor(ctx, target.AgentID, policy.ID)
			if err := s.store.ReplaceComplianceResults(ctx, target.AgentID, policy.ID, rows); err != nil {
				s.logger.Warn("storing compliance results failed",
					"hostname", target.Hostname, "error", err)
				return
			}
			s.recordScore(ctx, target.AgentID, policy.ID, exceptions)
			s.notifyComplianceDrift(ctx, target.Hostname, policy.Name, prev, rows, exceptions)
		}(target)
	}
	wg.Wait()
	stored := 0
	if rows, err := s.store.ListComplianceResults(ctx); err == nil {
		seen := map[string]bool{}
		for _, r := range rows {
			if r.PolicyID == policy.ID {
				seen[r.AgentID] = true
			}
		}
		stored = len(seen)
	}
	// Reporting how many endpoints actually produced results, not just how
	// many were asked: a run that reached nobody should not read the same
	// as one that reached everybody.
	s.logger.Info("compliance run complete", "policy", policy.Name,
		"endpoints_targeted", len(targets), "endpoints_with_results", stored)
}

// importPolicyResponse is what POST /api/compliance/import answers.
type importPolicyResponse struct {
	Checks   int    `json:"checks"`
	PolicyID string `json:"policy_id"`
}

// handleImportPolicy accepts a Wazuh SCA policy file. Importing rather
// than bundling keeps someone else's GPLv2 content out of this AGPL-3.0
// repository while still letting their benchmark work here.
func (s *Server) handleImportPolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "could not read the policy", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Imported policy"
	}

	checks, err := parseSCAPolicy(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(checks) == 0 {
		http.Error(w, "no checks found in that file", http.StatusBadRequest)
		return
	}
	encoded, err := json.Marshal(checks)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The platform matters: a run only targets endpoints whose OS matches,
	// and a Windows benchmark aimed at Linux hosts would produce hundreds
	// of unknowns that look like a broken engine rather than a mis-scoped
	// policy. Taken from the request when given, inferred from the content
	// otherwise.
	osTarget := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("os")))
	if osTarget == "" {
		osTarget = inferPolicyOS(name, checks)
	}
	policy := store.CompliancePolicy{
		ID: "imported-" + slugify(name), Name: name, OS: osTarget, Source: "imported",
		Checks: encoded, CreatedBy: auth.CurrentUser(r.Context()).Username,
	}
	if err := s.store.UpsertCompliancePolicy(r.Context(), policy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("compliance policy imported", "name", name, "checks", len(checks),
		"by", auth.CurrentUser(r.Context()).Username)
	s.audit(r.Context(), auditEvent{
		Action: "compliance.import", Actor: auth.CurrentUser(r.Context()).Username,
		Target: name, Severity: "notice",
		Detail: map[string]any{"checks": len(checks), "os": osTarget},
	})
	writeJSONResponse(w, importPolicyResponse{PolicyID: policy.ID, Checks: len(checks)})
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") == starterPolicyID {
		http.Error(w, "the built-in policy can't be deleted", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteCompliancePolicy(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// inferPolicyOS guesses the platform from the policy's own content. A
// registry rule can only mean Windows; a name is a weaker signal but a
// useful one when the rules are all shell commands that would run
// anywhere.
func inferPolicyOS(name string, checks []proto.ComplianceCheck) string {
	registry := 0
	for _, c := range checks {
		for _, rule := range c.Rules {
			if strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(rule), "not "), "r:") {
				registry++
			}
		}
	}
	if registry > 0 {
		return "windows"
	}
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "macos"), strings.Contains(lower, "apple"), strings.Contains(lower, "darwin"):
		return "darwin"
	case strings.Contains(lower, "windows"), strings.Contains(lower, "win"):
		return "windows"
	default:
		return "linux"
	}
}

func slugify(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '.':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "policy"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
