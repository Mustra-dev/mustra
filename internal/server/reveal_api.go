package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/reveal"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Reveal: sensitive-data discovery.
//
// A rule says what to look for (patterns), where (roots per OS), on which
// endpoints (computer groups) and how often. The server turns it into one
// job per endpoint and sends it as a command; the agent walks the files,
// runs the patterns, confirms matches with validators, and publishes a
// report with masked snippets. The report lands in Reveal's tables through
// the sensor consumer. Nothing about a file but its path, its size, its
// modification time and a masked fragment ever leaves the endpoint.

const revealDispatchConcurrency = 8

// revealTemplates are the rule sets an operator starts from -- the
// compliance regimes commonly shipped as rule sets, expressed as drafts.
func revealTemplates() []store.RevealRule {
	home := map[string][]string{"linux": {"/home", "/root", "/srv", "/var/www", "/opt"}, "darwin": {"/Users"}, "windows": {`C:\Users`}}
	shared := map[string][]string{"linux": {"/home", "/srv", "/var/www", "/opt", "/etc"}, "darwin": {"/Users", "/etc", "/opt"}, "windows": {`C:\Users`, `C:\inetpub`}}
	base := func(id, name, desc string, patterns []string, roots map[string][]string) store.RevealRule {
		return store.RevealRule{ID: id, Name: name, Description: desc, Kind: "rule", Enabled: false, GroupIDs: []string{},
			Roots: roots, Exclude: []string{}, Extensions: []string{}, MaxSizeBytes: 5 << 20, PatternIDs: patterns,
			CustomPatterns: []proto.RevealPattern{}, MinMatches: 1, IntervalHours: 24, Snippets: true}
	}
	return []store.RevealRule{
		base("template-pci", "PCI DSS — payment card numbers", "Card numbers at rest in documents, spreadsheets, logs and exports. Confirmed by the Luhn check, so a version string with sixteen digits is not a finding.", []string{"credit_card"}, home),
		base("template-hipaa", "HIPAA / PII — identifiers", "Social Security numbers, phone numbers and email addresses in the places people keep documents.", []string{"ssn_us", "phone_us", "email"}, home),
		base("template-gdpr", "GDPR — personal data", "Email addresses, phone numbers and bank account numbers in user data.", []string{"email", "phone_us", "iban"}, home),
		base("template-secrets", "Secrets — keys, tokens and passwords", "Private keys, cloud access keys, GitHub tokens, JWTs and passwords assigned in configuration files. Looks in /etc and web roots as well as home directories.", []string{"private_key", "aws_access_key", "github_token", "jwt", "password_assignment"}, shared),
	}
}

// revealPatternsResponse is what GET /api/reveal/patterns answers.
type revealPatternsResponse struct {
	Patterns []proto.RevealPattern `json:"patterns"`
}

func (s *Server) handleRevealPatterns(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, revealPatternsResponse{Patterns: reveal.Builtin()})
}

// revealTemplatesResponse is what GET /api/reveal/templates answers.
type revealTemplatesResponse struct {
	Templates []store.RevealRule `json:"templates"`
}

func (s *Server) handleRevealTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, revealTemplatesResponse{Templates: revealTemplates()})
}

// revealRulesResponse is what GET /api/reveal/rules answers.
type revealRulesResponse struct {
	Rules []store.RevealRule `json:"rules"`
}

func (s *Server) handleRevealRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListRevealRules(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSONResponse(w, revealRulesResponse{Rules: rules})
}

// validateRevealRule is the server's own check, run before anything is
// stored and again before anything is sent: a rule that cannot compile on
// the server would not compile on the agent either, and the agent is the
// wrong place to find that out.
func validateRevealRule(rule *store.RevealRule) error {
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		return fmt.Errorf("a rule needs a name")
	}
	if len(rule.PatternIDs) == 0 && len(rule.CustomPatterns) == 0 {
		return fmt.Errorf("a rule needs at least one pattern")
	}
	roots := 0
	for os, list := range rule.Roots {
		clean := list[:0]
		for _, p := range list {
			if p = strings.TrimSpace(p); p != "" {
				clean = append(clean, p)
			}
		}
		rule.Roots[os] = clean
		roots += len(clean)
	}
	if roots == 0 {
		return fmt.Errorf("a rule needs at least one root path for some operating system")
	}
	builtin := map[string]bool{}
	for _, p := range reveal.Builtin() {
		builtin[p.ID] = true
	}
	for _, id := range rule.PatternIDs {
		if !builtin[id] {
			return fmt.Errorf("unknown pattern %q", id)
		}
	}
	for i := range rule.CustomPatterns {
		c := &rule.CustomPatterns[i]
		c.Regex = strings.TrimSpace(c.Regex)
		if c.ID == "" {
			c.ID = "custom-" + idgen.New("")
		}
		if c.Name == "" {
			c.Name = c.Regex
		}
		if c.Regex == "" {
			return fmt.Errorf("custom pattern %q has no expression", c.Name)
		}
		if _, err := regexp.Compile(c.Regex); err != nil {
			return fmt.Errorf("custom pattern %q: %v", c.Name, err)
		}
	}
	if rule.MaxSizeBytes <= 0 {
		rule.MaxSizeBytes = 5 << 20
	}
	if rule.MinMatches <= 0 {
		rule.MinMatches = 1
	}
	if rule.IntervalHours <= 0 {
		rule.IntervalHours = 24
	}
	for i, e := range rule.Extensions {
		rule.Extensions[i] = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), "."))
	}
	return nil
}

func (s *Server) handleSaveRevealRule(w http.ResponseWriter, r *http.Request) {
	var rule store.RevealRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rule); err != nil {
		http.Error(w, "invalid rule: "+err.Error(), 400)
		return
	}
	if err := validateRevealRule(&rule); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	if rule.ID == "" || strings.HasPrefix(rule.ID, "template-") {
		rule.ID = idgen.New("rvl-")
		rule.CreatedBy = who
	}
	rule.Kind = "rule"
	if err := s.store.UpsertRevealRule(r.Context(), rule); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "reveal.rule_save", Actor: who, Target: rule.ID, Severity: "notice",
		Detail: map[string]any{"name": rule.Name, "patterns": len(rule.PatternIDs) + len(rule.CustomPatterns), "enabled": rule.Enabled}})
	saved, _ := s.store.GetRevealRule(r.Context(), rule.ID)
	writeJSONResponse(w, saved)
}

func (s *Server) handleDeleteRevealRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteRevealRule(r.Context(), id); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "reveal.rule_delete", Actor: auth.CurrentUser(r.Context()).Username, Target: id, Severity: "notice"})
	w.WriteHeader(204)
}

// runRevealRuleRequest is the body of POST /api/reveal/rules/{id}/run.
type runRevealRuleRequest struct {
	AgentIDs []string `json:"agent_ids"`
}

// runRevealRuleResponse is what POST /api/reveal/rules/{id}/run answers.
type runRevealRuleResponse struct {
	Dispatched int `json:"dispatched"`
	Skipped    int `json:"skipped"` // endpoints the run was meant for and did not reach
}

func (s *Server) handleRunRevealRule(w http.ResponseWriter, r *http.Request) {
	rule, err := s.store.GetRevealRule(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if rule == nil {
		http.NotFound(w, r)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	// An optional list narrows "scan now" to chosen endpoints; without it
	// the rule's own targets apply.
	var req runRevealRuleRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	var only map[string]bool
	if len(req.AgentIDs) > 0 {
		only = map[string]bool{}
		for _, id := range req.AgentIDs {
			only[id] = true
		}
	}
	sent, skipped, err := s.dispatchRevealRule(r.Context(), *rule, only, true)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.announceRevealScan(r.Context(), *rule, sent, skipped)
	s.audit(r.Context(), auditEvent{Action: "reveal.scan", Actor: who, Target: rule.ID, Severity: "notice",
		Detail: map[string]any{"name": rule.Name, "dispatched": sent, "skipped": skipped, "endpoints": req.AgentIDs}})
	writeJSONResponse(w, runRevealRuleResponse{Dispatched: sent, Skipped: skipped})
}

// revealSearchRequest is the body of POST /api/reveal/search.
type revealSearchRequest struct {
	Query string `json:"query" api:"required"`
	Regex bool   `json:"regex"`
	// AgentIDs and GroupIDs choose the endpoints. With neither, the search
	// goes to every online endpoint the caller may act on.
	AgentIDs   []string `json:"agent_ids"`
	GroupIDs   []string `json:"group_ids"`
	Roots      []string `json:"roots"`
	Extensions []string `json:"extensions"`
	MaxSizeMB  int      `json:"max_size_mb"`
}

// revealSearchResponse is what POST /api/reveal/search answers.
type revealSearchResponse struct {
	Dispatched int    `json:"dispatched"`
	RuleID     string `json:"rule_id"`
	Skipped    int    `json:"skipped"` // endpoints the search was meant for and did not reach
}

// handleRevealSearch is the quick search: one string or expression, sent
// now as a throwaway rule. It lives a day. It goes to the endpoints in
// agent_ids and group_ids, or with neither to every online endpoint; the
// action gate narrows either to those the caller may act on.
func (s *Server) handleRevealSearch(w http.ResponseWriter, r *http.Request) {
	var req revealSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	req.Query = strings.TrimSpace(req.Query)
	if len(req.Query) < 3 {
		http.Error(w, "the search needs at least three characters", 400)
		return
	}
	expr := req.Query
	if !req.Regex {
		expr = "(?i)" + regexp.QuoteMeta(req.Query)
	} else if _, err := regexp.Compile(expr); err != nil {
		http.Error(w, "not a valid expression: "+err.Error(), 400)
		return
	}
	roots := map[string][]string{"linux": {"/home", "/root", "/srv", "/var/www", "/opt", "/etc"}, "darwin": {"/Users", "/etc", "/opt"}, "windows": {`C:\Users`}}
	if len(req.Roots) > 0 {
		for os := range roots {
			roots[os] = req.Roots
		}
	}
	who := auth.CurrentUser(r.Context()).Username
	rule := store.RevealRule{ID: idgen.New("quick-"), Name: "Quick search: " + req.Query, Kind: "quick", Enabled: false,
		GroupIDs: req.GroupIDs, Roots: roots, Exclude: []string{}, Extensions: req.Extensions, MaxSizeBytes: int64(req.MaxSizeMB) << 20,
		PatternIDs: []string{}, CustomPatterns: []proto.RevealPattern{{ID: "quick", Name: req.Query, Regex: expr}},
		MinMatches: 1, IntervalHours: 24, Snippets: true, CreatedBy: who}
	if rule.GroupIDs == nil {
		rule.GroupIDs = []string{}
	}
	if rule.Extensions == nil {
		rule.Extensions = []string{}
	}
	if err := validateRevealRule(&rule); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	rule.Kind = "quick"
	if err := s.store.UpsertRevealRule(r.Context(), rule); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	only := map[string]bool{}
	for _, id := range req.AgentIDs {
		only[id] = true
	}
	sent, skipped, err := s.dispatchRevealRule(r.Context(), rule, only, true)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.announceRevealScan(r.Context(), rule, sent, skipped)
	s.audit(r.Context(), auditEvent{Action: "reveal.search", Actor: who, Target: rule.ID, Severity: "notice",
		Detail: map[string]any{"query": req.Query, "regex": req.Regex, "dispatched": sent}})
	writeJSONResponse(w, revealSearchResponse{RuleID: rule.ID, Dispatched: sent, Skipped: skipped})
}

// revealResultsResponse is what GET /api/reveal/results answers.
type revealResultsResponse struct {
	Matches []store.RevealMatch `json:"matches"`
}

func (s *Server) handleRevealResults(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, err := s.store.ListRevealMatches(r.Context(), store.RevealMatchFilter{
		RuleID: q.Get("rule"), AgentID: q.Get("agent"), PatternID: q.Get("pattern"), ConfirmedOnly: q.Get("confirmed") == "1"})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// What a scan found on an endpoint is as sensitive as the endpoint:
	// management rights bound what is read, as they bound what is scanned.
	scope, err := s.endpointScope(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if scope != nil {
		kept := rows[:0:0]
		for _, m := range rows {
			if scope[m.AgentID] {
				kept = append(kept, m)
			}
		}
		rows = kept
	}
	writeJSONResponse(w, revealResultsResponse{Matches: rows})
}

// revealScansResponse is what GET /api/reveal/scans answers.
type revealScansResponse struct {
	Scans []store.RevealScan `json:"scans"`
}

func (s *Server) handleRevealScans(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListRevealScans(r.Context(), r.URL.Query().Get("rule"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	scope, err := s.endpointScope(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if scope != nil {
		kept := rows[:0:0]
		for _, sc := range rows {
			if scope[sc.AgentID] {
				kept = append(kept, sc)
			}
		}
		rows = kept
	}
	writeJSONResponse(w, revealScansResponse{Scans: rows})
}

// revealOverviewResponse is what GET /api/reveal/overview answers.
type revealOverviewResponse struct {
	Endpoints    int                 `json:"endpoints"`
	PatternNames map[string]string   `json:"pattern_names"`
	Rules        int                 `json:"rules"`         // rules, not quick searches
	RulesEnabled int                 `json:"rules_enabled"` // of those, enabled
	Summary      store.RevealSummary `json:"summary"`
}

func (s *Server) handleRevealOverview(w http.ResponseWriter, r *http.Request) {
	summary, err := s.store.RevealSummary(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rules, err := s.store.ListRevealRules(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Quick searches are kept as rules of kind "quick", but the tile reads
	// "Rules enabled n / m" and the Rules tab leaves them out, so both
	// counts do.
	total, enabled := 0, 0
	for _, rl := range rules {
		if rl.Kind != "rule" {
			continue
		}
		total++
		if rl.Enabled {
			enabled++
		}
	}
	names := map[string]string{}
	for _, p := range reveal.Builtin() {
		names[p.ID] = p.Name
	}
	writeJSONResponse(w, revealOverviewResponse{
		Summary: summary, Rules: total, RulesEnabled: enabled, Endpoints: len(agents), PatternNames: names,
	})
}

// ---- dispatch ----

// errRevealAuthorGone: an unattended run whose rule has no active author
// to act as.
var errRevealAuthorGone = errors.New("the rule's author no longer exists or is inactive")

// revealTarget is an endpoint a run sends a scan to, with the roots for
// its OS.
type revealTarget struct {
	agent store.AgentRecord
	roots []string
}

// revealInScope reports whether a run may scan an endpoint: it is in the
// rule's groups (inGroups nil: the rule has none) and among the endpoints
// asked for (only empty: all of them).
func revealInScope(agentID string, inGroups, only map[string]bool) bool {
	return (inGroups == nil || inGroups[agentID]) && (len(only) == 0 || only[agentID])
}

// planRevealRun decides which endpoints of the fleet a run of rule sends a
// scan to. A run is meant for the endpoints asked for (only), or when none
// were, the rule's groups. One of those is skipped when it is outside the
// rule's groups, offline, outside what the run may act on (allowed, nil
// when nothing was narrowed), has no roots for its OS, or -- unless forced
// -- was scanned for this rule recently (last). An endpoint the run is not
// meant for is neither sent nor skipped: skipped is what the run missed.
func planRevealRun(rule store.RevealRule, agents []store.AgentRecord, inGroups, only, allowed map[string]bool,
	last map[string]store.RevealScan, force bool, now time.Time) (send []revealTarget, skipped int) {
	for _, a := range agents {
		meantFor := only[a.AgentID]
		if len(only) == 0 {
			meantFor = inGroups == nil || inGroups[a.AgentID]
		}
		if !meantFor {
			continue
		}
		if !revealInScope(a.AgentID, inGroups, only) || !a.Online || (allowed != nil && !allowed[a.AgentID]) {
			skipped++
			continue
		}
		roots := rule.Roots[a.OS]
		if len(roots) == 0 {
			skipped++
			continue
		}
		if !force {
			if sc, ok := last[a.AgentID]; ok {
				switch {
				case sc.FinishedAt == nil && now.Sub(sc.DispatchedAt) < 2*time.Hour:
					skipped++ // still running, or recently sent and not yet reported
					continue
				case sc.Error != "" && now.Sub(sc.DispatchedAt) < 15*time.Minute:
					// A scan that never ran -- an agent too old for the
					// command, say -- is tried again soon, not next day.
					// The first fleet-wide tick landed before the agents
					// had been updated and would otherwise have parked
					// thirty-eight endpoints for twenty-four hours.
					skipped++
					continue
				case sc.Error == "" && sc.FinishedAt != nil && now.Sub(sc.DispatchedAt) < time.Duration(rule.IntervalHours)*time.Hour:
					skipped++
					continue
				}
			}
		}
		send = append(send, revealTarget{agent: a, roots: roots})
	}
	return send, skipped
}

// dispatchRevealRule sends one job per endpoint planRevealRun picks; an
// endpoint that refuses it is skipped as well. The scan record is written
// before the command, so a report arriving for an unknown scan cannot
// happen and "running" is visible at once.
func (s *Server) dispatchRevealRule(ctx context.Context, rule store.RevealRule, only map[string]bool, force bool) (sent, skipped int, err error) {
	if s.nc == nil {
		return 0, 0, fmt.Errorf("no message bus")
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return 0, 0, err
	}
	var inGroups map[string]bool
	if len(rule.GroupIDs) > 0 {
		inGroups, err = s.agentsInGroups(ctx, rule.GroupIDs)
		if err != nil {
			return 0, 0, err
		}
	}
	// Access control at dispatch, not only when the rule was saved. An
	// unattended run acts with the rule author's management rights (which
	// may have shrunk since) and inside the reveal action group, which
	// binds everyone; a run somebody asked for acts with theirs. A rule
	// whose author is gone does not run.
	pctx := ctx
	if auth.CurrentUser(ctx) == nil {
		var ok bool
		if pctx, ok = s.endpointActionPrincipal(ctx, rule.CreatedBy); !ok {
			return 0, 0, errRevealAuthorGone
		}
	}
	candidates := make([]string, 0, len(agents))
	for _, a := range agents {
		if a.Online && revealInScope(a.AgentID, inGroups, only) {
			candidates = append(candidates, a.AgentID)
		}
	}
	allowedIDs, dropped, err := s.narrowTargets(pctx, "reveal", candidates)
	if err != nil {
		return 0, 0, err
	}
	var allowed map[string]bool
	if dropped > 0 {
		allowed = make(map[string]bool, len(allowedIDs))
		for _, id := range allowedIDs {
			allowed[id] = true
		}
		s.logger.Info("reveal: targets narrowed by access control", "rule", rule.Name, "created_by", rule.CreatedBy, "dropped", dropped, "remaining", len(allowedIDs))
	}
	scans, err := s.store.ListRevealScans(ctx, rule.ID)
	if err != nil {
		return 0, 0, err
	}
	last := map[string]store.RevealScan{}
	for _, sc := range scans {
		last[sc.AgentID] = sc
	}
	patterns := revealPatternsFor(rule)
	if len(patterns) == 0 {
		return 0, 0, fmt.Errorf("the rule has no patterns")
	}

	send, skipped := planRevealRun(rule, agents, inGroups, only, allowed, last, force, time.Now())
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, revealDispatchConcurrency)
	for _, t := range send {
		a, roots := t.agent, t.roots
		job := proto.RevealJob{ScanID: idgen.New("scan-"), RuleID: rule.ID, RuleName: rule.Name, Roots: roots, Exclude: rule.Exclude,
			Extensions: rule.Extensions, MaxSizeBytes: rule.MaxSizeBytes, ModifiedWithinDays: rule.ModifiedWithinDays,
			Patterns: patterns, MinMatches: rule.MinMatches, RequirePairs: rule.RequirePairs,
			MaxFiles: 200000, TimeBudgetSeconds: 900, Snippets: rule.Snippets}
		wg.Add(1)
		go func(a store.AgentRecord, job proto.RevealJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			payload, _ := json.Marshal(proto.AgentCommand{Cmd: "reveal_scan", Reveal: &job})
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			if err := s.store.MarkRevealDispatched(ctx, rule.ID, a.AgentID, job.ScanID); err != nil {
				s.logger.Warn("reveal: could not record dispatch", "rule", rule.Name, "hostname", a.Hostname, "error", err)
			}
			msg, err := s.nc.RequestWithContext(cctx, bnats.Cmd(a.AgentID), payload)
			var res proto.AgentCommandResult
			if err == nil {
				_ = json.Unmarshal(msg.Data, &res)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil || !res.OK {
				skipped++
				detail := res.Error
				if err != nil {
					detail = err.Error()
				}
				// An agent that predates reveal_scan answers "unknown
				// command"; say so where the scans page can see it.
				_ = s.store.RecordRevealReport(ctx, proto.RevealReport{ScanID: job.ScanID, RuleID: rule.ID, AgentID: a.AgentID,
					Started: time.Now().UTC().Format(time.RFC3339), Finished: time.Now().UTC().Format(time.RFC3339), Error: "not started: " + detail})
				return
			}
			sent++
		}(a, job)
	}
	wg.Wait()
	return sent, skipped, nil
}

func revealPatternsFor(rule store.RevealRule) []proto.RevealPattern {
	want := map[string]bool{}
	for _, id := range rule.PatternIDs {
		want[id] = true
	}
	var out []proto.RevealPattern
	for _, p := range reveal.Builtin() {
		if want[p.ID] {
			out = append(out, p)
		}
	}
	return append(out, rule.CustomPatterns...)
}

// recordRevealReport is the consumer's half: a report published by an
// agent as a "reveal" snapshot.
func (s *Server) recordRevealReport(ctx context.Context, snap proto.SensorSnapshot) error {
	var rep proto.RevealReport
	if err := json.Unmarshal(snap.Data, &rep); err != nil {
		return fmt.Errorf("malformed reveal report: %w", err)
	}
	if rep.AgentID == "" {
		rep.AgentID = snap.AgentID
	}
	if rep.AgentID != snap.AgentID {
		return fmt.Errorf("reveal report for %s arrived from %s", rep.AgentID, snap.AgentID)
	}
	if err := s.store.RecordRevealReport(ctx, rep); err != nil {
		return err
	}
	if len(rep.Matches) > 0 {
		s.logger.Info("reveal report", "agent_id", rep.AgentID, "rule", rep.RuleID, "files_matched", rep.FilesMatched, "matches", len(rep.Matches))
	}
	return nil
}

// revealSchedulerLoop re-runs every enabled rule on its interval and
// retires day-old quick searches.
func (s *Server) revealSchedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	lastPurge := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		rules, err := s.store.ListRevealRules(ctx)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if rule.Kind != "rule" || !rule.Enabled {
				continue
			}
			sent, skipped, err := s.dispatchRevealRule(ctx, rule, nil, false)
			if errors.Is(err, errRevealAuthorGone) {
				// Paused rather than warned about every minute: it runs
				// again once somebody with an account saves it.
				off := rule
				off.Enabled = false
				if uerr := s.store.UpsertRevealRule(ctx, off); uerr != nil {
					s.logger.Warn("reveal: pausing rule failed", "rule", rule.Name, "error", uerr)
				}
				s.logger.Warn("reveal: rule paused, its author no longer exists or is inactive", "rule", rule.Name, "created_by", rule.CreatedBy)
				s.audit(ctx, auditEvent{Action: "reveal_rule.paused", Actor: "system", Target: rule.Name, Severity: "warning",
					Detail: map[string]any{"id": rule.ID, "created_by": rule.CreatedBy,
						"reason": "the rule's author no longer exists or is inactive; save it again under an active account"}})
			} else if err != nil {
				s.logger.Warn("reveal: scheduled dispatch failed", "rule", rule.Name, "error", err)
			} else if sent > 0 {
				s.logger.Info("reveal: scheduled scans dispatched", "rule", rule.Name, "endpoints", sent)
				s.announceRevealScan(ctx, rule, sent, skipped)
			}
		}
		if time.Since(lastPurge) > time.Hour {
			lastPurge = time.Now()
			if n, err := s.store.PurgeQuickSearches(ctx, 24*time.Hour); err == nil && n > 0 {
				s.logger.Info("reveal: retired quick searches", "count", n)
			}
		}
	}
}
