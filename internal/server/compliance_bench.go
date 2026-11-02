package server

// Hardening scores: each endpoint is matched to the benchmark written for
// its operating system and version (an imported CIS policy, by its name),
// scanned with it, and scored. The score weighs each passed or failed
// check by severity; checks that could not be evaluated ("unknown") and
// checks under an exception ("excepted") are left out rather than counted
// either way.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// "daily": scan every online endpoint with its benchmark once a day.
const settingComplianceAutoScan = "compliance.auto_scan"

var benchmarkName = regexp.MustCompile(`(?i)\b(Debian|Ubuntu|Windows Server|Windows|macOS|Rocky Linux|AlmaLinux|Red Hat Enterprise Linux|RHEL|Fedora)\s+(\d+(?:\.\d+)?)`)

func normalizeFamily(f string) string {
	switch f = strings.ToLower(f); f {
	case "rhel", "red hat enterprise linux":
		return "rhel"
	case "rocky linux":
		return "rocky"
	case "almalinux":
		return "alma"
	}
	return f
}

// policyBenchmark reads which OS and version a policy is written for from
// its name ("CIS Debian 13", "CIS Windows Server 2025").
func policyBenchmark(name string) (family string, version float64, ok bool) {
	m := benchmarkName.FindStringSubmatch(name)
	if m == nil {
		return "", 0, false
	}
	v, err := strconv.ParseFloat(m[2], 64)
	return normalizeFamily(m[1]), v, err == nil
}

// agentBenchmark says which benchmark family and version fit an endpoint.
func agentBenchmark(a store.AgentRecord) (family string, version float64) {
	num := func(s string, majorOnly bool) float64 {
		m := regexp.MustCompile(`\d+(?:\.\d+)?`).FindString(s)
		v, _ := strconv.ParseFloat(m, 64)
		if majorOnly {
			v = math.Floor(v)
		}
		return v
	}
	p := strings.ToLower(a.Platform)
	switch a.OS {
	case "linux":
		switch p {
		case "debian", "raspbian":
			return "debian", num(a.PlatformVersion, true)
		case "ubuntu":
			return "ubuntu", num(a.PlatformVersion, false)
		case "rhel", "centos", "rocky", "almalinux", "fedora":
			family := map[string]string{"rhel": "rhel", "centos": "rhel", "rocky": "rocky", "almalinux": "alma", "fedora": "fedora"}[p]
			return family, num(a.PlatformVersion, true)
		}
	case "windows":
		if m := regexp.MustCompile(`Server (\d{4})`).FindStringSubmatch(a.Platform); m != nil {
			return "windows server", num(m[1], false)
		}
		if m := regexp.MustCompile(`Windows (\d+)`).FindStringSubmatch(a.Platform); m != nil {
			return "windows", num(m[1], false)
		}
	case "darwin":
		return "macos", num(a.PlatformVersion, true)
	}
	return "", 0
}

// pickBenchmark chooses the policy for an endpoint: the same OS family and
// version, else the newest benchmark not newer than the endpoint, else the
// oldest one newer. exact is false for those approximations.
func pickBenchmark(a store.AgentRecord, policies []store.CompliancePolicy) (store.CompliancePolicy, bool, bool) {
	family, version := agentBenchmark(a)
	if family == "" {
		return store.CompliancePolicy{}, false, false
	}
	type cand struct {
		p store.CompliancePolicy
		v float64
	}
	var cands []cand
	for _, p := range policies {
		if f, v, ok := policyBenchmark(p.Name); ok && f == family {
			cands = append(cands, cand{p, v})
		}
	}
	if len(cands) == 0 {
		return store.CompliancePolicy{}, false, false
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].v < cands[j].v })
	var below *cand
	for i := range cands {
		if cands[i].v == version {
			return cands[i].p, true, true
		}
		if cands[i].v < version {
			below = &cands[i]
		}
	}
	if below != nil {
		return below.p, false, true
	}
	return cands[0].p, false, true
}

var severityWeight = map[string]float64{"critical": 4, "high": 3, "medium": 2, "low": 1}

// hardeningScore: severity-weighted share of evaluated checks that pass.
func hardeningScore(results []store.ComplianceResult) (score float64, pass, fail, unknown int) {
	var got, total float64
	for _, r := range results {
		w := severityWeight[strings.ToLower(r.Severity)]
		if w == 0 {
			w = 1
		}
		switch r.State {
		case "pass":
			pass++
			got += w
			total += w
		case "fail":
			fail++
			total += w
		case stateExcepted:
		default:
			unknown++
		}
	}
	if total == 0 {
		return 0, pass, fail, unknown
	}
	return math.Round(1000*got/total) / 10, pass, fail, unknown
}

// complianceDrift lists the checks that passed on the previous scan and
// fail on this one, exceptions applied to both, with the score before and
// after. A first scan has nothing to drift from.
func complianceDrift(prev, now []store.ComplianceResult, x exceptionSet) (regressed []string, before, after float64) {
	if len(prev) == 0 {
		return nil, 0, 0
	}
	p := append([]store.ComplianceResult(nil), prev...)
	n := append([]store.ComplianceResult(nil), now...)
	x.apply(p)
	x.apply(n)
	was := map[string]string{}
	for _, r := range p {
		was[r.CheckID] = r.State
	}
	for _, r := range n {
		if r.State == "fail" && was[r.CheckID] == "pass" {
			regressed = append(regressed, r.Title)
		}
	}
	before, _, _, _ = hardeningScore(p)
	after, _, _, _ = hardeningScore(n)
	return regressed, before, after
}

// notifyComplianceDrift raises one notification per endpoint and scan when
// settings that were compliant stop being so: hardening that quietly
// wears off is the thing a weekly glance at the score misses.
func (s *Server) notifyComplianceDrift(ctx context.Context, hostname, policy string, prev, now []store.ComplianceResult, x exceptionSet) {
	regressed, before, after := complianceDrift(prev, now, x)
	if len(regressed) == 0 {
		return
	}
	shown := regressed
	if len(shown) > 5 {
		shown = shown[:5]
	}
	detail := fmt.Sprintf("Score %.1f%% → %.1f%%. Now failing: %s", before, after, strings.Join(shown, "; "))
	if more := len(regressed) - len(shown); more > 0 {
		detail += fmt.Sprintf(" and %d more", more)
	}
	s.notify(ctx, "warning", "Comply",
		fmt.Sprintf("Hardening drift on %s: %d check(s) no longer pass", hostname, len(regressed)),
		safeTruncate(detail, 600), "/compliance")
	s.logger.Info("compliance drift", "hostname", hostname, "policy", policy, "regressed", len(regressed))
}

func (s *Server) recordScore(ctx context.Context, agentID, policyID string, x exceptionSet) {
	results, err := s.store.ComplianceResultsFor(ctx, agentID, policyID)
	if err != nil || len(results) == 0 {
		return
	}
	s.storeScore(ctx, agentID, policyID, results, x)
}

func (s *Server) storeScore(ctx context.Context, agentID, policyID string, results []store.ComplianceResult, x exceptionSet) {
	x.apply(results)
	score, pass, fail, unknown := hardeningScore(results)
	if pass+fail == 0 {
		return
	}
	_ = s.store.RecordComplianceScore(ctx, store.ComplianceScore{AgentID: agentID, PolicyID: policyID, Score: score, Pass: pass, Fail: fail, Unknown: unknown})
}

// scanBenchmarks runs each target endpoint's own benchmark; only is the
// set of agent IDs to consider (nil: every online endpoint), and maxAge
// skips endpoints scanned more recently than that.
func (s *Server) scanBenchmarks(ctx context.Context, only map[string]bool, maxAge time.Duration) (map[string]int, error) {
	policies, err := s.store.ListCompliancePolicies(ctx)
	if err != nil {
		return nil, err
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	last := map[string]time.Time{}
	if res, err := s.store.ListComplianceResults(ctx); err == nil {
		for _, r := range res {
			k := r.AgentID + "|" + r.PolicyID
			if r.CheckedAt.After(last[k]) {
				last[k] = r.CheckedAt
			}
		}
	}
	byPolicy := map[string][]store.AgentRecord{}
	pol := map[string]store.CompliancePolicy{}
	for _, a := range agents {
		if !a.Online || !a.Managed || (only != nil && !only[a.AgentID]) {
			continue
		}
		p, _, ok := pickBenchmark(a, policies)
		if !ok || (maxAge > 0 && time.Since(last[a.AgentID+"|"+p.ID]) < maxAge) {
			continue
		}
		byPolicy[p.ID] = append(byPolicy[p.ID], a)
		pol[p.ID] = p
	}
	counts := map[string]int{}
	for id, targets := range byPolicy {
		// The list carries no checks; load the policy itself.
		full, err := s.store.GetCompliancePolicy(ctx, id)
		if err != nil || full == nil {
			continue
		}
		var checks []proto.ComplianceCheck
		if json.Unmarshal(full.Checks, &checks) != nil || len(checks) == 0 {
			continue
		}
		counts[full.Name] = len(targets)
		go s.runCompliance(context.WithoutCancel(ctx), *full, checks, targets)
	}
	return counts, nil
}

func (s *Server) complianceScanLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if v, _ := s.store.GetSetting(ctx, settingComplianceAutoScan); v == "daily" {
			if _, err := s.scanBenchmarks(ctx, nil, 23*time.Hour); err != nil {
				s.logger.Warn("scheduled benchmark scan failed", "error", err)
			}
		}
	}
}

// scanBenchmarksRequest is the body of POST /api/compliance/scan.
type scanBenchmarksRequest struct {
	AgentIDs []string `json:"agent_ids"`
}

// scanBenchmarksResponse is what POST /api/compliance/scan answers.
type scanBenchmarksResponse struct {
	Benchmarks map[string]int `json:"benchmarks"`
}

// POST /api/compliance/scan {"agent_ids":[…]} — empty: the whole fleet.
func (s *Server) handleScanBenchmarks(w http.ResponseWriter, r *http.Request) {
	var body scanBenchmarksRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	var only map[string]bool
	if len(body.AgentIDs) > 0 {
		only = map[string]bool{}
		for _, id := range body.AgentIDs {
			only[id] = true
		}
	}
	counts, err := s.scanBenchmarks(r.Context(), only, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	s.audit(r.Context(), auditEvent{Action: "compliance.scan", Actor: who, Target: "matching benchmarks", Detail: map[string]any{"benchmarks": counts}})
	writeJSONResponse(w, scanBenchmarksResponse{Benchmarks: counts})
}

// complianceSettingsRequest is the body of POST /api/compliance/settings.
type complianceSettingsRequest struct {
	AutoScan string `json:"auto_scan"`
}

// POST /api/compliance/settings {"auto_scan":"daily"|""}
func (s *Server) handleComplianceSettings(w http.ResponseWriter, r *http.Request) {
	var body complianceSettingsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body); err != nil || (body.AutoScan != "" && body.AutoScan != "daily") {
		http.Error(w, `auto_scan must be "daily" or empty`, http.StatusBadRequest)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	if err := s.store.SetSetting(r.Context(), settingComplianceAutoScan, body.AutoScan, who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "settings.compliance", Actor: who, Target: "benchmark scans", Severity: "notice", Detail: map[string]any{"auto_scan": body.AutoScan}})
	w.WriteHeader(http.StatusNoContent)
}

type endpointScore struct {
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Platform  string    `json:"platform"`
	PolicyID  string    `json:"policy_id,omitempty"`
	Benchmark string    `json:"benchmark,omitempty"`
	Exact     bool      `json:"exact"`
	Score     *float64  `json:"score,omitempty"`
	Pass      int       `json:"pass"`
	Fail      int       `json:"fail"`
	Unknown   int       `json:"unknown"`
	Excepted  int       `json:"excepted"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Trend     []float64 `json:"trend"`
}

// complianceScoresResponse is what GET /api/compliance/scores answers.
// fleet_score is there only once an endpoint has been scored.
type complianceScoresResponse struct {
	AutoScan   string          `json:"auto_scan"`
	Endpoints  []endpointScore `json:"endpoints"`
	FleetScore *float64        `json:"fleet_score,omitempty"`
	Scored     int             `json:"scored"`
}

// GET /api/compliance/scores[?agent_id=]
func (s *Server) handleComplianceScores(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policies, err := s.store.ListCompliancePolicies(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	results, _ := s.store.ListComplianceResults(ctx)
	s.loadExceptions(ctx).apply(results)
	byKey := map[string][]store.ComplianceResult{}
	for _, res := range results {
		byKey[res.AgentID+"|"+res.PolicyID] = append(byKey[res.AgentID+"|"+res.PolicyID], res)
	}
	history, _ := s.store.ComplianceScoreHistory(ctx, 30)
	trend := map[string][]float64{}
	for _, h := range history {
		trend[h.AgentID+"|"+h.PolicyID] = append(trend[h.AgentID+"|"+h.PolicyID], h.Score)
	}
	want := r.URL.Query().Get("agent_id")
	out := []endpointScore{}
	var sum float64
	scored := 0
	for _, a := range agents {
		if (want != "" && a.AgentID != want) || !a.Managed {
			continue
		}
		e := endpointScore{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Platform: a.Platform, Trend: []float64{}}
		if p, exact, ok := pickBenchmark(a, policies); ok {
			e.PolicyID, e.Benchmark, e.Exact = p.ID, p.Name, exact
			if res := byKey[a.AgentID+"|"+p.ID]; len(res) > 0 {
				score, pass, fail, unknown := hardeningScore(res)
				e.Pass, e.Fail, e.Unknown = pass, fail, unknown
				for _, x := range res {
					if x.CheckedAt.After(e.CheckedAt) {
						e.CheckedAt = x.CheckedAt
					}
					if x.State == stateExcepted {
						e.Excepted++
					}
				}
				if pass+fail > 0 {
					e.Score = &score
					sum += score
					scored++
				}
			}
			if t := trend[a.AgentID+"|"+p.ID]; t != nil {
				e.Trend = t
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := -1.0, -1.0
		if out[i].Score != nil {
			si = *out[i].Score
		}
		if out[j].Score != nil {
			sj = *out[j].Score
		}
		if si != sj {
			return si < sj
		}
		return strings.ToLower(out[i].Hostname) < strings.ToLower(out[j].Hostname)
	})
	resp := complianceScoresResponse{Endpoints: out, Scored: scored}
	if scored > 0 {
		fleet := math.Round(10*sum/float64(scored)) / 10
		resp.FleetScore = &fleet
	}
	auto, _ := s.store.GetSetting(ctx, settingComplianceAutoScan)
	resp.AutoScan = auto
	writeJSONResponse(w, resp)
}

// GET /api/compliance/report.csv[?agent_id=][&policy_id=] — every result,
// worst first, for an endpoint or the whole fleet.
func (s *Server) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, policyID := r.URL.Query().Get("agent_id"), r.URL.Query().Get("policy_id")
	var results []store.ComplianceResult
	var err error
	if agentID != "" {
		results, err = s.store.ComplianceResultsFor(ctx, agentID, policyID)
	} else {
		results, err = s.store.ListComplianceResults(ctx)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.loadExceptions(ctx).apply(results)
	names := map[string]string{}
	if ps, err := s.store.ListCompliancePolicies(ctx); err == nil {
		for _, p := range ps {
			names[p.ID] = p.Name
		}
	}
	name := "fleet"
	if agentID != "" && len(results) > 0 {
		name = results[0].Hostname
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="hardening-%s-%s.csv"`, strings.Map(func(c rune) rune {
		if strings.ContainsRune(`"\/:*?<>|`, c) {
			return '_'
		}
		return c
	}, name), time.Now().UTC().Format("2006-01-02")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"endpoint", "benchmark", "check", "title", "severity", "state", "detail", "checked_at"})
	for _, res := range results {
		if policyID != "" && res.PolicyID != policyID {
			continue
		}
		_ = cw.Write([]string{res.Hostname, names[res.PolicyID], res.CheckID, csvSafe(res.Title), res.Severity, res.State, csvSafe(res.Detail), res.CheckedAt.UTC().Format(time.RFC3339)})
	}
	cw.Flush()
}

// csvSafe defuses spreadsheet formulas in text that came from endpoints.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
