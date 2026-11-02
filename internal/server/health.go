package server

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Endpoint health and risk scoring.
//
// Two scores, deliberately separate because they answer different
// questions. Health asks "is this machine working well for the person
// using it" — CPU, memory, disk pressure. Risk asks "how much would it
// cost us if this machine were compromised" — missing patches, known
// vulnerabilities, whether mustra can even manage it, multiplied by how
// much the machine matters.
//
// Both use the same shape: a category contributes
// 100/(1+events), the categories are weighted, and the result is banded.
// The 100/(1+events) curve is the good part — one bad event costs half
// the category's score, the second costs a sixth more, and the twentieth
// is nearly free. That matches how people actually reason about repeated
// problems: the first is alarming, the tenth is a known condition.

type healthScore struct {
	AgentID   string                `json:"agent_id"`
	Hostname  string                `json:"hostname"`
	OS        string                `json:"os"`
	Site      string                `json:"site"`
	Online    bool                  `json:"online"`
	Score     int                   `json:"score"`
	Band      string                `json:"band"`
	Breakdown map[string]int        `json:"breakdown"`
	Detail    proto.PerformanceInfo `json:"detail"`
	Reported  bool                  `json:"reported"`
}

// categoryScore is the curve: no events is 100, and each additional event
// costs progressively less than the one before it.
func categoryScore(events int) int {
	if events < 0 {
		events = 0
	}
	return int(math.Round(100 / (1 + float64(events))))
}

func band(score int) string {
	switch {
	case score >= 90:
		return "good"
	case score >= 70:
		return "fair"
	case score >= 40:
		return "poor"
	default:
		return "very poor"
	}
}

// healthResponse is what GET /api/health answers.
type healthResponse struct {
	Bands      map[string]int `json:"bands"`
	Endpoints  []healthScore  `json:"endpoints"`
	FleetBand  string         `json:"fleet_band"`
	FleetScore int            `json:"fleet_score"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := s.store.ListSensorDataForSensor(r.Context(), string(proto.SensorPerformance))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	perf := map[string]proto.PerformanceInfo{}
	for _, row := range rows {
		var list []proto.PerformanceInfo
		if err := json.Unmarshal(row.Data, &list); err != nil || len(list) == 0 {
			continue
		}
		perf[row.AgentID] = list[0]
	}

	out := make([]healthScore, 0, len(agents))
	bands := map[string]int{"good": 0, "fair": 0, "poor": 0, "very poor": 0, "unreported": 0}
	for _, a := range agents {
		h := healthScore{
			AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS,
			Site: a.Site, Online: a.Online, Breakdown: map[string]int{},
		}
		p, ok := perf[a.AgentID]
		if !ok || p.Samples == 0 {
			// No history is not a perfect score. Scoring an unreported
			// endpoint 100 would make a broken agent look like the
			// healthiest machine in the fleet.
			h.Score = 0
			h.Band = "unreported"
			bands["unreported"]++
			out = append(out, h)
			continue
		}
		h.Reported = true
		h.Detail = p
		h.Breakdown["cpu"] = categoryScore(p.CPUEvents)
		h.Breakdown["memory"] = categoryScore(p.MemoryEvents)
		h.Breakdown["disk"] = categoryScore(p.DiskEvents)
		// Disk weighted highest: a full disk stops a machine outright,
		// where sustained CPU merely makes it slow.
		h.Score = int(math.Round(
			0.30*float64(h.Breakdown["cpu"]) +
				0.30*float64(h.Breakdown["memory"]) +
				0.40*float64(h.Breakdown["disk"])))
		h.Band = band(h.Score)
		bands[h.Band]++
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reported != out[j].Reported {
			return !out[i].Reported
		}
		return out[i].Score < out[j].Score
	})

	fleet := 0
	scored := 0
	for _, h := range out {
		if h.Reported {
			fleet += h.Score
			scored++
		}
	}
	avg := 0
	if scored > 0 {
		avg = int(math.Round(float64(fleet) / float64(scored)))
	}
	writeJSONResponse(w, healthResponse{
		Endpoints: out, Bands: bands, FleetScore: avg, FleetBand: band(avg),
	})
}

// ---- risk ----

// criticalityMultiplier scales an endpoint's risk by how much it matters.
// A vulnerability on a domain controller is not the same finding as the
// same vulnerability on a spare laptop, and a single number that treats
// them alike is a number nobody trusts.
var criticalityMultiplier = map[string]float64{
	"low": 1.0, "medium": 1.33, "high": 1.67, "critical": 2.0,
}

type riskScore struct {
	AgentID        string         `json:"agent_id"`
	Hostname       string         `json:"hostname"`
	OS             string         `json:"os"`
	Site           string         `json:"site"`
	Criticality    string         `json:"criticality"`
	Score          int            `json:"score"`
	Band           string         `json:"band"`
	Factors        map[string]int `json:"factors"`
	Vulns          int            `json:"vulnerabilities"`
	CriticalVulns  int            `json:"critical_vulnerabilities"`
	MissingPatches int            `json:"missing_patches"`
	Manageable     bool           `json:"manageable"`
}

func riskBand(score int) string {
	switch {
	case score >= 750:
		return "critical"
	case score >= 500:
		return "high"
	case score >= 250:
		return "medium"
	default:
		return "low"
	}
}

// riskScoresResponse is what GET /api/risk/scores answers.
type riskScoresResponse struct {
	Bands      map[string]int `json:"bands"`
	Endpoints  []riskScore    `json:"endpoints"`
	FleetBand  string         `json:"fleet_band"`
	FleetScore int            `json:"fleet_score"`
	Levels     []string       `json:"levels"`
}

func (s *Server) handleRiskScores(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vulns, err := s.store.ListAllAgentVulnerabilities(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	crit, err := s.store.ListCriticality(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	vulnCount := map[string]int{}
	critCount := map[string]int{}
	for _, v := range vulns {
		// A finding the distribution says is already fixed here, or has
		// explicitly declined to advise on, is not risk this endpoint
		// carries. Counting it would put every Debian host at the same
		// inflated number regardless of how well it is actually kept.
		if v.Suppressed {
			continue
		}
		vulnCount[v.AgentID]++
		if v.Severity == "critical" || v.Severity == "high" {
			critCount[v.AgentID]++
		}
	}
	patchCount := s.missingPatchCounts(r.Context())
	manageable := s.manageableAgents(r.Context())

	out := make([]riskScore, 0, len(agents))
	bands := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	for _, a := range agents {
		level := crit[a.AgentID]
		if level == "" {
			level = "medium"
		}
		rs := riskScore{
			AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Site: a.Site,
			Criticality: level, Factors: map[string]int{},
			Vulns: vulnCount[a.AgentID], CriticalVulns: critCount[a.AgentID],
			MissingPatches: patchCount[a.AgentID], Manageable: manageable[a.AgentID],
		}

		// Each factor contributes points of risk, capped so no single one
		// can saturate the score on its own.
		//
		// The weights are set so a realistic fleet lands across the range
		// rather than all at the cap. The first version multiplied counts
		// by 8 and clipped at 200, which meant every host with more than
		// 25 severe findings scored identically — on a real fleet that was
		// 32 of 34 endpoints, and a score that gives almost everything the
		// same number is decoration rather than information. Severity is
		// weighted four times the raw count, since "how bad" discriminates
		// where "how many" mostly reflects how large the package set is.
		rs.Factors["vulnerabilities"] = capAt(
			int(math.Round(float64(rs.CriticalVulns)*0.6+float64(rs.Vulns)*0.15)), 250)
		rs.Factors["missing_patches"] = capAt(rs.MissingPatches*12, 150)
		if !rs.Manageable {
			// An endpoint mustra cannot fully manage is one it cannot fix,
			// which is itself risk regardless of what is wrong with it.
			rs.Factors["unmanageable"] = 100
		}
		if !a.Online {
			rs.Factors["offline"] = 50
		}

		base := 0
		for _, v := range rs.Factors {
			base += v
		}
		rs.Score = capAt(int(math.Round(float64(base)*criticalityMultiplier[level])), 1000)
		rs.Band = riskBand(rs.Score)
		bands[rs.Band]++
		out = append(out, rs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })

	total := 0
	for _, rs := range out {
		total += rs.Score
	}
	avg := 0
	if len(out) > 0 {
		avg = int(math.Round(float64(total) / float64(len(out))))
	}
	writeJSONResponse(w, riskScoresResponse{
		Endpoints: out, Bands: bands, FleetScore: avg, FleetBand: riskBand(avg),
		Levels: []string{"low", "medium", "high", "critical"},
	})
}

func capAt(v, max int) int {
	if v > max {
		return max
	}
	return v
}

// missingPatchCounts reads the cached patches sensor rather than asking
// the fleet: risk scoring runs on page load, and waking every endpoint to
// draw a chart would be a poor trade.
func (s *Server) missingPatchCounts(ctx context.Context) map[string]int {
	out := map[string]int{}
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorPatches))
	if err != nil {
		return out
	}
	for _, row := range rows {
		var patches []proto.PatchInfo
		if err := json.Unmarshal(row.Data, &patches); err != nil {
			continue
		}
		out[row.AgentID] = len(patches)
	}
	return out
}

func (s *Server) manageableAgents(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorPrivileges))
	if err != nil {
		return out
	}
	for _, row := range rows {
		items, err := sensorRows(row.Data)
		if err != nil || len(items) == 0 {
			continue
		}
		if full, ok := items[0]["full_rights"].(bool); ok {
			out[row.AgentID] = full
		}
	}
	return out
}

// setCriticalityRequest is the body of POST /api/risk/criticality.
type setCriticalityRequest struct {
	AgentID string `json:"agent_id" api:"required"`
	Level   string `json:"level" api:"required"`
}

// setCriticalityResponse is what POST /api/risk/criticality answers.
type setCriticalityResponse struct {
	AgentID string `json:"agent_id"`
	Level   string `json:"level"`
}

func (s *Server) handleSetCriticality(w http.ResponseWriter, r *http.Request) {
	var body setCriticalityRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body.AgentID = strings.TrimSpace(body.AgentID)
	if body.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	if _, ok := criticalityMultiplier[body.Level]; !ok {
		http.Error(w, "level must be low, medium, high or critical", http.StatusBadRequest)
		return
	}
	if err := s.store.SetCriticality(r.Context(), body.AgentID, body.Level); err != nil {
		if errors.Is(err, store.ErrUnknownAgent) {
			http.Error(w, "no such endpoint", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// It reweights the endpoint's risk for everyone, so say who did it.
	s.audit(r.Context(), auditEvent{Action: "agent.criticality", Actor: auth.CurrentUser(r.Context()).Username,
		Target: body.AgentID, AgentID: body.AgentID, Severity: "notice", Detail: map[string]any{"level": body.Level}})
	writeJSONResponse(w, setCriticalityResponse{AgentID: body.AgentID, Level: body.Level})
}

var _ = store.AgentRecord{}
