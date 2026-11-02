package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Confidence Score, from this fleet's own history and nothing else.
//
// Some tools compute this partly from install-success data pooled across
// every customer. mustra has no such corpus and inventing one would be a
// lie, so this is local only: how often a package has actually worked
// *here*, on how many machines, and what it did to their health.
//
// The hard part is not the arithmetic, it is refusing to answer. Three
// successes out of three is not 100% confidence, it is no evidence; a
// score presented without its sample size is worse than no score, because
// it looks like knowledge. So a package with too little history reports
// "not enough history" and says how much it has.

const (
	// confidenceMinAttempts is the point below which this declines to
	// score. Chosen so a first rollout to a ring of five does not come
	// back reading 100%.
	confidenceMinAttempts = 8
	confidenceWindow      = 180 * 24 * time.Hour
	healthSampleEvery     = 15 * time.Minute
	healthSampleKeep      = 120 * 24 * time.Hour
)

type confidence struct {
	Package     string     `json:"package"`
	PackageID   string     `json:"package_id,omitempty"`
	Score       *int       `json:"score,omitempty"`
	Band        string     `json:"band"`
	Reason      string     `json:"reason"`
	Attempts    int        `json:"attempts"`
	Succeeded   int        `json:"succeeded"`
	Failed      int        `json:"failed"`
	Endpoints   int        `json:"endpoints"`
	SuccessPct  *float64   `json:"success_pct,omitempty"`
	HealthDelta *float64   `json:"health_delta,omitempty"`
	HealthN     int        `json:"health_samples"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
}

// scoreConfidence turns a package's history into a number, or declines.
//
// The success rate is the score. The health delta adjusts it, because a
// package that installs cleanly and leaves the machine slower is not a
// confident deployment — but it adjusts gently and is capped, since health
// moves for a hundred reasons that have nothing to do with a package.
func scoreConfidence(o store.DeployOutcome) confidence {
	c := confidence{
		Attempts: o.Attempts, Succeeded: o.Succeeded, Failed: o.Failed,
		Endpoints: o.Endpoints, HealthN: o.HealthN,
		FirstSeen: o.FirstSeen, LastSeen: o.LastSeen,
	}
	if o.Attempts < confidenceMinAttempts {
		c.Band = "unknown"
		c.Reason = fmt.Sprintf("not enough history: %d of %d attempts needed before this is worth a number",
			o.Attempts, confidenceMinAttempts)
		if o.Attempts > 0 {
			pct := float64(o.Succeeded) * 100 / float64(o.Attempts)
			c.SuccessPct = &pct
		}
		return c
	}
	pct := float64(o.Succeeded) * 100 / float64(o.Attempts)
	c.SuccessPct = &pct
	score := pct

	if o.HealthBefore != nil && o.HealthAfter != nil && o.HealthN > 0 {
		delta := *o.HealthAfter - *o.HealthBefore
		c.HealthDelta = &delta
		// Only a fall counts against it, and only up to 15 points. A rise
		// after a deployment is far more likely to be the machine's week
		// improving than the package helping.
		if delta < 0 {
			penalty := math.Min(15, -delta/2)
			score -= penalty
		}
	}
	if score < 0 {
		score = 0
	}
	n := int(math.Round(score))
	c.Score = &n
	switch {
	case n >= 90:
		c.Band = "high"
	case n >= 70:
		c.Band = "moderate"
	default:
		c.Band = "low"
	}
	c.Reason = fmt.Sprintf("%d of %d attempts succeeded on %d endpoint(s)", o.Succeeded, o.Attempts, o.Endpoints)
	if c.HealthDelta != nil {
		c.Reason += fmt.Sprintf("; health %+.1f in the day after", *c.HealthDelta)
	}
	return c
}

// deploymentSummaries is every label a run of this package can have been
// recorded under — the same strings deploymentLabel writes. A cancellation
// is left out on purpose: calling a deployment off says nothing about
// whether the package works.
func deploymentSummaries(p store.SoftwarePackage) []string {
	if p.Kind == store.KindAction {
		return []string{p.Name}
	}
	return []string{"Install " + p.Name, "Update " + p.Name, "Remove " + p.Name, p.Name}
}

// fleetHealthScores computes the current health score per endpoint, the
// same way the Health page does. Kept here so the sampler and the page
// cannot drift apart into two different definitions of "healthy".
func (s *Server) fleetHealthScores(ctx context.Context) (map[string]int, error) {
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorPerformance))
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, row := range rows {
		var list []proto.PerformanceInfo
		if err := json.Unmarshal(row.Data, &list); err != nil || len(list) == 0 {
			continue
		}
		p := list[0]
		if p.Samples == 0 {
			continue // unreported is not a score
		}
		out[row.AgentID] = int(math.Round(
			0.30*float64(categoryScore(p.CPUEvents)) +
				0.30*float64(categoryScore(p.MemoryEvents)) +
				0.40*float64(categoryScore(p.DiskEvents))))
	}
	return out, nil
}

// healthSampleLoop keeps a history of the health score so a deployment can
// be compared with the day before it.
func (s *Server) healthSampleLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(90 * time.Second):
	}
	ticker := time.NewTicker(healthSampleEvery)
	defer ticker.Stop()
	for {
		scores, err := s.fleetHealthScores(ctx)
		if err != nil {
			s.logger.Warn("health sampling failed", "error", err)
		} else if err := s.store.RecordHealthSamples(ctx, time.Now().Truncate(time.Minute), scores); err != nil {
			s.logger.Warn("recording health samples failed", "error", err)
		}
		if _, err := s.store.PruneHealthSamples(ctx, healthSampleKeep); err != nil {
			s.logger.Warn("pruning health samples failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// confidenceResponse is what GET /api/confidence answers.
type confidenceResponse struct {
	HealthSamples int          `json:"health_samples"`
	MinAttempts   int          `json:"min_attempts"`
	Packages      []confidence `json:"packages"`
	WindowDays    int          `json:"window_days"`
}

// GET /api/confidence — every catalog package with what this fleet knows
// about it.
func (s *Server) handleConfidence(w http.ResponseWriter, r *http.Request) {
	pkgs, err := s.store.ListSoftwarePackages(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]confidence, 0, len(pkgs))
	for _, p := range pkgs {
		o, err := s.store.DeployOutcomeFor(r.Context(), deploymentSummaries(p), confidenceWindow)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c := scoreConfidence(o)
		c.Package, c.PackageID = p.Name, p.ID
		out = append(out, c)
	}
	// Anything scoreable first, worst score first inside that: the useful
	// reading is "what am I least sure about", not an alphabet.
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Score == nil) != (out[j].Score == nil) {
			return out[i].Score != nil
		}
		if out[i].Score != nil && *out[i].Score != *out[j].Score {
			return *out[i].Score < *out[j].Score
		}
		return out[i].Attempts > out[j].Attempts
	})
	var samples int
	_ = s.store.QueryRowInt(r.Context(), `SELECT count(*) FROM endpoint_health`, &samples)
	writeJSONResponse(w, confidenceResponse{
		Packages: out, MinAttempts: confidenceMinAttempts,
		WindowDays: int(confidenceWindow.Hours() / 24), HealthSamples: samples,
	})
}

// GET /api/confidence/patches — the same question for patching as a whole,
// which is one answer rather than one per patch: mustra records a patch run
// per endpoint, not per KB.
func (s *Server) handlePatchConfidence(w http.ResponseWriter, r *http.Request) {
	o, err := s.store.DeployOutcomeFor(r.Context(), []string{
		"Apply pending patches", "Apply pending patches (bulk deployment)",
	}, confidenceWindow)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c := scoreConfidence(o)
	c.Package = "Patch runs"
	writeJSONResponse(w, c)
}
