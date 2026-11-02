package server

import (
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func planIDs(send []revealTarget) []string {
	var out []string
	for _, t := range send {
		out = append(out, t.agent.AgentID)
	}
	return out
}

// skipped counts the endpoints a run was meant for and did not reach,
// never the rest of the fleet.
func TestPlanRevealRunSkipsOnlyTargetedEndpoints(t *testing.T) {
	now := time.Now()
	rule := store.RevealRule{ID: "rvl-1", Roots: map[string][]string{"linux": {"/home"}}, IntervalHours: 24}
	fleet := []store.AgentRecord{
		{AgentID: "web-01", OS: "linux", Online: true},
		{AgentID: "web-02", OS: "linux", Online: true},
		{AgentID: "web-03", OS: "linux", Online: true},
	}

	t.Run("a run on one endpoint skips none of the others", func(t *testing.T) {
		send, skipped := planRevealRun(rule, fleet, nil, map[string]bool{"web-01": true}, nil, nil, false, now)
		if got := planIDs(send); len(got) != 1 || got[0] != "web-01" || skipped != 0 {
			t.Fatalf("send %v skipped %d, want [web-01] and 0", got, skipped)
		}
	})

	t.Run("endpoints outside the rule's groups are not skipped", func(t *testing.T) {
		send, skipped := planRevealRun(rule, fleet, map[string]bool{"web-02": true}, nil, nil, nil, false, now)
		if got := planIDs(send); len(got) != 1 || got[0] != "web-02" || skipped != 0 {
			t.Fatalf("send %v skipped %d, want [web-02] and 0", got, skipped)
		}
	})

	t.Run("an endpoint asked for outside the rule's groups is skipped", func(t *testing.T) {
		send, skipped := planRevealRun(rule, fleet, map[string]bool{"web-02": true}, map[string]bool{"web-01": true, "web-02": true}, nil, nil, false, now)
		if got := planIDs(send); len(got) != 1 || got[0] != "web-02" || skipped != 1 {
			t.Fatalf("send %v skipped %d, want [web-02] and web-01 skipped", got, skipped)
		}
	})

	t.Run("a targeted endpoint that cannot be scanned is skipped", func(t *testing.T) {
		fleet := []store.AgentRecord{
			{AgentID: "web-01", OS: "linux", Online: false},  // offline
			{AgentID: "win-01", OS: "windows", Online: true}, // no roots for Windows
			{AgentID: "web-02", OS: "linux", Online: true},   // outside the caller's access
			{AgentID: "web-03", OS: "linux", Online: true},   // scanned an hour ago
			{AgentID: "web-04", OS: "linux", Online: true},   // sent
		}
		allowed := map[string]bool{"web-01": true, "win-01": true, "web-03": true, "web-04": true}
		last := map[string]store.RevealScan{"web-03": {AgentID: "web-03", DispatchedAt: now.Add(-time.Hour), FinishedAt: ptrTime(now.Add(-time.Hour))}}
		send, skipped := planRevealRun(rule, fleet, nil, nil, allowed, last, false, now)
		if got := planIDs(send); len(got) != 1 || got[0] != "web-04" || skipped != 4 {
			t.Fatalf("send %v skipped %d, want [web-04] and 4", got, skipped)
		}
		send, skipped = planRevealRun(rule, fleet, nil, nil, allowed, last, true, now)
		if got := planIDs(send); len(got) != 2 || skipped != 3 {
			t.Fatalf("forced: send %v skipped %d, want web-03 and web-04 sent, 3 skipped", got, skipped)
		}
	})
}

func ptrTime(t time.Time) *time.Time { return &t }
