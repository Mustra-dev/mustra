package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// filterToAgents is the one place "specific endpoints" is honoured, shared
// by Deploy now, the deploy preview and a schedule firing. The dangerous
// case is the empty one: if an explicit list that matched nothing were
// treated the same as no list at all, picking three endpoints that all went
// offline would patch the entire fleet.
func TestFilterToAgents(t *testing.T) {
	agents := []store.AgentRecord{
		{AgentID: "a1", Hostname: "one"},
		{AgentID: "a2", Hostname: "two"},
		{AgentID: "a3", Hostname: "three"},
	}

	t.Run("no list leaves the set alone", func(t *testing.T) {
		if got := filterToAgents(agents, nil); len(got) != 3 {
			t.Fatalf("want all 3 agents, got %d", len(got))
		}
	})

	t.Run("keeps only the named endpoints", func(t *testing.T) {
		got := filterToAgents(agents, []string{"a3", "a1"})
		if len(got) != 2 || got[0].AgentID != "a1" || got[1].AgentID != "a3" {
			t.Fatalf("want a1 and a3 in resolved order, got %+v", got)
		}
	})

	t.Run("an unknown or offline id simply drops out", func(t *testing.T) {
		got := filterToAgents(agents, []string{"a2", "gone"})
		if len(got) != 1 || got[0].AgentID != "a2" {
			t.Fatalf("want only a2, got %+v", got)
		}
	})

	t.Run("a list matching nothing selects nothing", func(t *testing.T) {
		if got := filterToAgents(agents, []string{"gone"}); len(got) != 0 {
			t.Fatalf("want no agents, got %+v", got)
		}
	})

	t.Run("does not write through the caller's slice", func(t *testing.T) {
		_ = filterToAgents(agents, []string{"a3"})
		if agents[0].AgentID != "a1" {
			t.Fatalf("source slice was overwritten: %+v", agents)
		}
	})
}

func TestPatchUnsupportedReasonHAOS(t *testing.T) {
	if why := patchUnsupportedReason(store.AgentRecord{OS: "linux", Platform: "haos"}); why == "" {
		t.Fatal("a Home Assistant OS endpoint must not be sent apply_patches")
	}
	for _, p := range []string{"ubuntu", "debian", "rhel", ""} {
		if why := patchUnsupportedReason(store.AgentRecord{OS: "linux", Platform: p}); why != "" {
			t.Fatalf("platform %q wrongly refused: %s", p, why)
		}
	}
}
