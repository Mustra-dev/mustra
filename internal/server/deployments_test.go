package server

import (
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// A patch job is acknowledged in milliseconds and finishes minutes or hours
// later. These cases pin the distinction the console depends on: an action
// that is merely open means the work is still going, and only a reported
// outcome ends the run. Closing the action on acknowledgement made every
// deployment terminal on arrival, so "Active" was permanently empty and a
// killed update was indistinguishable from a clean one.
func TestDeploymentStatus(t *testing.T) {
	fresh := time.Now().Add(-time.Minute)
	old := time.Now().Add(-deploymentStallAfter - time.Minute)

	cases := []struct {
		name    string
		started time.Time
		counts  map[string]int
		want    string
	}{
		{"open action is running, not succeeded", fresh, map[string]int{"started": 1}, "running"},
		{"open action past the stall window", old, map[string]int{"started": 1}, "stalled"},
		{"nothing reported yet", fresh, map[string]int{}, "running"},
		{"nothing ever reported", old, map[string]int{}, "no response"},
		{"reported success", fresh, map[string]int{"succeeded": 2}, "succeeded"},
		{"reported failure", fresh, map[string]int{"failed": 1}, "failed"},
		{"timeout is its own outcome", fresh, map[string]int{"timed_out": 1}, "timed out"},
		{"timeout alongside success is partial", fresh, map[string]int{"timed_out": 1, "succeeded": 1}, "partial"},
		{"timeout alongside failure is not success", fresh, map[string]int{"timed_out": 1, "failed": 1}, "failed"},
		{"mixed failure and success", fresh, map[string]int{"failed": 1, "succeeded": 1}, "partial"},
		{"one still open among finished", fresh, map[string]int{"succeeded": 1, "started": 1}, "running"},
		{"says the stage: installing", fresh, map[string]int{"succeeded": 1, "installing": 1}, "installing"},
		{"says the stage: downloading", fresh, map[string]int{"downloading": 2, "started": 1}, "downloading"},
		{"installing outranks downloading", fresh, map[string]int{"downloading": 1, "installing": 1}, "installing"},
		{"every endpoint offline is no response", fresh, map[string]int{"no_response": 2}, "no response"},
		{"offline alongside success is partial", fresh, map[string]int{"no_response": 1, "succeeded": 1}, "partial"},
		{"offline alongside timeout is not success", fresh, map[string]int{"no_response": 1, "timed_out": 1}, "failed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := store.PatchJobRun{ID: "run-test", StartedAt: tc.started}
			if got := deploymentStatus(run, tc.counts); got != tc.want {
				t.Errorf("deploymentStatus(%v) = %q, want %q", tc.counts, got, tc.want)
			}
		})
	}
}

// The stall window has to outlast the agent's own patch cap, or a machine
// that is legitimately still installing gets reported as stalled.
func TestDeploymentStallWindowOutlastsAgentPatchTimeout(t *testing.T) {
	const agentPatchApplyTimeout = 2 * time.Hour // internal/agent.patchApplyTimeout
	if deploymentStallAfter <= agentPatchApplyTimeout {
		t.Fatalf("deploymentStallAfter (%v) must exceed the agent's patch timeout (%v)",
			deploymentStallAfter, agentPatchApplyTimeout)
	}
}
