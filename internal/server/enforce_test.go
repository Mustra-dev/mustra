package server

import (
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func TestValidateEnforceSettingsFillsInIDs(t *testing.T) {
	got, err := validateEnforceSettings([]proto.EnforceSetting{
		{Name: "firewall on", Rules: []string{"c:true -> r:."}, RemediateLinux: "true"},
	}, "report", "linux")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].ID == "" {
		t.Error("a setting saved without an id can never be tracked across runs")
	}
}

// Enforce is the server's decision at dispatch time, taken from the failure
// history. An author who sets it in the payload must not be able to
// pre-authorise their own remediation past the give-up ceiling.
func TestValidateEnforceSettingsClearsTheEnforceFlag(t *testing.T) {
	got, err := validateEnforceSettings([]proto.EnforceSetting{
		{Name: "x", Rules: []string{"p:init"}, RemediateLinux: "true", Enforce: true},
	}, "report", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Enforce {
		t.Error("the author's enforce flag survived; only the dispatcher may set it")
	}
}

func TestValidateEnforceSettingsRejectsRulelessSettings(t *testing.T) {
	_, err := validateEnforceSettings([]proto.EnforceSetting{
		{Name: "nothing to check", Rules: []string{"  ", ""}},
	}, "report", "")
	if err == nil {
		t.Fatal("a setting with no rules checks nothing and must be refused")
	}
}

// A policy that can never fix anything but claims to enforce would report
// drift forever while looking like it was handling it.
func TestValidateEnforceSettingsRefusesEnforceWithNoFix(t *testing.T) {
	_, err := validateEnforceSettings([]proto.EnforceSetting{
		{Name: "firewall on", Rules: []string{"p:ufw"}},
	}, "enforce", "linux")
	if err == nil {
		t.Fatal("enforce mode with no remediation must be refused")
	}
	if !strings.Contains(err.Error(), "report mode") {
		t.Errorf("the error should point at the way out, got: %v", err)
	}
}

// The same settings are fine in report mode: watching first is exactly the
// workflow the default is there to encourage.
func TestValidateEnforceSettingsAllowsReportWithNoFix(t *testing.T) {
	if _, err := validateEnforceSettings([]proto.EnforceSetting{
		{Name: "firewall on", Rules: []string{"p:ufw"}},
	}, "report", "linux"); err != nil {
		t.Fatalf("report mode should not require a remediation: %v", err)
	}
}

// A Windows-only fix does not make a Linux-targeted policy enforceable.
func TestValidateEnforceSettingsJudgesTheTargetedPlatform(t *testing.T) {
	if _, err := validateEnforceSettings([]proto.EnforceSetting{
		{Name: "x", Rules: []string{"p:x"}, RemediateWindows: "Restart-Service x"},
	}, "enforce", "linux"); err == nil {
		t.Fatal("a Windows-only remediation cannot enforce a Linux policy")
	}
	if _, err := validateEnforceSettings([]proto.EnforceSetting{
		{Name: "x", Rules: []string{"p:x"}, RemediateWindows: "Restart-Service x"},
	}, "enforce", "windows"); err != nil {
		t.Fatalf("it should be fine when the policy targets Windows: %v", err)
	}
}

func TestValidateEnforceSettingsRejectsDuplicateIDs(t *testing.T) {
	_, err := validateEnforceSettings([]proto.EnforceSetting{
		{ID: "dup", Name: "a", Rules: []string{"p:a"}},
		{ID: "dup", Name: "b", Rules: []string{"p:b"}},
	}, "report", "")
	if err == nil {
		t.Fatal("two settings sharing an id would overwrite each other's results")
	}
}

func TestSummariseEnforceCountsEndpointsOnce(t *testing.T) {
	policies := []store.EnforcePolicy{{ID: "p1", Name: "Firewall"}}
	results := []store.EnforceResult{
		{PolicyID: "p1", AgentID: "a1", State: "compliant"},
		{PolicyID: "p1", AgentID: "a1", State: "drifted"},
		{PolicyID: "p1", AgentID: "a2", State: "failing"},
		{PolicyID: "gone", AgentID: "a3", State: "compliant"},
	}
	out := summariseEnforce(policies, results)
	if len(out) != 1 {
		t.Fatalf("got %d policies, want 1", len(out))
	}
	// Two settings on one endpoint is one endpoint, not two.
	if out[0].Endpoints != 2 {
		t.Errorf("endpoints = %d, want 2", out[0].Endpoints)
	}
	if out[0].Compliant != 1 || out[0].Drifted != 1 || out[0].Failing != 1 {
		t.Errorf("tally = %+v", out[0])
	}
}

// The safety property the schema comment claimed and the code did not have:
// a policy targeted at a group that is later deleted must target nothing.
// A blank group id means "the whole fleet", so without the flag a policy
// scoped to twelve servers silently became one that remediates every
// endpoint — found by testing the failure path, not by reading the code.
func TestOrphanedTargetingIsNothingNotEverything(t *testing.T) {
	orphan := store.EnforcePolicy{Name: "Firewall", GroupDeleted: true}
	// enforceTargets short-circuits before touching the store, which is what
	// makes this testable without one — and is also why it is correct even
	// if the agent list is unavailable.
	got, err := (&Server{}).enforceTargets(t.Context(), orphan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("an orphaned policy targeted %d endpoints, want 0", len(got))
	}
}

func TestOrphanedPlaybookTargetsNothing(t *testing.T) {
	got, err := (&Server{}).playbookTargets(t.Context(), store.Playbook{Name: "Reboot", GroupDeleted: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("an orphaned playbook targeted %d endpoints, want 0", len(got))
	}
}

// And it must say so, rather than describing itself as fleet-wide.
func TestOrphanedPlaybookSaysWhatItTargets(t *testing.T) {
	got := playbookTargetDesc(store.Playbook{GroupDeleted: true})
	if strings.Contains(got, "every endpoint") {
		t.Fatalf("described as %q — an orphan must never read as fleet-wide", got)
	}
	if !strings.Contains(got, "deleted") {
		t.Errorf("described as %q, want it to say the group is gone", got)
	}
}

// Postgres hands jsonb back reserialized, so comparing it to Go's compact
// output as bytes said "changed" every time — and every save, including a
// rename, wiped the failure counters. A remediation mustra had given up on
// would start running again because somebody fixed a typo in the name.
func TestSettingsDifferIgnoresSerialisationNoise(t *testing.T) {
	settings := []proto.EnforceSetting{{
		ID: "set-1", Name: "Firewall on", Severity: "high",
		Rules: []string{"c:true -> r:."}, RemediateLinux: "true",
	}}
	// What jsonb gives back: spaces after separators, keys in another order.
	stored := []byte(`[{"name": "Firewall on", "id": "set-1", "rules": ["c:true -> r:."], ` +
		`"severity": "high", "remediate_linux": "true"}]`)
	if settingsDiffer(stored, settings) {
		t.Fatal("identical settings reported as changed; every save would clear the history")
	}
}

func TestSettingsDifferSeesARealEdit(t *testing.T) {
	stored := []byte(`[{"id":"set-1","name":"Firewall on","rules":["c:true -> r:."]}]`)
	changed := []proto.EnforceSetting{{
		ID: "set-1", Name: "Firewall on", Rules: []string{"c:false -> r:."},
	}}
	if !settingsDiffer(stored, changed) {
		t.Fatal("an edited rule was not detected; stale counters would suppress the fixed command")
	}
}
