package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// The agent-update package is an action package, and an action package is
// never "installed" — so it stayed eligible on every endpoint for ever,
// including the ones that had just taken it. mustra knows the agent's
// version without a sensor, which is exactly what fact detection uses.
func TestAgentVersionApplicability(t *testing.T) {
	ops := store.SoftwareOps{Install: "true", Update: "true"}
	pkg := store.SoftwarePackage{
		Kind:     store.KindAction,
		Name:     "Update mustra agent",
		Detect:   store.SoftwareDetect{Fact: store.FactAgentVersion},
		Commands: map[string]store.SoftwareOps{"linux": ops},
	}

	if state, _, _ := agentVersionState("0.36.2", "0.33.0", ops, "linux"); state != stateUpdateEligible {
		t.Errorf("an endpoint on 0.33.0 while 0.36.2 is served = %q, want update eligible", state)
	}
	if state, _, why := agentVersionState("0.36.2", "0.36.2", ops, "linux"); state != stateInstalled {
		t.Errorf("an endpoint already on 0.36.2 = %q (%s), want installed", state, why)
	}
	// An unstamped control plane must not nag the entire fleet on the
	// strength of a build flag nobody set.
	if state, _, _ := agentVersionState("dev", "0.36.2", ops, "linux"); state != stateInstalled {
		t.Errorf("with an unstamped control plane, state = %q, want installed", state)
	}
	if state, _, _ := agentVersionState("0.36.2", "", ops, "linux"); state != stateInstallEligible {
		t.Errorf("an endpoint reporting no version = %q, want install eligible", state)
	}

	// And the operation must agree, or the picker offers what the deploy
	// will drop.
	if !operationApplies(pkg, "update", stateUpdateEligible) {
		t.Error("update does not apply to an endpoint that is behind")
	}
	if operationApplies(pkg, "update", stateInstalled) {
		t.Error("update applies to an endpoint already on the served version")
	}
}

// Mid-rollout an endpoint can be ahead of the control plane. Pushing the
// older build at it is a downgrade, not an update.
func TestAgentAheadOfControlPlaneIsNotEligible(t *testing.T) {
	pkg := store.SoftwarePackage{
		Kind:     store.KindAction,
		Detect:   store.SoftwareDetect{Fact: store.FactAgentVersion},
		Commands: map[string]store.SoftwareOps{"linux": {Install: "true"}},
	}
	_ = pkg
	state, found, why := agentVersionState("0.36.2", "99.0.0",
		store.SoftwareOps{Install: "true"}, "linux")
	if state != stateInstalled {
		t.Fatalf("state = %q, want installed — an ahead endpoint must not be offered a downgrade", state)
	}
	if found != "99.0.0" || why == "" {
		t.Errorf("found=%q why=%q — it should report what it is on and why it is excluded", found, why)
	}
}

// An action package with no fact keeps its old behaviour: a reboot is not
// something an endpoint can be "already on".
func TestOrdinaryActionPackageStaysAlwaysEligible(t *testing.T) {
	pkg := store.SoftwarePackage{
		Kind:     store.KindAction,
		Commands: map[string]store.SoftwareOps{"linux": {Install: "reboot"}},
	}
	if !operationApplies(pkg, "install", stateInstallEligible) {
		t.Error("a plain action package must still run anywhere it has a command")
	}
}

// Applicability answers "should this endpoint get it". Whether there is
// anything to run is a different question, and conflating them recorded
// runs that dispatched nothing and then showed as stalled for ever.
func TestTargetsRequireARunnableCommand(t *testing.T) {
	pkg := store.SoftwarePackage{
		Kind: store.KindSoftware, Name: "foo",
		Commands: map[string]store.SoftwareOps{"linux": {Install: "apt-get install foo"}},
	}
	if hasCommandFor(pkg, "linux", "remove") {
		t.Error("remove reported as runnable with no remove command — this is the eight-target no-op")
	}
	if !hasCommandFor(pkg, "linux", "install") {
		t.Error("install should be runnable")
	}
	// Update falls back to install in the dispatcher, so it is real.
	if !hasCommandFor(pkg, "linux", "update") {
		t.Error("update should fall back to the install command")
	}
	if hasCommandFor(pkg, "windows", "install") {
		t.Error("a platform with no commands at all is never runnable")
	}
}

// Self Service used to decide what to offer with its own logic that never
// consulted Requirements, so a package restricted to amd64 was offered on
// an arm64 Mac — and install authorization is derived from that same list,
// so it would have been allowed to run.
func TestRequirementsGateIsShared(t *testing.T) {
	pkg := store.SoftwarePackage{
		Name:         "x86-only tool",
		Requirements: store.SoftwareRequirements{Arch: []string{"amd64"}},
	}
	if ok, why := meetsRequirements(pkg, store.AgentRecord{Arch: "arm64"}); ok {
		t.Error("an arm64 endpoint passed an amd64-only requirement")
	} else if why == "" {
		t.Error("a refusal must say what it needed")
	}
	if ok, _ := meetsRequirements(pkg, store.AgentRecord{Arch: "amd64"}); !ok {
		t.Error("the matching architecture was refused")
	}

	ram := store.SoftwarePackage{Requirements: store.SoftwareRequirements{MinRAMMB: 8192}}
	if ok, _ := meetsRequirements(ram, store.AgentRecord{MemTotalMB: 4096}); ok {
		t.Error("an endpoint under the RAM floor passed")
	}
	// Unknown memory is not a reason to refuse — an endpoint that has not
	// reported yet should not be locked out of everything.
	if ok, _ := meetsRequirements(ram, store.AgentRecord{MemTotalMB: 0}); !ok {
		t.Error("an endpoint with no reported memory was refused")
	}
}

// The migration that carried the old catalog into the package model stamps
// match:"contains" on every item it moves, and Self Service's exact-key
// lookup missed precisely those — re-offering software already present.
func TestInstalledDetectionHonoursContains(t *testing.T) {
	apps := map[string]string{"microsoft visual studio code (user)": "1.90.0"}
	exact := store.SoftwareDetect{AppName: "Visual Studio Code"}
	if got := matchInstalled(exact, "Visual Studio Code", apps); got != "" {
		t.Errorf("exact match found %q where the installed name differs", got)
	}
	contains := store.SoftwareDetect{AppName: "Visual Studio Code", Match: "contains"}
	if got := matchInstalled(contains, "Visual Studio Code", apps); got != "1.90.0" {
		t.Errorf("contains match = %q, want the installed version — this is the re-offer bug", got)
	}
}

// The deploy API accepted "run" for a legacy action package, but
// hasCommandFor only knew install/update/remove, so every target was
// dropped and the reply blamed eligibility.
func TestLegacyActionPackageRuns(t *testing.T) {
	pkg := store.SoftwarePackage{
		Kind: store.KindAction, Name: "flush dns",
		Commands: map[string]store.SoftwareOps{"linux": {Install: "resolvectl flush-caches"}},
	}
	if !operationApplies(pkg, "run", stateInstallEligible) {
		t.Error("run must apply to an action package with a command here")
	}
	if !hasCommandFor(pkg, "linux", "run") {
		t.Error("run must be runnable: it is the action's command")
	}
	if got := legacyCommand(pkg, pkg.Commands["linux"], "run"); got != "resolvectl flush-caches" {
		t.Errorf("run dispatched %q, want the action's command", got)
	}
	if hasCommandFor(pkg, "windows", "run") {
		t.Error("no command for this platform means nothing to run")
	}

	detected := pkg
	detected.Detect.AppName = "foo"
	if !operationApplies(detected, "run", stateInstalled) {
		t.Error("an action with an app-name rule still runs regardless of what is installed")
	}
	if operationApplies(detected, "run", stateNotApplicable) {
		t.Error("not applicable stays not applicable")
	}
	// The agent-version update action keeps its special detection: an
	// endpoint already on the serving build is not re-run.
	updater := pkg
	updater.Detect.Fact = store.FactAgentVersion
	if operationApplies(updater, "run", stateInstalled) {
		t.Error("run must not re-run the agent update on an up-to-date endpoint")
	}
	if !operationApplies(updater, "run", stateUpdateEligible) {
		t.Error("run must reach an outdated endpoint")
	}

	software := store.SoftwarePackage{
		Kind:     store.KindSoftware,
		Commands: map[string]store.SoftwareOps{"linux": {Install: "apt-get install foo"}},
	}
	if hasCommandFor(software, "linux", "run") || operationApplies(software, "run", stateInstallEligible) {
		t.Error("run means nothing for a software package")
	}
}

// What hasCommandFor promises, the dispatcher must send: update with only
// an install command used to pass the check and then dispatch "".
func TestUpdateDispatchesTheInstallCommandWhenThereIsNoUpdate(t *testing.T) {
	pkg := store.SoftwarePackage{Kind: store.KindSoftware}
	ops := store.SoftwareOps{Install: "apt-get install -y foo"}
	if got := legacyCommand(pkg, ops, "update"); got != ops.Install {
		t.Errorf("update dispatched %q, want the install command", got)
	}
	ops.Update = "apt-get install --only-upgrade foo"
	if got := legacyCommand(pkg, ops, "update"); got != ops.Update {
		t.Errorf("update dispatched %q, want the update command", got)
	}
}
