package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

func evTrigger(source, severity, title string) store.PlaybookTrigger {
	return store.PlaybookTrigger{Kind: store.TriggerEvent, Enabled: true,
		Source: source, Severity: severity, TitleMatch: title}
}

func TestEventMatching(t *testing.T) {
	n := store.Notification{Source: "Patch", Severity: "critical", Title: "Patch run failed on an endpoint"}
	cases := []struct {
		name string
		tr   store.PlaybookTrigger
		want bool
	}{
		{"everything empty matches anything", evTrigger("", "", ""), true},
		{"source matches, case-insensitively", evTrigger("patch", "", ""), true},
		{"wrong source", evTrigger("Threat Response", "", ""), false},
		{"severity matches", evTrigger("", "CRITICAL", ""), true},
		{"wrong severity", evTrigger("", "warning", ""), false},
		{"title substring", evTrigger("", "", "run failed"), true},
		{"title substring, case-insensitively", evTrigger("", "", "RUN FAILED"), true},
		{"title that is not there", evTrigger("", "", "reboot"), false},
		{"all three, all right", evTrigger("Patch", "critical", "failed"), true},
		{"all three, one wrong", evTrigger("Patch", "notice", "failed"), false},
	}
	for _, c := range cases {
		if got := eventMatches(c.tr, n); got != c.want {
			t.Errorf("%s: matched = %v, want %v", c.name, got, c.want)
		}
	}
}

// A playbook that raises a Guide item which starts a playbook is a loop
// that runs until somebody notices, and the fleet is what it runs on while
// nobody does. Notifications from Playbooks never reach a trigger.
func TestPlaybookNotificationsCannotTriggerPlaybooks(t *testing.T) {
	if playbooksSource != "Playbooks" {
		t.Fatalf("the guard names %q; the notify() calls in playbooks.go use \"Playbooks\"", playbooksSource)
	}
	// The guard is in fireEventTriggers, which needs a store. What is
	// asserted here is that a trigger which would otherwise match one of
	// the playbook engine's own notifications really does match it — so
	// the guard is load-bearing rather than decorative.
	own := store.Notification{Source: playbooksSource, Severity: "warning", Title: "Nightly patch finished partial"}
	if !eventMatches(evTrigger("", "", ""), own) {
		t.Fatal("a catch-all trigger does not match a playbook's own notification; the source guard is not what stops the loop")
	}
}

// The cooldown has a floor. A trigger with none is an outage waiting for
// the first busy day: one Guide item per finding, hundreds at a time.
func TestCooldownFloor(t *testing.T) {
	if triggerMinCooldown < 60 {
		t.Fatalf("cooldown floor is %ds", triggerMinCooldown)
	}
}

func TestApprovalHoursAreBounded(t *testing.T) {
	if approvalDefaultHours <= 0 || approvalDefaultHours > approvalMaxHours {
		t.Fatalf("default %dh against a max of %dh", approvalDefaultHours, approvalMaxHours)
	}
	// A gate with no bound is not a gate, it is an abandoned run.
	if approvalMaxHours > 24*7 {
		t.Fatalf("a gate can sit for %dh", approvalMaxHours)
	}
}

// A gate that is the last step approves nothing: every endpoint stops
// there, somebody is asked, and whatever they say there is nothing left to
// run. Refused at save time rather than discovered when the approval comes
// back.
func TestApprovalCannotBeTheLastStep(t *testing.T) {
	s := &Server{}
	steps := []playbookStep{
		{Kind: "patch", RunIf: "always", OnFailure: "stop"},
		{Kind: "approval", RunIf: "always", OnFailure: "stop"},
	}
	if _, err := s.validatePlaybookSteps(nil, steps); err == nil {
		t.Fatal("a trailing approval step was accepted")
	}
	ok := []playbookStep{
		{Kind: "approval", RunIf: "always", OnFailure: "stop"},
		{Kind: "patch", RunIf: "always", OnFailure: "stop"},
	}
	if _, err := s.validatePlaybookSteps(nil, ok); err != nil {
		t.Fatalf("a gate with something after it was rejected: %v", err)
	}
}
