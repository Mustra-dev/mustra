package server

import (
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// The point of a confidence score is refusing to answer when there is no
// evidence. Three successes out of three is not certainty, it is nothing.
func TestConfidenceDeclinesWithoutHistory(t *testing.T) {
	c := scoreConfidence(store.DeployOutcome{Attempts: 3, Succeeded: 3, Endpoints: 3})
	if c.Score != nil {
		t.Fatalf("three attempts must not produce a score, got %d", *c.Score)
	}
	if c.Band != "unknown" {
		t.Errorf("band should be unknown, got %q", c.Band)
	}
	// It still reports what little it has, rather than hiding it.
	if c.SuccessPct == nil || *c.SuccessPct != 100 {
		t.Error("the raw rate should still be visible")
	}
	if c.Reason == "" {
		t.Error("it must say why it declined")
	}
	// Nothing at all is also unknown, and must not divide by zero.
	if s := scoreConfidence(store.DeployOutcome{}); s.Score != nil || s.SuccessPct != nil {
		t.Error("no attempts should give no numbers")
	}
}

func TestConfidenceScoresWithEnoughHistory(t *testing.T) {
	c := scoreConfidence(store.DeployOutcome{Attempts: 20, Succeeded: 19, Failed: 1, Endpoints: 20})
	if c.Score == nil {
		t.Fatal("twenty attempts should score")
	}
	if *c.Score != 95 {
		t.Errorf("19/20 should be 95, got %d", *c.Score)
	}
	if c.Band != "high" {
		t.Errorf("95 should band high, got %q", c.Band)
	}
}

// A package that installs cleanly and leaves the machine slower is not a
// confident deployment — but health moves for a hundred unrelated reasons,
// so the adjustment is gentle, capped, and one-directional.
func TestConfidenceHealthDelta(t *testing.T) {
	before, after := 90.0, 60.0
	c := scoreConfidence(store.DeployOutcome{
		Attempts: 20, Succeeded: 20, Endpoints: 20,
		HealthBefore: &before, HealthAfter: &after, HealthN: 20,
	})
	// 100 with a 30-point fall: half of 30 is 15, which is the cap.
	if *c.Score != 85 {
		t.Errorf("a 30-point health fall should cost the capped 15, got %d", *c.Score)
	}
	if c.HealthDelta == nil || *c.HealthDelta != -30 {
		t.Error("the delta should be reported alongside")
	}

	// A big improvement must not inflate the score past its success rate:
	// the machine's week getting better is not the package working.
	up, upAfter := 50.0, 100.0
	c2 := scoreConfidence(store.DeployOutcome{
		Attempts: 20, Succeeded: 18, Endpoints: 20,
		HealthBefore: &up, HealthAfter: &upAfter, HealthN: 20,
	})
	if *c2.Score != 90 {
		t.Errorf("a health rise must not raise the score above 18/20, got %d", *c2.Score)
	}

	// A catastrophic package cannot score below zero.
	z, zAfter := 100.0, 0.0
	c3 := scoreConfidence(store.DeployOutcome{
		Attempts: 10, Succeeded: 0, Failed: 10, Endpoints: 10,
		HealthBefore: &z, HealthAfter: &zAfter, HealthN: 10,
	})
	if *c3.Score != 0 {
		t.Errorf("score must floor at zero, got %d", *c3.Score)
	}
}

// A cancellation is not a deployment of the package. Counting "Cancel
// Reboot Computer" as an attempt would score an action package by how
// often somebody called it off, which is the opposite of the question.
func TestDeploymentSummariesExcludeCancel(t *testing.T) {
	for _, p := range []store.SoftwarePackage{
		{Name: "Reboot Computer (Windows)", Kind: store.KindAction},
		{Name: "jq", Kind: store.KindSoftware},
	} {
		for _, s := range deploymentSummaries(p) {
			if strings.HasPrefix(s, "Cancel ") {
				t.Fatalf("%s: summaries include a cancellation: %q", p.Name, s)
			}
		}
	}
	// And an action package is recorded under its bare name, not "Install X".
	got := deploymentSummaries(store.SoftwarePackage{Name: "Reboot Computer", Kind: store.KindAction})
	if len(got) != 1 || got[0] != "Reboot Computer" {
		t.Fatalf("action package summaries = %v", got)
	}
}
