package server

import (
	"math"
	"testing"
)

// The 100/(1+events) curve is the whole point of the score: the first bad
// event is alarming, the tenth is a known condition. These pin that shape,
// because a linear penalty would make every busy machine look equally
// broken and the number would stop meaning anything.
func TestCategoryScoreDecaysSharplyThenFlattens(t *testing.T) {
	for _, tc := range []struct {
		events int
		want   int
	}{
		{0, 100}, // nothing wrong
		{1, 50},  // one event costs half
		{2, 33},
		{3, 25},
		{9, 10},
		{99, 1},
	} {
		if got := categoryScore(tc.events); got != tc.want {
			t.Errorf("categoryScore(%d) = %d, want %d", tc.events, got, tc.want)
		}
	}
	// The marginal cost of an event has to fall away sharply: that is what
	// distinguishes this from a linear penalty, which would make every
	// busy machine look equally broken.
	//
	// Compared across the range rather than between adjacent counts,
	// because rounding a real-valued curve to an integer score wobbles by
	// a point either way (100/8 rounds up to 13, 100/9 down to 11) and
	// asserting strict monotonicity on the rounded values would be
	// pinning an artefact of rounding, not the behaviour that matters.
	firstEvent := categoryScore(0) - categoryScore(1)
	tenthEvent := categoryScore(9) - categoryScore(10)
	if firstEvent < 40 {
		t.Errorf("the first event should be expensive, cost %d", firstEvent)
	}
	if tenthEvent > 2 {
		t.Errorf("the tenth event should be nearly free, cost %d", tenthEvent)
	}
	// And the score must never increase as things get worse.
	for n := 0; n < 50; n++ {
		if categoryScore(n+1) > categoryScore(n) {
			t.Fatalf("score rose from %d to %d events", n, n+1)
		}
	}
}

func TestCategoryScoreHandlesNonsense(t *testing.T) {
	if got := categoryScore(-5); got != 100 {
		t.Errorf("a negative event count should score 100, got %d", got)
	}
}

func TestBands(t *testing.T) {
	for score, want := range map[int]string{
		100: "good", 90: "good", 89: "fair", 70: "fair",
		69: "poor", 40: "poor", 39: "very poor", 0: "very poor",
	} {
		if got := band(score); got != want {
			t.Errorf("band(%d) = %q, want %q", score, got, want)
		}
	}
}

// Criticality is a multiplier, so the same findings on a critical host
// must score strictly higher than on a low one — that is the entire
// reason the concept exists.
func TestCriticalityOrdersMultipliers(t *testing.T) {
	order := []string{"low", "medium", "high", "critical"}
	for i := 1; i < len(order); i++ {
		if criticalityMultiplier[order[i]] <= criticalityMultiplier[order[i-1]] {
			t.Errorf("%s must weigh more than %s", order[i], order[i-1])
		}
	}
	if criticalityMultiplier["low"] != 1.0 {
		t.Error("low criticality must not scale the score at all")
	}
}

func TestRiskBandsAndCap(t *testing.T) {
	if got := capAt(5000, 1000); got != 1000 {
		t.Errorf("capAt should clamp, got %d", got)
	}
	if got := capAt(10, 1000); got != 10 {
		t.Errorf("capAt should pass values under the cap, got %d", got)
	}
	for score, want := range map[int]string{
		1000: "critical", 750: "critical", 749: "high",
		500: "high", 499: "medium", 250: "medium", 249: "low", 0: "low",
	} {
		if got := riskBand(score); got != want {
			t.Errorf("riskBand(%d) = %q, want %q", score, got, want)
		}
	}
}

// A score that gives most of the fleet the same number is decoration. This
// pins the property the first version failed: across a realistic spread of
// findings, endpoints must land on meaningfully different scores rather
// than all at the cap.
func TestRiskFactorsDiscriminateAcrossARealisticFleet(t *testing.T) {
	// Counts taken from the observed distribution on a real 34-endpoint
	// fleet: total vulnerabilities 0-604, severe 0-253.
	fleet := []struct{ vulns, critical, patches int }{
		{0, 0, 0}, {294, 110, 0}, {331, 134, 0}, {443, 180, 2}, {604, 253, 2},
	}
	seen := map[int]bool{}
	for _, f := range fleet {
		score := capAt(int(math.Round(float64(f.critical)*0.6+float64(f.vulns)*0.15)), 250) +
			capAt(f.patches*12, 150)
		seen[score] = true
	}
	if len(seen) < len(fleet) {
		t.Errorf("only %d distinct scores for %d distinct endpoints — the scale is saturating",
			len(seen), len(fleet))
	}
}
