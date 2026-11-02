package server

import (
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestComplianceDrift(t *testing.T) {
	r := func(id, title, state string) store.ComplianceResult {
		return store.ComplianceResult{AgentID: "a1", CheckID: id, Title: title, State: state}
	}
	prev := []store.ComplianceResult{r("1", "SSH root login", "pass"), r("2", "Firewall", "pass"), r("3", "Audit", "fail"), r("4", "Camera", "pass")}
	now := []store.ComplianceResult{r("1", "SSH root login", "fail"), r("2", "Firewall", "pass"), r("3", "Audit", "fail"), r("4", "Camera", "fail")}
	x := buildExceptionSet([]store.ComplianceException{{ID: "e1", Title: "Camera"}}, nil, time.Now())
	regressed, before, after := complianceDrift(prev, now, x)
	if len(regressed) != 1 || regressed[0] != "SSH root login" {
		t.Fatalf("only SSH root login regressed (Audit already failed, Camera is excepted): %v", regressed)
	}
	if !(before > after) {
		t.Errorf("the score should drop: %.1f → %.1f", before, after)
	}
	if got, _, _ := complianceDrift(nil, now, x); got != nil {
		t.Errorf("a first scan has nothing to drift from: %v", got)
	}
}
