package server

import (
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestExceptionsLeaveChecksOutOfTheScore(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	x := buildExceptionSet([]store.ComplianceException{
		{Title: "Ensure sshd PermitRootLogin is disabled."},
		{Title: "Ensure separate partition exists for /var/log", GroupID: "g-pve"},
		{Title: "Ensure ufw default deny firewall policy.", GroupID: "g-gone"},
		{Title: "Ensure pam_faillock module is enabled.", ExpiresAt: &past},
		{Title: "Ensure nodev option set on /var partition.", ExpiresAt: &future},
	}, map[string]map[string]bool{"g-pve": {"pve1": true}}, now)

	res := []store.ComplianceResult{
		{AgentID: "pve1", Title: "Ensure  SSHD PermitRootLogin is disabled", State: "fail"},       // fleet-wide, wording normalised
		{AgentID: "pve1", Title: "Ensure separate partition exists for /var/log.", State: "fail"}, // group member
		{AgentID: "web1", Title: "Ensure separate partition exists for /var/log.", State: "fail"}, // not in the group
		{AgentID: "web1", Title: "Ensure ufw default deny firewall policy.", State: "fail"},       // deleted group: nobody
		{AgentID: "web1", Title: "Ensure pam_faillock module is enabled.", State: "fail"},         // expired
		{AgentID: "web1", Title: "Ensure nodev option set on /var partition.", State: "fail"},     // not yet expired
		{AgentID: "web1", Title: "Ensure auditd is installed.", State: "pass"},
	}
	x.apply(res)
	want := []string{stateExcepted, stateExcepted, "fail", "fail", "fail", stateExcepted, "pass"}
	for i, r := range res {
		if r.State != want[i] {
			t.Errorf("%s on %s: state %q, want %q", r.Title, r.AgentID, r.State, want[i])
		}
	}
	score, pass, fail, unknown := hardeningScore(res)
	if pass != 1 || fail != 3 || unknown != 0 || score != 25 {
		t.Errorf("score %v pass %d fail %d unknown %d; want 25, 1, 3, 0", score, pass, fail, unknown)
	}
}

func TestEmptyExceptionSetChangesNothing(t *testing.T) {
	res := []store.ComplianceResult{{AgentID: "a", Title: "x", State: "fail"}}
	exceptionSet{}.apply(res)
	if res[0].State != "fail" {
		t.Fatal("an empty exception set excepted a check")
	}
}
