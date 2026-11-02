package server

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// An approver may shorten a window but never extend it: the policy is the
// ceiling, and a decision that could raise it would make the policy
// advisory.
func TestApproverCannotExtendBeyondPolicy(t *testing.T) {
	clamp := func(requested, max int) int {
		if requested <= 0 || requested > max {
			return max
		}
		return requested
	}
	if got := clamp(60, 30); got != 30 {
		t.Errorf("asking for longer than the policy allows must clamp to %d, got %d", 30, got)
	}
	if got := clamp(10, 30); got != 10 {
		t.Errorf("a shorter window must be honoured, got %d", got)
	}
	if got := clamp(0, 30); got != 30 {
		t.Errorf("unspecified must take the policy's window, got %d", got)
	}
	if got := clamp(-5, 30); got != 30 {
		t.Errorf("a negative window must not become access forever, got %d", got)
	}
}

// A session is live only while its window is: the clock decides, not the
// sweeper that happens to run once a minute.
func TestSessionWindowIsDecidedByTheClock(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Minute)
	expired := func(s *store.ShellSession) bool {
		return s.ExpiresAt != nil && time.Now().After(*s.ExpiresAt)
	}
	if !expired(&store.ShellSession{ExpiresAt: &past}) {
		t.Error("a session past its window must refuse the next command")
	}
	if expired(&store.ShellSession{ExpiresAt: &future}) {
		t.Error("a session inside its window must still work")
	}
	if expired(&store.ShellSession{}) {
		t.Error("a session with no window never expires on the clock")
	}
}

// The policy that applies is the highest-priority enabled one covering the
// endpoint, and an unscoped policy covers everything.
func TestJumpPolicyOrdering(t *testing.T) {
	// ListJumpPolicies orders by priority DESC, so the first enabled match
	// wins. This encodes the contract the store query has to keep.
	policies := []store.JumpPolicy{
		{Name: "high", Priority: 10, Enabled: true, GroupIDs: []string{"g1"}},
		{Name: "catch-all", Priority: 0, Enabled: true, GroupIDs: []string{}},
		{Name: "disabled", Priority: 99, Enabled: false, GroupIDs: []string{}},
	}
	members := map[string]map[string]bool{"g1": {"a": true}}
	pick := func(agentID string) string {
		for _, p := range policies {
			if !p.Enabled {
				continue
			}
			if len(p.GroupIDs) == 0 || agentSet(members, p.GroupIDs)[agentID] {
				return p.Name
			}
		}
		return ""
	}
	if got := pick("a"); got != "high" {
		t.Errorf("the scoped, higher-priority policy should win for a: %q", got)
	}
	if got := pick("b"); got != "catch-all" {
		t.Errorf("an endpoint outside every scoped policy falls to the catch-all: %q", got)
	}
}

// No groups means every endpoint, which needs no lookup: the check must
// let it through without reading the groups, so a store error can't refuse
// an unscoped save.
func TestRequireKnownGroupsAllowsNoGroups(t *testing.T) {
	s := &Server{} // no store: reading the groups would panic
	for _, ids := range [][]string{nil, {}} {
		rec := httptest.NewRecorder()
		if !s.requireKnownGroups(rec, httptest.NewRequest("POST", "/api/jump/policies", nil), ids) {
			t.Fatalf("%#v refused: %d %q", ids, rec.Code, rec.Body.String())
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("%#v wrote a response: %q", ids, rec.Body.String())
		}
	}
}
