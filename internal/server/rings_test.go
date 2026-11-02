package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// Progression criteria are the entire point of a staged rollout: without
// them it is just a slower way to break everything.
func TestRingPassed(t *testing.T) {
	for _, tc := range []struct {
		name             string
		ring             store.Ring
		succeeded, total int
		want             bool
	}{
		{"no criteria passes", store.Ring{}, 0, 5, true},
		{"min success met", store.Ring{MinSuccess: 3}, 3, 5, true},
		{"min success short", store.Ring{MinSuccess: 3}, 2, 5, false},
		{"rate met", store.Ring{SuccessRate: 80}, 4, 5, true},
		{"rate short", store.Ring{SuccessRate: 80}, 3, 5, false},
		{"both must hold", store.Ring{MinSuccess: 5, SuccessRate: 50}, 4, 5, false},

		// A ring where nothing reported back has not passed. Treating
		// silence as success is how a rollout continues past a ring whose
		// endpoints were all offline.
		{"nothing reported", store.Ring{}, 0, 0, false},
		{"nothing reported, criteria set", store.Ring{SuccessRate: 50}, 0, 0, false},
	} {
		got, why := ringPassed(tc.ring, tc.succeeded, tc.total)
		if got != tc.want {
			t.Errorf("%s: got %v (%s), want %v", tc.name, got, why, tc.want)
		}
		if !got && why == "" {
			t.Errorf("%s: a halt must say why", tc.name)
		}
	}
}

// A non-zero percentage of a small fleet must not round down to nothing:
// "10% of 5 endpoints" should be one machine, not a silently empty ring.
func TestDynamicRingNeverRoundsToNothing(t *testing.T) {
	for _, tc := range []struct{ total, percent, wantAtLeast int }{
		{5, 10, 1},
		{34, 10, 3},
		{100, 25, 25},
	} {
		n := tc.total * tc.percent / 100
		if n < 1 && tc.percent > 0 {
			n = 1
		}
		if n < tc.wantAtLeast {
			t.Errorf("%d%% of %d gave %d, want at least %d", tc.percent, tc.total, n, tc.wantAtLeast)
		}
	}
}
