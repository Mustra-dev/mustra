package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Small fleets answer at once, as before; a large fleet's heavy answers are
// spread so they do not arrive as one burst the broker cuts the
// connection over; the window is bounded.
func TestAnswerWindowMs(t *testing.T) {
	cases := []struct {
		kind     proto.QueryKind
		expected int
		lo, hi   int
	}{
		{proto.QueryKindProcesses, 41, 0, 0},
		{proto.QueryKindInstalledApps, 41, 0, 0},
		{proto.QueryKindFacts, 5000, 0, 0},
		{proto.QueryKindProcesses, 5000, 4000, 6000},
		{proto.QueryKindInstalledApps, 5000, 10000, 12000},
		{proto.QueryKindInstalledApps, 100000, 15000, 15000},
		{proto.QueryKindProcesses, 0, 0, 0},
	}
	for _, c := range cases {
		got := answerWindowMs(c.kind, c.expected)
		if got < c.lo || got > c.hi {
			t.Errorf("answerWindowMs(%s, %d) = %d ms, want %d..%d", c.kind, c.expected, got, c.lo, c.hi)
		}
	}
}
