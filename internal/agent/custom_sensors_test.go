package agent

import (
	"strings"
	"testing"
)

// A custom sensor runs a command somebody wrote, so its output is entirely
// unbounded — a typo can cat a logfile. These bounds are what keep one bad
// sensor from turning into a fleet-wide flood of oversized messages.
func TestSplitSensorLinesBoundsOutput(t *testing.T) {
	t.Run("splits and trims carriage returns", func(t *testing.T) {
		got := splitSensorLines([]byte("alpha\r\nbeta\ngamma\n"))
		want := []string{"alpha", "beta", "gamma"}
		if len(got) != len(want) {
			t.Fatalf("got %d lines %q, want %d", len(got), got, len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("line %d = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("caps the number of lines", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < maxCustomSensorLines*3; i++ {
			b.WriteString("line\n")
		}
		got := splitSensorLines([]byte(b.String()))
		if len(got) > maxCustomSensorLines+1 { // +1 for the truncation marker
			t.Fatalf("got %d lines, want at most %d", len(got), maxCustomSensorLines+1)
		}
		if !strings.Contains(got[len(got)-1], "truncated") {
			t.Errorf("truncation was not announced, last line is %q", got[len(got)-1])
		}
	})

	t.Run("empty output is no lines, not one empty line", func(t *testing.T) {
		if got := splitSensorLines(nil); len(got) != 0 {
			t.Fatalf("got %q, want no lines", got)
		}
	})
}

// The command is server-authored, but quoting it wrong would break the
// update on every Windows endpoint at once rather than one of them.
func TestPSQuote(t *testing.T) {
	cases := map[string]string{
		"simple":          "'simple'",
		"it's":            "'it''s'",
		"a 'quoted' word": "'a ''quoted'' word'",
		"":                "''",
	}
	for in, want := range cases {
		if got := psQuote(in); got != want {
			t.Errorf("psQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
