package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// An agent older than the restart support would install and never
// restart, so the choice is refused rather than silently dropped.
func TestPatchRestartUnsupportedReason(t *testing.T) {
	for _, c := range []struct {
		mode, version string
		refused       bool
	}{
		{"", "0.50.0", false},
		{"if_required", "0.57.1", true},
		{"always", "0.57.2", false},
		{"always", "0.58.0", false},
	} {
		got := patchRestart{Mode: c.mode, WarnMinutes: 5}.unsupportedReason(store.AgentRecord{AgentVersion: c.version})
		if (got != "") != c.refused {
			t.Errorf("%q on %s: reason %q, refused want %v", c.mode, c.version, got, c.refused)
		}
	}
}
