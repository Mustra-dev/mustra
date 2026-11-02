package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Drops are booked under the kind that dropped them, with that kind's
// source; what an older agent sends only as a total stays network, as
// before (#123).
func TestSuppressedRecorderRowsByKind(t *testing.T) {
	rows := suppressedRecorderRows(proto.RecorderBatch{AgentID: "agt-1", Suppressed: 15,
		SuppressedByKind: map[string]int{"dns": 10, "registry": 3},
		Sources:          map[string]string{"dns": "etw", "registry": "etw-reg"}})
	got := map[string]int{}
	for _, r := range rows {
		got[r.Op] = r.Count
		if r.Kind != "suppressed" {
			t.Errorf("row kind %q, want suppressed", r.Kind)
		}
		if r.Op == "dns" && r.Source != "etw" {
			t.Errorf("dns drops source %q, want etw", r.Source)
		}
	}
	if len(got) != 3 || got["dns"] != 10 || got["registry"] != 3 || got["network"] != 2 {
		t.Errorf("rows %v, want dns 10, registry 3 and the 2 unsplit as network", got)
	}

	old := suppressedRecorderRows(proto.RecorderBatch{AgentID: "agt-1", Suppressed: 7})
	if len(old) != 1 || old[0].Op != "network" || old[0].Count != 7 {
		t.Errorf("total-only batch: %+v, want one network row of 7", old)
	}
	if none := suppressedRecorderRows(proto.RecorderBatch{AgentID: "agt-1"}); len(none) != 0 {
		t.Errorf("nothing dropped: %+v, want no rows", none)
	}
}
