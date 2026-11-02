package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// A second update request for the same endpoint within updateResend is
// not sent: two at once is how agents before 0.57.4 lost their binary.
func TestUpdateIsNotResentWhileRecent(t *testing.T) {
	s := &Server{}
	s.updateSent.Store("agt-1", time.Now().Add(-time.Minute))
	out := s.updateAgentWith(context.Background(), store.AgentRecord{AgentID: "agt-1", Hostname: "pbs"}, false)
	if out.Started || !strings.Contains(out.Detail, "already asked") {
		t.Fatalf("got %+v, want a refusal", out)
	}
}
