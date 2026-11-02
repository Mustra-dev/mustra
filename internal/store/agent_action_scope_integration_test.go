package store

import (
	"context"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
)

// An action id names one agent's action, and a result is attributed to an
// agent from its subject. A result from another agent must not close or
// advance it (defence in depth; coordinator finding).
func TestAgentActionUpdatesScopedByAgentID(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	owner := idgen.New("agt-")
	other := idgen.New("agt-")
	for _, id := range []string{owner, other} {
		if err := s.UpsertOnRegister(ctx, id, proto.AgentInfo{Hostname: id}); err != nil {
			t.Fatal(err)
		}
	}
	actionID := idgen.New("act-")
	if err := s.StartAgentAction(ctx, AgentAction{ID: actionID, AgentID: owner, Kind: "patch_apply",
		Summary: "x", RequestedBy: "t"}); err != nil {
		t.Fatal(err)
	}

	// Another agent cannot advance it.
	if err := s.SetAgentActionProgress(ctx, other, actionID, "installing", "hijack"); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetAgentAction(ctx, actionID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status == "installing" || a.Detail == "hijack" {
		t.Fatalf("another agent advanced the action: status=%q detail=%q", a.Status, a.Detail)
	}

	// Another agent cannot close it.
	if err := s.FinishAgentAction(ctx, other, actionID, "failed", "hijack"); err != nil {
		t.Fatal(err)
	}
	if a, _ = s.GetAgentAction(ctx, actionID); a.FinishedAt != nil || a.Status == "failed" {
		t.Fatalf("another agent closed the action: status=%q finished=%v", a.Status, a.FinishedAt)
	}

	// The owning agent still can.
	if err := s.SetAgentActionProgress(ctx, owner, actionID, "installing", "real"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishAgentAction(ctx, owner, actionID, "succeeded", "done"); err != nil {
		t.Fatal(err)
	}
	a, _ = s.GetAgentAction(ctx, actionID)
	if a.Status != "succeeded" || a.FinishedAt == nil {
		t.Fatalf("owning agent could not close its own action: %+v", a)
	}

	// The empty-agent escape hatch (server-internal callers) still works.
	a2 := idgen.New("act-")
	if err := s.StartAgentAction(ctx, AgentAction{ID: a2, AgentID: owner, Kind: "k", Summary: "x", RequestedBy: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishAgentAction(ctx, "", a2, "expired", "server"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetAgentAction(ctx, a2); got.Status != "expired" {
		t.Fatalf("unscoped finish did not apply: %q", got.Status)
	}
}
