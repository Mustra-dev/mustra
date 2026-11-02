package store

import (
	"context"
	"slices"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// Exposure rows follow what the briefings find: added once with their
// first-seen time kept, removed when the endpoint is no longer vulnerable,
// and attempts counted up to giving up.
func TestThreatExposuresFollowTheBriefings(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	brief := idgen.New("kev-test-")
	a1, a2 := testAgent(t, s), testAgent(t, s)
	t.Cleanup(func() { _, _ = s.SyncThreatExposures(context.Background(), map[string][]string{}) })

	got, err := s.SyncThreatExposures(ctx, map[string][]string{brief: {a1, a2}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[brief]) != 2 {
		t.Fatalf("exposures = %+v", got[brief])
	}
	first := got[brief][a1].FirstSeen

	if err := s.RecordThreatPatchAttempt(ctx, []string{brief}, []string{a1}, "run-1", 3); err != nil {
		t.Fatal(err)
	}
	got, err = s.SyncThreatExposures(ctx, map[string][]string{brief: {a1}})
	if err != nil {
		t.Fatal(err)
	}
	e := got[brief][a1]
	if _, still := got[brief][a2]; still {
		t.Fatal("an endpoint no longer vulnerable kept its exposure")
	}
	if !e.FirstSeen.Equal(first) || e.Attempts != 1 || e.LastRunID != "run-1" || e.LastAttempt == nil || e.GaveUp {
		t.Fatalf("after one attempt: %+v", e)
	}
	for range 2 {
		if err := s.RecordThreatPatchAttempt(ctx, []string{brief}, []string{a1}, "run-n", 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkThreatOverdueNotified(ctx, []string{brief}, []string{a1}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.SyncThreatExposures(ctx, map[string][]string{brief: {a1}})
	if e := got[brief][a1]; e.Attempts != 3 || !e.GaveUp || !e.OverdueNotified {
		t.Fatalf("after three attempts: %+v", e)
	}
	// Fixed and then vulnerable again: a new exposure, counted afresh.
	_, _ = s.SyncThreatExposures(ctx, map[string][]string{})
	got, _ = s.SyncThreatExposures(ctx, map[string][]string{brief: {a1}})
	if e := got[brief][a1]; e.Attempts != 0 || e.GaveUp || e.OverdueNotified {
		t.Fatalf("a new exposure inherited the old one's state: %+v", e)
	}
}

// A patch job's package list reads back as stored; no list is nil, which
// means everything pending, and must stay distinct from an empty list.
func TestActionPatchOnlyRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	agent := testAgent(t, s)
	act := AgentAction{ID: idgen.New("act-"), RunID: idgen.New("run-"), AgentID: agent, Kind: "patch_apply", Summary: "test"}
	if err := s.StartAgentAction(ctx, act); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ActionPatchOnly(ctx, act.ID); err != nil || got != nil {
		t.Fatalf("unset list = %v, %v; want nil", got, err)
	}
	if err := s.SetActionPatchOnly(ctx, act.ID, []string{"libssl3t64", "openssl"}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ActionPatchOnly(ctx, act.ID); err != nil || !slices.Equal(got, []string{"libssl3t64", "openssl"}) {
		t.Fatalf("list = %v, %v", got, err)
	}
	if err := s.SetActionPatchOnly(ctx, act.ID, []string{}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ActionPatchOnly(ctx, act.ID); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty list = %#v, %v; want non-nil empty", got, err)
	}
}
