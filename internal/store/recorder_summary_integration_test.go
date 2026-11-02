package store

import (
	"context"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
)

// An endpoint that reported a kind's events and a suppressed row for it is
// one endpoint, not one per source; the suppressed row's empty source is
// not a source (#123).
func TestRecorderSummaryCountsEachEndpointOncePerKind(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	run := idgen.New("")[:12]
	kind := "kind-" + run // a kind only this run writes
	a, b := "agt-rsum-a-"+run, "agt-rsum-b-"+run
	for _, id := range []string{a, b} {
		if err := s.UpsertOnRegister(ctx, id, proto.AgentInfo{Hostname: id, OS: "linux", Arch: "amd64"}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if err := s.InsertRecorderEvents(ctx, []RecorderEvent{
		{AgentID: a, Kind: kind, At: now, Count: 3, Summary: "x", Source: "netpoll"},
		{AgentID: a, Kind: "suppressed", Op: kind, At: now, Count: 40, Summary: "dropped"},
		{AgentID: b, Kind: kind, At: now, Count: 2, Summary: "y", Source: "netpoll"},
		{AgentID: b, Kind: kind, At: now, Count: 1, Summary: "z", Source: "ebpf"},
	}); err != nil {
		t.Fatal(err)
	}
	sum, err := s.RecorderEventSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := sum[kind]
	if got.Endpoints != 2 || got.Events != 6 || got.Suppressed != 40 {
		t.Errorf("summary %+v, want 2 endpoints, 6 events, 40 suppressed", got)
	}
	if len(got.Sources) != 2 || got.Sources["netpoll"] != 2 || got.Sources["ebpf"] != 1 {
		t.Errorf("sources %v, want netpoll 2 and ebpf 1, no empty key", got.Sources)
	}
}

// A file event a signal matched names the signal, as a recorder event
// does; only indicators were joined before (#123).
func TestFileEventMatchedBySignalHasItsName(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	run := idgen.New("")[:12]
	agent, sig := "agt-fev-"+run, "sig-"+run
	if err := s.UpsertOnRegister(ctx, agent, proto.AgentInfo{Hostname: agent, OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSignal(ctx, Signal{ID: sig, Name: "Cron or sudoers changed " + run, Severity: "high", Expression: `path contains "/etc/sudoers"`, Objects: []string{"file"}, Enabled: true, CreatedBy: "t"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteSignal(context.Background(), sig) })
	if err := s.InsertFileEvents(ctx, []FileEvent{{AgentID: agent, Path: "/etc/sudoers.d/deploy", Op: "write", At: time.Now().UTC(), Count: 1, MatchedIOC: sig}}); err != nil {
		t.Fatal(err)
	}
	evs, err := s.ListFileEvents(ctx, agent, true, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].IOCName != "Cron or sudoers changed "+run {
		t.Fatalf("events %+v, want one named after the signal", evs)
	}
}
