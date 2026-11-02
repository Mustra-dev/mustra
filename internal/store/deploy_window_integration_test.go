package store

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
)

// The Deploy window's schedule fields survive a round trip, and a run that
// asked to be told is reported finished exactly once, only when every job
// has reached a final state.
func TestDeployWindowScheduleAndFinishedRun(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to disposable Postgres")
	}
	ctx := context.Background()
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	pkg := idgen.New("sw-window-test-")
	if _, e = s.UpsertSoftwarePackage(ctx, SoftwarePackage{ID: pkg, Name: "Dock firmware", Commands: map[string]SoftwareOps{}}); e != nil {
		t.Fatal(e)
	}
	in := ScheduledAction{ID: idgen.New("sch-"), Name: "Dock firmware nightly", PackageID: pkg, Operation: "install", Kind: "daily", TimeOfDay: "03:00",
		AgentIDs: []string{"agt-a", "agt-b"}, GroupIDs: []string{"grp-1"}, AllowReboot: true, ForceRemove: true, ExpireSeconds: 3600,
		OverrideWindows: true, NotifyMessageID: "eun-1", NotifyOnFinish: true}
	out, e := s.UpsertScheduledAction(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	if !slices.Equal(out.AgentIDs, in.AgentIDs) || !slices.Equal(out.GroupIDs, in.GroupIDs) || !out.AllowReboot || !out.ForceRemove ||
		out.ExpireSeconds != 3600 || !out.OverrideWindows || out.NotifyMessageID != "eun-1" || !out.NotifyOnFinish {
		t.Fatalf("schedule fields lost: %+v", out)
	}
	// An older schedule with none of them set reads back empty, not NULL.
	plain, e := s.UpsertScheduledAction(ctx, ScheduledAction{ID: idgen.New("sch-"), Name: "Plain", PackageID: pkg, Operation: "install", Kind: "daily", TimeOfDay: "03:00"})
	if e != nil || plain.AgentIDs == nil || len(plain.AgentIDs) != 0 || plain.NotifyOnFinish {
		t.Fatalf("plain schedule: %+v %v", plain, e)
	}

	for _, id := range []string{"agt-a", "agt-b"} {
		if _, e = s.pool.Exec(ctx, `INSERT INTO agents(agent_id,hostname,os,arch,site) VALUES($1,$1,'windows','amd64','lab') ON CONFLICT DO NOTHING`, id); e != nil {
			t.Fatal(e)
		}
	}
	rev, e := s.SaveDeployDraft(ctx, proto.DeployRevision{ID: idgen.New("rev-"), PackageID: pkg, Label: "1", CreatedBy: "test", Definition: proto.DeployDefinition{Version: 1}})
	if e != nil {
		t.Fatal(e)
	}
	runID := idgen.New("run-")
	jobs := []proto.DeployJob{{ID: idgen.New("djob-"), RunID: runID, AgentID: "agt-a", PackageID: pkg, RevisionID: rev.ID, Operation: "install"},
		{ID: idgen.New("djob-"), RunID: runID, AgentID: "agt-b", PackageID: pkg, RevisionID: rev.ID, Operation: "install"}}
	if e = s.CreateDeployRun(ctx, PatchJobRun{ID: runID, ScheduleName: "Install Dock firmware", TargetDesc: "test", TriggeredBy: "test", NotifyOnFinish: true}, jobs); e != nil {
		t.Fatal(e)
	}
	if e = s.UpdateDeployJob(ctx, jobs[0].ID, "agt-a", "succeeded", "ok"); e != nil {
		t.Fatal(e)
	}
	if run, _, e := s.ClaimFinishedRun(ctx, runID); e != nil || run != nil {
		t.Fatalf("claimed with a job still queued: %v %v", run, e)
	}
	if e = s.UpdateDeployJob(ctx, jobs[1].ID, "agt-b", "failed", "exit 1"); e != nil {
		t.Fatal(e)
	}
	run, counts, e := s.ClaimFinishedRun(ctx, runID)
	if e != nil || run == nil || counts["succeeded"] != 1 || counts["failed"] != 1 || run.ScheduleName != "Install Dock firmware" {
		t.Fatalf("finished run not claimed: %v %v %v", run, counts, e)
	}
	if again, _, e := s.ClaimFinishedRun(ctx, runID); e != nil || again != nil {
		t.Fatalf("claimed twice: %v %v", again, e)
	}
	// A run that did not ask is never claimed.
	quiet := idgen.New("run-")
	if e = s.CreateDeployRun(ctx, PatchJobRun{ID: quiet, ScheduleName: "quiet", TargetDesc: "test", TriggeredBy: "test"}, []proto.DeployJob{{ID: idgen.New("djob-"), RunID: quiet, AgentID: "agt-a", PackageID: pkg, RevisionID: rev.ID, Operation: "install"}}); e != nil {
		t.Fatal(e)
	}
	if r, _, _ := s.ClaimFinishedRun(ctx, quiet); r != nil {
		t.Fatal("claimed a run that did not ask")
	}
}
