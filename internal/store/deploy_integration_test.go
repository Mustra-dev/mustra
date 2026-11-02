package store

import (
	"context"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"os"
	"testing"
)

func TestDeployRevisionPersistence(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = applySchema(ctx, s.pool); e != nil {
		t.Fatal("repeated migration:", e)
	}
	id := idgen.New("sw-integration-")
	_, e = s.UpsertSoftwarePackage(ctx, SoftwarePackage{ID: id, Name: "Integration", Kind: KindSoftware, Commands: map[string]SoftwareOps{}, Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	rev, e := s.SaveDeployDraft(ctx, proto.DeployRevision{ID: idgen.New("rev-integration-"), PackageID: id, Label: "1", CreatedBy: "test", Definition: proto.DeployDefinition{Version: 1, Variants: []proto.DeployVariant{{ID: "unix", OS: "darwin"}}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.PublishDeployRevision(ctx, *rev); e != nil {
		t.Fatal(e)
	}
	if e = s.PublishDeployRevision(ctx, *rev); e == nil {
		t.Fatal("published revision was mutable")
	}
	pkg, e := s.GetSoftwarePackage(ctx, id)
	if e != nil || pkg.DeployDefinition == nil || pkg.DeployRevision != rev.ID {
		t.Fatalf("revision projection: %#v %v", pkg, e)
	}
	pkg.Name = "Renamed"
	pkg, e = s.UpsertSoftwarePackage(ctx, *pkg)
	if e != nil || pkg.DeployRevision != rev.ID {
		t.Fatal("legacy metadata save lost revision", e)
	}
	if _, e = s.ListSoftwarePackages(ctx); e != nil {
		t.Fatal(e)
	}
	sensor, e := s.UpsertCustomSensor(ctx, CustomSensor{ID: "csn-input-test", Name: "Inputs", Commands: map[string]string{"darwin": "echo test"}, Parameters: []proto.DeployParameter{{Name: "path", Type: "text", Default: "x"}}})
	if e != nil {
		t.Fatal(e)
	}
	if len(sensor.Parameters) != 1 {
		t.Fatal("sensor input schema lost")
	}
	schedule, e := s.UpsertScheduledAction(ctx, ScheduledAction{ID: "sched-input-test", Name: "Pinned", PackageID: id, Operation: "install", Kind: "daily", TimeOfDay: "03:00", RevisionID: rev.ID})
	if e != nil {
		t.Fatal(e)
	}
	if schedule.RevisionID != rev.ID || schedule.FollowLatest {
		t.Fatal("schedule pin lost")
	}
	agent := idgen.New("agt-deploy-test-")
	if _, e = s.pool.Exec(ctx, `INSERT INTO agents(agent_id,hostname,os,arch,site) VALUES($1,'test','darwin','arm64','test')`, agent); e != nil {
		t.Fatal(e)
	}
	run := PatchJobRun{ID: idgen.New("run-test-"), ScheduleName: "test", TriggeredBy: "test"}
	job := proto.DeployJob{ID: idgen.New("act-test-"), RunID: run.ID, AgentID: agent, PackageID: id, RevisionID: rev.ID}
	if e = s.CreateDeployRun(ctx, run, []proto.DeployJob{job}, true); e != nil {
		t.Fatal(e)
	}
	got, e := s.GetDeployJob(ctx, job.ID)
	if e != nil || got.Status != "held" {
		t.Fatal("held rollout", got, e)
	}
	if e = s.CancelHeldDeployJobs(ctx, run.ID, "not released"); e != nil {
		t.Fatal(e)
	}
	got, e = s.GetDeployJob(ctx, job.ID)
	if e != nil || got.Status != "cancelled" {
		t.Fatal("held cleanup", got, e)
	}
	if _, e = s.pool.Exec(ctx, `DELETE FROM agents WHERE agent_id=$1`, agent); e != nil {
		t.Fatal("history prevented endpoint deletion", e)
	}
	if got, e = s.GetDeployJob(ctx, job.ID); e != nil || got == nil {
		t.Fatal("deployment history lost on endpoint deletion", e)
	}

}
