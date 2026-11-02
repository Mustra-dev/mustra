package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
)

func TestActionRevisionReferencesAndRetirement(t *testing.T) {
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
	id := idgen.New("sw-action-test-")
	if _, e = s.UpsertSoftwarePackage(ctx, SoftwarePackage{ID: id, Name: "Test action", Kind: KindAction, Commands: map[string]SoftwareOps{}}); e != nil {
		t.Fatal(e)
	}
	revisions := []*proto.DeployRevision{}
	for _, label := range []string{"1", "2"} {
		rev, e := s.SaveDeployDraft(ctx, proto.DeployRevision{ID: idgen.New("rev-"), PackageID: id, Label: label, CreatedBy: "test", Definition: proto.DeployDefinition{Version: 2, Kind: "action"}})
		if e != nil {
			t.Fatal(e)
		}
		if e = s.PublishDeployRevision(ctx, *rev); e != nil {
			t.Fatal(e)
		}
		revisions = append(revisions, rev)
	}
	schedule := ScheduledAction{ID: idgen.New("sch-"), Name: "Pinned action", PackageID: id, Operation: "run", RevisionID: revisions[0].ID, Kind: "daily", TimeOfDay: "03:00", Parameters: map[string]string{"input": "private-value"}}
	if _, e = s.UpsertScheduledAction(ctx, schedule); e != nil {
		t.Fatal(e)
	}
	pb := idgen.New("pb-")
	steps := []map[string]any{{"kind": "package", "package_id": id, "operation": "run", "revision_id": revisions[0].ID}, {"kind": "package", "package_id": id, "operation": "run", "revision_id": revisions[0].ID}}
	raw, _ := json.Marshal(steps)
	if _, e = s.pool.Exec(ctx, `INSERT INTO playbooks(id,name,steps,created_by,updated_by) VALUES($1,'Test',$2,'test','test')`, pb, raw); e != nil {
		t.Fatal(e)
	}
	refs, e := s.DeployReferences(ctx, revisions[0].ID)
	if e != nil || len(refs) != 3 {
		t.Fatalf("reference list %d %v", len(refs), e)
	}
	for _, r := range refs {
		encoded, _ := json.Marshal(r)
		var exposed map[string]any
		json.Unmarshal(encoded, &exposed)
		if exposed["parameters"] != nil || exposed["Original"] != nil {
			t.Fatal("private snapshot exposed")
		}
	}
	// A concurrent edit must prevent every selected update, including other owners.
	if _, e = s.pool.Exec(ctx, `UPDATE scheduled_actions SET name='Changed' WHERE id=$1`, schedule.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.UpdateDeployReferences(ctx, revisions[0].ID, revisions[1].ID, "test", refs); e == nil {
		t.Fatal("stale preview accepted")
	}
	got, e := s.DeployReferences(ctx, revisions[0].ID)
	if e != nil || len(got) != 3 {
		t.Fatal("partial update committed", e)
	}
	if e = s.UpdateDeployReferences(ctx, revisions[0].ID, revisions[1].ID, "test", got); e != nil {
		t.Fatal(e)
	}
	got, e = s.DeployReferences(ctx, revisions[0].ID)
	if e != nil || len(got) != 0 {
		t.Fatal("old references remain", e)
	}
	if e = s.RetireDeployRevision(ctx, revisions[1].ID, false, "", "test"); e != nil {
		t.Fatal(e)
	}
	rev, e := s.GetDeployRevision(ctx, revisions[1].ID)
	if e != nil || !rev.Retired {
		t.Fatal("retirement not retained", e)
	}
	pkg, e := s.GetSoftwarePackage(ctx, id)
	if e != nil || pkg.DeployRevision != revisions[0].ID {
		t.Fatal("active fallback not selected", e)
	}
	if e = s.UpdateDeployReferences(ctx, revisions[0].ID, revisions[1].ID, "test", nil); e == nil {
		t.Fatal("retired replacement accepted")
	}
	if e = s.RetireDeployRevision(ctx, revisions[0].ID, true, "", "test"); e != nil {
		t.Fatal(e)
	}
	pkg, e = s.GetSoftwarePackage(ctx, id)
	if e != nil || pkg.Enabled {
		t.Fatal("retired package still enabled", e)
	}
	if e = applySchema(ctx, s.pool); e != nil {
		t.Fatal("repeat migration", e)
	}
}
