package store

import (
	"context"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// A pending approval names the playbook it belongs to, so an API client
// need not look the run up. That includes a pause an older server parked
// without recording it.
func TestPlaybookPauseNamesItsPlaybook(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to disposable Postgres")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	pbID := idgen.New("pb-pause-test-")
	if _, err = s.pool.Exec(ctx, `INSERT INTO playbooks (id, name) VALUES ($1, 'pause test')`, pbID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM playbooks WHERE id = $1`, pbID) })
	newRun := func() string {
		id := idgen.New("run-pause-test-")
		if err := s.StartPlaybookRun(ctx, PlaybookRun{ID: id, PlaybookID: pbID, Name: "pause test"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM playbook_runs WHERE id = $1`, id) })
		return id
	}

	runID := newRun()
	if err := s.CreatePlaybookPause(ctx, PlaybookPause{RunID: runID, StepIndex: 1, StepName: "approve"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPlaybookPause(ctx, runID)
	if err != nil || got == nil {
		t.Fatalf("get pause: %v %v", got, err)
	}
	if got.PlaybookID != pbID {
		t.Fatalf("playbook_id = %q, want %q", got.PlaybookID, pbID)
	}
	list, err := s.ListPlaybookPauses(ctx, "pending")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range list {
		if p.RunID == runID {
			found = true
			if p.PlaybookID != pbID {
				t.Fatalf("listed playbook_id = %q, want %q", p.PlaybookID, pbID)
			}
		}
	}
	if !found {
		t.Fatal("the pause is not listed")
	}

	// A pause as an older server wrote it.
	legacyRun := newRun()
	if _, err = s.pool.Exec(ctx, `INSERT INTO playbook_run_pauses (run_id, step_index) VALUES ($1, 0)`, legacyRun); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetPlaybookPause(ctx, legacyRun)
	if err != nil || got == nil {
		t.Fatalf("get legacy pause: %v %v", got, err)
	}
	if got.PlaybookID != pbID {
		t.Fatalf("legacy playbook_id = %q, want %q", got.PlaybookID, pbID)
	}
}
