package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// A save answers with the ceiling as stored, so the caller sees the time
// the database stamped rather than the zero time it sent.
func TestUpsertActionGroupAnswersTheStoredRow(t *testing.T) {
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

	module := idgen.New("test-module-")
	t.Cleanup(func() { _ = s.DeleteActionGroup(context.Background(), module) })

	before := time.Now().Add(-time.Minute)
	got, err := s.UpsertActionGroup(ctx, ActionGroup{Module: module, GroupIDs: nil, Enabled: true, UpdatedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if got.UpdatedAt.Before(before) {
		t.Fatalf("updated_at = %v, want the time of the save", got.UpdatedAt)
	}
	if got.Module != module || !got.Enabled || got.UpdatedBy != "alice" || got.GroupIDs == nil {
		t.Fatalf("save answered %+v", got)
	}

	// An update stamps a new time too.
	first := got.UpdatedAt
	got, err = s.UpsertActionGroup(ctx, ActionGroup{Module: module, GroupIDs: []string{"g1"}, UpdatedBy: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if got.UpdatedAt.Before(first) || got.Enabled || got.UpdatedBy != "bob" || len(got.GroupIDs) != 1 {
		t.Fatalf("update answered %+v", got)
	}
}
