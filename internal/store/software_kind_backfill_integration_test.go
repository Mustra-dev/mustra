package store

import (
	"context"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// Adopting software saved its package with kind "" (#119). The schema
// gives such a package the kind it was always read as, and leaves an
// action package alone.
func TestSchemaGivesAdoptedPackagesTheirKind(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close) // first registered, last run: the row cleanup needs the pool

	pkgs := []struct{ id, stored, want string }{
		{idgen.New("sw-"), "", KindSoftware},
		{idgen.New("sw-"), KindAction, KindAction},
	}
	for _, p := range pkgs {
		if _, err := s.pool.Exec(ctx, `INSERT INTO software_packages (id, kind, name) VALUES ($1, $2, 'kind backfill')`, p.id, p.stored); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.DeleteSoftwarePackage(context.Background(), p.id) })
	}
	// Twice: the schema runs on every start.
	for range 2 {
		s2, err := Open(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		s2.Close()
	}
	for _, p := range pkgs {
		var kind string
		if err := s.pool.QueryRow(ctx, `SELECT kind FROM software_packages WHERE id = $1`, p.id).Scan(&kind); err != nil {
			t.Fatal(err)
		}
		if kind != p.want {
			t.Errorf("package stored with kind %q: %q after the schema, want %q", p.stored, kind, p.want)
		}
	}
}

// A package saved without a kind is software, as every path reads it,
// whichever handler built it.
func TestPackageSavedWithoutAKindIsSoftware(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close) // first registered, last run: the row cleanup needs the pool

	out, err := s.UpsertSoftwarePackage(ctx, SoftwarePackage{ID: idgen.New("sw-"), Name: "no kind", Commands: map[string]SoftwareOps{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteSoftwarePackage(context.Background(), out.ID) })
	if out.Kind != KindSoftware {
		t.Errorf("saved without a kind: kind %q, want %q", out.Kind, KindSoftware)
	}
}
