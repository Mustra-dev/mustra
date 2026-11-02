package store

import (
	"context"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// The schema carries the old Self Service catalog into the package model
// once per item. It used to run on every start, so a carried package an
// operator deleted came back at the next restart.
func TestCatalogItemsCarryIntoPackagesOnce(t *testing.T) {
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
	exists := func(id string) bool {
		t.Helper()
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM software_packages WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	reopen := func() {
		t.Helper()
		s2, err := Open(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		s2.Close()
	}
	cleanup := func(id string) {
		t.Cleanup(func() {
			_, _ = s.pool.Exec(context.Background(), `DELETE FROM software_packages WHERE id = $1`, id)
			_, _ = s.pool.Exec(context.Background(), `DELETE FROM catalog_items WHERE id = $1`, id)
		})
	}

	t.Run("an item not yet carried is carried once", func(t *testing.T) {
		// What a release from before the package model leaves behind.
		id := idgen.New("cat-carry-test-")
		cleanup(id)
		if _, err := s.pool.Exec(ctx, `INSERT INTO catalog_items (id, name, packages, group_ids, allow_requests, enabled, carried_to_packages)
VALUES ($1, 'Carry test', '{"linux":"jq"}', '{}', false, true, false)`, id); err != nil {
			t.Fatal(err)
		}
		reopen()
		p, err := s.GetSoftwarePackage(ctx, id)
		if err != nil || p == nil {
			t.Fatalf("item was not carried into the package model: %v %v", p, err)
		}
		if !p.SelfService || p.AllowRequests || p.Commands["linux"].Install != "jq" {
			t.Fatalf("carried package lost the item's settings: %+v", p)
		}
		if _, err := s.pool.Exec(ctx, `DELETE FROM software_packages WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		reopen()
		if exists(id) {
			t.Fatal("a deleted package came back from catalog_items on the next start")
		}
	})

	t.Run("upgrading from the every-start backfill copies nothing more", func(t *testing.T) {
		// A database from a build that still had the every-start backfill:
		// no flag column, and an item whose package has since been deleted.
		// This drops the flag column on the shared database the DSN names,
		// which is why that has to be a disposable one; the next Open
		// below adds it back.
		if _, err := s.pool.Exec(ctx, `ALTER TABLE catalog_items DROP COLUMN IF EXISTS carried_to_packages`); err != nil {
			t.Fatal(err)
		}
		id := idgen.New("cat-upgrade-test-")
		cleanup(id)
		if _, err := s.pool.Exec(ctx, `INSERT INTO catalog_items (id, name, packages) VALUES ($1, 'Upgrade test', '{"windows":"Git.Git"}')`, id); err != nil {
			t.Fatal(err)
		}
		reopen()
		if exists(id) {
			t.Fatal("the upgrade re-copied an item the old backfill had already had its chance at")
		}
		var carried bool
		if err := s.pool.QueryRow(ctx, `SELECT carried_to_packages FROM catalog_items WHERE id = $1`, id).Scan(&carried); err != nil {
			t.Fatal(err)
		}
		if !carried {
			t.Fatal("an existing item was left uncarried, so a later start could still copy it")
		}
		reopen()
		if exists(id) {
			t.Fatal("a repeated start copied the item")
		}
	})
}
