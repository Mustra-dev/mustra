package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRestorePsqlArgsWrapTheDumpInOneTransaction(t *testing.T) {
	got := restorePsqlArgs("postgres://x", "pre.sql", "dump.sql", "post.sql")
	want := []string{"--no-psqlrc", "--dbname", "postgres://x", "-v", "ON_ERROR_STOP=1", "--single-transaction",
		"--file", "pre.sql", "--file", "dump.sql", "--file", "post.sql"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

// olderDump is what pg_dump --clean --if-exists wrote before a release
// added a table with a foreign key into users: it drops and recreates
// users and knows nothing of the newer tables.
const olderDump = `SET search_path = '';
ALTER TABLE IF EXISTS ONLY public.users DROP CONSTRAINT IF EXISTS users_pkey;
DROP TABLE IF EXISTS public.users;
CREATE TABLE public.users (id text NOT NULL, name text NOT NULL DEFAULT '');
INSERT INTO public.users (id, name) VALUES ('u1', 'restored');
ALTER TABLE ONLY public.users ADD CONSTRAINT users_pkey PRIMARY KEY (id);
`

// TestRestoreOfAnOlderDumpSurvivesNewerForeignKeys needs a disposable
// Postgres database (its public schema is rewritten) and psql on PATH:
//
//	MUSTRA_TEST_RESTORE_DSN=postgres://user:pass@localhost:5432/scratch?sslmode=disable
func TestRestoreOfAnOlderDumpSurvivesNewerForeignKeys(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_RESTORE_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_RESTORE_DSN to a disposable Postgres database")
	}
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql not on PATH")
	}
	psql := func(args ...string) (string, error) {
		cmd := exec.Command("psql", append([]string{"--no-psqlrc", "-X", "-At", "--dbname", dsn, "-v", "ON_ERROR_STOP=1"}, args...)...)
		cmd.Env = pgToolEnv(dsn)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	setup := `DROP TABLE IF EXISTS public.identities, public.notes, public.credentials, public.users CASCADE;
CREATE TABLE public.users (id text PRIMARY KEY, name text NOT NULL DEFAULT '');
CREATE TABLE public.identities (subject text PRIMARY KEY, user_id text NOT NULL REFERENCES public.users(id) ON DELETE CASCADE);
CREATE TABLE public.notes (id int PRIMARY KEY, user_id text REFERENCES public.users(id) ON DELETE SET NULL);
CREATE TABLE public.credentials (agent_id text PRIMARY KEY, secret_hash text NOT NULL);
INSERT INTO public.users VALUES ('u1', 'live'), ('u2', 'live');
INSERT INTO public.identities VALUES ('s1', 'u1'), ('s2', 'u2');
INSERT INTO public.notes VALUES (1, 'u1'), (2, 'u2'), (3, NULL);
INSERT INTO public.credentials VALUES ('agt-1', 'h');`
	if out, err := psql("-c", setup); err != nil {
		t.Fatalf("setup: %v: %s", err, out)
	}
	t.Cleanup(func() {
		psql("-c", "DROP TABLE IF EXISTS public.identities, public.notes, public.credentials, public.users CASCADE")
	})

	dir := t.TempDir()
	dump := filepath.Join(dir, "database.sql")
	if err := os.WriteFile(dump, []byte(olderDump), 0o600); err != nil {
		t.Fatal(err)
	}

	// The failure this guards against: the bare dump cannot drop users_pkey.
	if out, err := psql("--single-transaction", "--file", dump); err == nil || !strings.Contains(out, "depend") {
		t.Fatalf("expected the bare dump to fail on the dependent foreign key, got err=%v out=%s", err, out)
	}

	pre, post, cleanup, err := restoreWrapperFiles()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	cmd := exec.Command("psql", restorePsqlArgs(dsn, pre, dump, post)...)
	cmd.Env = pgToolEnv(dsn)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restore with the wrapper failed: %v: %s", err, out)
	}

	checks := map[string]string{
		"SELECT string_agg(id || '=' || name, ',' ORDER BY id) FROM public.users":                                                                                           "u1=restored",
		"SELECT string_agg(subject || '=' || user_id, ',' ORDER BY subject) FROM public.identities":                                                                         "s1=u1",
		"SELECT string_agg(id || '=' || coalesce(user_id, '-'), ',' ORDER BY id) FROM public.notes":                                                                         "1=u1,2=-,3=-",
		"SELECT count(*) FROM public.credentials":                                                                                                                           "1",
		"SELECT string_agg(conname, ',' ORDER BY conname) FROM pg_constraint WHERE contype = 'f' AND conrelid IN ('public.identities'::regclass, 'public.notes'::regclass)": "identities_user_id_fkey,notes_user_id_fkey",
	}
	for q, want := range checks {
		got, err := psql("-c", q)
		if err != nil {
			t.Fatalf("%s: %v: %s", q, err, got)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	// The re-added constraint is enforced again.
	if out, err := psql("-c", "INSERT INTO public.identities VALUES ('s9', 'nobody')"); err == nil {
		t.Errorf("foreign key not enforced after restore: %s", out)
	}
}
