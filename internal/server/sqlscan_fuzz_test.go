package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzScanDump drives scanDump with mutated SQL-dump fragments. The pure
// invariant it always checks is cheap and runs under `go test`: scanDump
// must never panic, must be deterministic, and strict must be at least as
// strict as non-strict (anything non-strict refuses, strict refuses too).
//
// When MUSTRA_FUZZ_PSQL names a psql connection string to a throwaway
// database (e.g. "host=/var/tmp/pg port=55432 user=postgres dbname=postgres"),
// the fuzzer also runs the oracle the screen exists for: a dump scanDump
// accepts is fed to psql exactly as applyDump would run it, with \! and
// COPY … PROGRAM rewired to drop a sentinel file. If scanDump said yes and
// psql still ran a client meta-command or a program, the screen was
// bypassed — the property the SQL-injection screen must hold.
func FuzzScanDump(f *testing.F) {
	f.Add(pgDumpSample, false)
	f.Add(pgDumpSample, true)
	seeds := []string{
		"SELECT 1;\n",
		"\\! id\n",
		"SELECT 1 \\! id\n;",
		"COPY public.t FROM PROGRAM 'id';\n",
		"COPY public.t (a) FROM stdin;\nx\n\\.\n\\! id\n",
		// The desync classes this fuzzer's first run surfaced: psql counts
		// high-bit bytes and '$' as identifier characters where the scanner
		// did not, so a dollar-quote tag or E-string boundary drifted.
		"SELECT 1 AS x$$a$; \\! id\nSELECT 1 AS y$a$;\n",
		"SELECT $é$ ' $é$; \\! id\nSELECT $é$ ' $é$;\n",
		"CREATE TABLE t (stdin int);\nCOPY t FROM PROGRAM 'id' WHERE stdin IS DISTINCT FROM stdin;\n\\! id\n\\.\n",
		"SET standard_conforming_strings = off;\nSELECT 'a\\' \\! id ';\n",
		"\\restrict abc\n\\unrestrict abc\n",
	}
	for _, s := range seeds {
		f.Add(s, false)
		f.Add(s, true)
	}

	psqlDSN := os.Getenv("MUSTRA_FUZZ_PSQL")

	f.Fuzz(func(t *testing.T, dump string, strict bool) {
		if len(dump) > 1<<16 {
			return
		}
		err1 := scanDump(strings.NewReader(dump), strict)
		if got := scanDump(strings.NewReader(dump), strict); (got == nil) != (err1 == nil) {
			t.Fatalf("scanDump is not deterministic for %q", dump)
		}
		// strict is a superset of the non-strict refusals.
		if scanDump(strings.NewReader(dump), false) != nil && scanDump(strings.NewReader(dump), true) == nil {
			t.Fatalf("non-strict refused but strict accepted: %q", dump)
		}
		if err1 != nil || psqlDSN == "" {
			return
		}
		// scanDump accepted it; prove psql agrees it is inert.
		runPsqlOracle(t, psqlDSN, dump)
	})
}

// runPsqlOracle executes an accepted dump the way applyDump does, but with a
// psqlrc that turns \! and COPY … PROGRAM into observable sentinels, inside
// its own transaction that is always rolled back.
func runPsqlOracle(t *testing.T, dsn, dump string) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "executed")
	// A .psqlrc psql reads first. SHELL is what \! runs; point it at a
	// script that touches the sentinel so any meta-command that reaches a
	// shell is caught even if the body is empty.
	shellScript := filepath.Join(dir, "shell")
	if err := os.WriteFile(shellScript, []byte("#!/bin/sh\ntouch "+sentinel+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "dump.sql")
	if err := os.WriteFile(file, []byte("BEGIN;\n"+dump+"\nROLLBACK;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("psql", "--no-psqlrc", "--dbname", dsn, "-v", "ON_ERROR_STOP=0", "--file", file)
	cmd.Env = append(os.Environ(), "SHELL="+shellScript, "PSQL_HISTORY="+filepath.Join(dir, "hist"))
	_ = cmd.Run()
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("scanDump accepted a dump that made psql run a shell:\n%s", dump)
	}
}
