package server

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeArchive builds a minimal archive the way createBackup does, so the
// reader can be tested without a database behind it.
func writeArchive(t *testing.T, dir, id string, m BackupManifest, members map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, id+".tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range members {
		if err := writeTarFile(tw, name, []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	blob, _ := json.Marshal(m)
	if err := writeTarFile(tw, backupManifestName, blob); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadManifestRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := BackupManifest{ID: "bk-1", CreatedBy: "admin", ServerVersion: "0.67.2", Note: "before an upgrade"}
	path := writeArchive(t, dir, "bk-1", want, map[string]string{backupDatabaseName: "-- dump\n"})

	got, err := readManifest(path)
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if got.ID != want.ID || got.Note != want.Note || got.ServerVersion != want.ServerVersion {
		t.Fatalf("manifest round-trip lost data: %+v", got)
	}
}

// A file that is not one of ours must be refused by name, before a restore
// starts pushing its contents at psql.
func TestReadManifestRejectsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "notes.tar.gz")
	if err := os.WriteFile(plain, []byte("this is not a gzip archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(plain); err == nil {
		t.Fatal("a non-archive was accepted as a backup")
	}

	noManifest := writeArchive(t, dir, "bk-empty", BackupManifest{}, nil)
	// Rewrite it without the manifest member.
	f, _ := os.Create(noManifest)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	_ = writeTarFile(tw, "something-else", []byte("x"))
	tw.Close()
	gz.Close()
	f.Close()
	if _, err := readManifest(noManifest); err == nil {
		t.Fatal("an archive with no manifest was accepted as a backup")
	}
}

// backupPath is fed straight from a URL, so it has to refuse anything that
// climbs out of the backup directory.
func TestBackupPathRefusesTraversal(t *testing.T) {
	for _, id := range []string{"", "../../etc/passwd", "a/b", "..\\win", ".."} {
		if _, err := backupPath(id); err == nil {
			t.Errorf("backupPath(%q) was accepted", id)
		}
	}
}

// A restore extracts operator-supplied archives, so a member whose path
// climbs out of the destination must be refused rather than written.
func TestExtractIntoRefusesEscapingMembers(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		backupPackageDir + "/../../escaped",
		backupPackageDir + "/",
	} {
		hdr := &tar.Header{Name: name, Size: 0}
		if _, err := extractInto(strings.NewReader(""), hdr, root, backupPackageDir+"/"); err == nil {
			t.Errorf("extractInto accepted %q", name)
		}
	}
}

func TestListBackupsIsNewestFirstAndSkipsJunk(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MUSTRA_BACKUP_DIR", dir)

	older := BackupManifest{ID: "bk-old"}
	older.CreatedAt = older.CreatedAt.AddDate(2020, 0, 0)
	newer := BackupManifest{ID: "bk-new"}
	newer.CreatedAt = newer.CreatedAt.AddDate(2030, 0, 0)
	writeArchive(t, dir, "bk-old", older, map[string]string{backupDatabaseName: "x"})
	writeArchive(t, dir, "bk-new", newer, map[string]string{backupDatabaseName: "x"})
	// Not an archive; must be skipped rather than breaking the listing.
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{logger: slog.Default()}
	got, err := s.listBackups()
	if err != nil {
		t.Fatalf("listBackups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 backups, got %d", len(got))
	}
	if got[0].ID != "bk-new" {
		t.Errorf("backups are not newest-first: %s came first", got[0].ID)
	}
}

func TestPruneKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MUSTRA_BACKUP_DIR", dir)

	for i, id := range []string{"bk-1", "bk-2", "bk-3"} {
		m := BackupManifest{ID: id}
		m.CreatedAt = m.CreatedAt.AddDate(2000+i, 0, 0)
		writeArchive(t, dir, id, m, map[string]string{backupDatabaseName: "x"})
	}
	s := &Server{logger: slog.Default()}
	s.pruneBackups(2)

	got, err := s.listBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(got))
	}
	if got[0].ID != "bk-3" || got[1].ID != "bk-2" {
		t.Errorf("pruned the wrong ones; kept %s and %s", got[0].ID, got[1].ID)
	}
}

// keep=0 would mean "delete everything"; it must be treated as a misread
// setting and do nothing rather than empty the directory.
func TestPruneRefusesToDeleteEverything(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MUSTRA_BACKUP_DIR", dir)
	writeArchive(t, dir, "bk-1", BackupManifest{ID: "bk-1"}, map[string]string{backupDatabaseName: "x"})

	s := &Server{logger: slog.Default()}
	s.pruneBackups(0)

	got, _ := s.listBackups()
	if len(got) != 1 {
		t.Fatalf("prune with keep=0 removed backups; %d left", len(got))
	}
}

// A file that is not a mustra backup is the caller's mistake, not a
// server fault: the restore refuses it, which the handler answers 422,
// rather than failing it as a 500.
func TestRestoreRefusesFilesThatAreNotBackups(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MUSTRA_BACKUP_SIGNING_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	notGzip := filepath.Join(dir, "notes.tar.gz")
	if err := os.WriteFile(notGzip, []byte("this is not a gzip archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	noManifest := filepath.Join(dir, "no-manifest.tar.gz")
	writeRawArchive(t, noManifest, [][2]string{{"something-else", "x"}})
	noDump := writeArchive(t, dir, "bk-nodump", BackupManifest{ID: "bk-nodump"}, nil)
	blob, _ := json.Marshal(BackupManifest{ID: "bk-two"})
	twoDumps := filepath.Join(dir, "two-dumps.tar.gz")
	writeRawArchive(t, twoDumps, [][2]string{
		{backupDatabaseName, "-- one\n"}, {backupDatabaseName, "-- two\n"}, {backupManifestName, string(blob)},
	})

	unsafe := writeArchive(t, dir, "bk-unsafe", BackupManifest{ID: "bk-unsafe"},
		map[string]string{backupPackageDir + "/../escape": "x", backupDatabaseName: "-- dump\n"})
	large := writeArchive(t, dir, "bk-large", BackupManifest{ID: "bk-large"},
		map[string]string{backupDatabaseName: strings.Repeat("-- padding\n", 1000)})

	s := &Server{logger: slog.Default()}
	refused := func(name, path string) {
		t.Helper()
		_, err := s.restoreBackup(t.Context(), path, "root", true)
		if !errors.Is(err, errRestoreRefused) {
			t.Errorf("%s: got %v, want a refusal", name, err)
		}
	}
	for name, path := range map[string]string{
		"not gzip": notGzip, "no manifest": noManifest, "no dump": noDump, "two dumps": twoDumps,
		"unsafe path": unsafe,
	} {
		refused(name, path)
	}
	t.Setenv("MUSTRA_RESTORE_MAX_BYTES", "4096")
	refused("too large", large)

	// A file the server cannot read is its own fault, not the archive's.
	_, err := s.restoreBackup(t.Context(), filepath.Join(dir, "gone.tar.gz"), "root", true)
	if err == nil || errors.Is(err, errRestoreRefused) {
		t.Errorf("a missing file: got %v, want a failure that is not a refusal", err)
	}
}

// writeRawArchive writes members in order, duplicates included, which
// writeArchive's map cannot express.
func writeRawArchive(t *testing.T, path string, members [][2]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		if err := writeTarFile(tw, m[0], []byte(m[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// io.Discard would be quieter, but these tests deliberately exercise the
// warn paths (an unreadable archive is skipped, not fatal) and seeing them
// while a test is being written is worth the noise.
var _ = slog.Default
