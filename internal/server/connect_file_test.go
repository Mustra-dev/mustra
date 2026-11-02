package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestFileExportsStayInExportDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MUSTRA_EXPORT_DIR", dir)
	outside := filepath.Join(t.TempDir(), "victim.csv")
	for _, target := range []string{outside, "/etc/cron.d/x.csv", "../x.csv", "a/../../x.csv", filepath.Join(dir, "..", "x.csv")} {
		if err := deliverFileAs(store.ExportConfig{Target: target, Source: "agents"}, []byte("x"), "csv"); err == nil {
			t.Errorf("target %q accepted", target)
		}
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("a file was written outside the export directory")
	}
	// A symlink inside the directory cannot lead out of it.
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := deliverFileAs(store.ExportConfig{Target: "link/x.csv", Source: "agents"}, []byte("x"), "csv"); err == nil {
		t.Error("a write through a symlink out of the export directory was accepted")
	}
	for _, target := range []string{"reports/", "fixed.csv", filepath.Join(dir, "abs") + "/", dir} {
		if err := deliverFileAs(store.ExportConfig{Target: target, Source: "agents"}, []byte("x"), "csv"); err != nil {
			t.Errorf("target %q refused: %v", target, err)
		}
	}
}
