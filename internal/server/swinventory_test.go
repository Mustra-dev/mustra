package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestPresenceRowsMergesDuplicateEntries(t *testing.T) {
	rows := presenceRows([]proto.InstalledApp{
		{Name: "Google Chrome 128.0.6613.120", Version: "128.0.6613.120", Publisher: "Google LLC"},
		{Name: "Google Chrome", Version: "129.0.1", Publisher: "Google LLC", Executable: "chrome", InstallDate: "2026-01-05", LastUsed: "2026-09-10T08:00:00Z"},
		{Name: "", Version: "1"},
		{Name: "7-Zip 23.01 (x64)", Version: "23.01", Publisher: "Igor Pavlov", Executable: `C:\Program Files\7-Zip\7zFM.exe`},
	}, "windows")
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d: %+v", len(rows), rows)
	}
	c := rows[0]
	if c.ProductKey != "google chrome" || c.Version != "129.0.1" || c.Executable != "chrome" || c.InstallDate != "2026-01-05" || c.LastUsedReported.IsZero() || c.Vendor != "Google" {
		t.Fatalf("chrome row: %+v", c)
	}
	if rows[1].ProductKey != "7 zip" || rows[1].Executable != "7zfm" {
		t.Fatalf("7-zip row: %+v", rows[1])
	}
}
