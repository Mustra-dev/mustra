package server

import (
	"io/fs"
	"strings"
	"testing"
)

// Client-side CSV exports carry agent-reported values (hostnames, paths,
// snippets) into a spreadsheet, where a cell starting with = + - @ runs as
// a formula. Every page that builds a CSV blob must quote its cells through
// app.js csvRow/csvCell, which neutralises them the way csvsafe.go does on
// the server.
func TestClientCSVExportsNeutraliseFormulas(t *testing.T) {
	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(app), `if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;`) {
		t.Error("app.js csvCell no longer prefixes formula-leading cells with a quote")
	}
	found := 0
	err = fs.WalkDir(staticFS, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.Contains(path, "/vendor/") {
			return err
		}
		if !strings.HasSuffix(path, ".html") && !strings.HasSuffix(path, ".js") {
			return nil
		}
		b, err := staticFS.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		if !strings.Contains(src, "text/csv") {
			return nil
		}
		found++
		if !strings.Contains(src, "csvRow(") {
			t.Errorf("%s builds a CSV download without csvRow", path)
		}
		if strings.Contains(src, `.replace(/"/g, '""')`) {
			t.Errorf("%s still quotes CSV cells by hand, bypassing formula neutralisation", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Error("no client-side CSV export found; update this test if they moved server-side")
	}
}
