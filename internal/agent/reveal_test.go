package agent

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/reveal"
)

// A directory with the shapes a scan has to get right: a text file with a
// real card number and a fake one, a binary file with a card number in it,
// a file too large to read, a spreadsheet, an excluded directory, and a
// file with the wrong extension.
func TestRevealScanFindsConfirmedMatchesOnly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("notes.txt", "customer card 4111 1111 1111 1111 paid\nnot a card 4111 1111 1111 1112\nbuild 5500000000000004 done\n")
	write("binary.txt", "prefix\x00\x00 4111 1111 1111 1111")
	write("big.log", strings.Repeat("x", 10000)+" 4111111111111111")
	write("skipme.bin", "4111 1111 1111 1111")
	write("node_modules/secret.txt", "4111 1111 1111 1111")
	write("mail.txt", "reach me at alex@example.com")
	// A spreadsheet: a zip with one XML part.
	xlsx := filepath.Join(dir, "cards.xlsx")
	zf, _ := os.Create(xlsx)
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("xl/worksheets/sheet1.xml")
	w.Write([]byte(`<row><c><v>5500 0000 0000 0004</v></c></row>`))
	zw.Close()
	zf.Close()

	job := proto.RevealJob{ScanID: "s1", RuleID: "r1", Roots: []string{dir}, Patterns: reveal.Builtin(),
		MaxSizeBytes: 4000, Snippets: true}
	patterns, err := reveal.Compile(job.Patterns)
	if err != nil {
		t.Fatal(err)
	}
	var report proto.RevealReport
	scanReveal(context.Background(), job, patterns, &report)

	got := map[string]proto.RevealMatch{}
	for _, m := range report.Matches {
		got[filepath.Base(m.Path)+"|"+m.PatternID] = m
	}
	m, ok := got["notes.txt|credit_card"]
	// Three shapes: a formatted valid card (confirmed), a formatted number
	// that fails Luhn, and a bare valid run with no card word near it.
	if !ok || m.Count != 3 || m.Confirmed != 1 {
		t.Fatalf("notes.txt: want 3 matches, 1 confirmed; got %+v", m)
	}
	if !strings.Contains(m.Snippet, "1111") || strings.Contains(m.Snippet, "4111 1111 1111 1111") {
		t.Errorf("snippet must be masked with the tail kept: %q", m.Snippet)
	}
	if _, ok := got["mail.txt|email"]; !ok {
		t.Error("email not found")
	}
	if _, ok := got["cards.xlsx|credit_card"]; !ok {
		t.Error("the spreadsheet's card number was not found")
	}
	for _, bad := range []string{"binary.txt|credit_card", "big.log|credit_card", "skipme.bin|credit_card", "secret.txt|credit_card"} {
		if _, ok := got[bad]; ok {
			t.Errorf("%s should not have been scanned", bad)
		}
	}
	if report.FilesMatched != 3 || report.Skipped < 2 {
		t.Errorf("files_matched=%d skipped=%d; %+v", report.FilesMatched, report.Skipped, report)
	}
}

func TestRevealScanBudgets(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		os.WriteFile(filepath.Join(dir, "f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".txt"), []byte("4111 1111 1111 1111"), 0o644)
	}
	job := proto.RevealJob{Roots: []string{dir}, Patterns: reveal.Builtin(), MaxFiles: 10}
	patterns, _ := reveal.Compile(job.Patterns)
	var report proto.RevealReport
	scanReveal(context.Background(), job, patterns, &report)
	if !report.Truncated || report.FilesSeen > 10 {
		t.Errorf("file budget not honoured: truncated=%v seen=%d", report.Truncated, report.FilesSeen)
	}
}
