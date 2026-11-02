package server

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The bug this helper exists to end: slicing by byte offset can cut a
// multi-byte character in half, Postgres refuses invalid UTF-8 in a text
// column, every call site only logs the failure, and the row stays open —
// so a finished install renders as running and then stalled.
func TestSafeTruncateNeverProducesInvalidUTF8(t *testing.T) {
	// A 3-byte rune straddling every plausible cut point.
	s := strings.Repeat("€", 400) // 1200 bytes
	for n := 1; n < 1200; n++ {
		got := safeTruncate(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("safeTruncate(…, %d) produced invalid UTF-8 — Postgres would reject this", n)
		}
	}
}

func TestSafeTruncateLeavesShortStringsAlone(t *testing.T) {
	if got := safeTruncate("apt-get install foo", 8000); got != "apt-get install foo" {
		t.Errorf("a short string was altered: %q", got)
	}
	// Exactly at the limit is not over it.
	s := strings.Repeat("a", 100)
	if got := safeTruncate(s, 100); got != s {
		t.Errorf("a string exactly at the cap was truncated")
	}
}

func TestSafeTruncateSaysItTruncated(t *testing.T) {
	got := safeTruncate(strings.Repeat("a", 200), 50)
	if !strings.Contains(got, "truncated") {
		t.Error("a truncated transcript must say so, or it reads as the whole output")
	}
	if len(got) > 50+len("\n… (truncated)") {
		t.Errorf("result is %d bytes, longer than the cap plus its marker", len(got))
	}
}
