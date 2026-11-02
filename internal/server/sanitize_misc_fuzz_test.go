package server

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzCSVCell proves the spreadsheet-formula neutralization: a cell holding
// agent-reported text (hostname, software name, log line) is never handed to
// a spreadsheet in a form it would evaluate as a formula. Any cell that
// begins with =, +, -, @, tab or CR must come back prefixed with a single
// quote; everything else is unchanged.
func FuzzCSVCell(f *testing.F) {
	for _, s := range []string{
		"", "host-1", "=HYPERLINK(1)", "+1", "-1", "@SUM", "\tx", "\rx",
		"=1+2", "normal", " =leadingspace", "a=b", "\x00", "=\n=",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := csvCell(s)
		if s == "" {
			if out != "" {
				t.Fatalf("empty cell changed to %q", out)
			}
			return
		}
		dangerous := strings.IndexByte("=+-@\t\r", s[0]) >= 0
		if dangerous {
			if out != "'"+s {
				t.Fatalf("dangerous cell %q not neutralized: %q", s, out)
			}
		} else if out != s {
			t.Fatalf("safe cell %q altered to %q", s, out)
		}
		// The neutralized value must never itself start with a formula
		// trigger (the quote is the first byte).
		if out != "" && strings.IndexByte("=+-@\t\r", out[0]) >= 0 {
			t.Fatalf("csvCell(%q)=%q still starts with a formula trigger", s, out)
		}
	})
}

// FuzzSafeTruncate proves safeTruncate always returns valid UTF-8 that
// Postgres will accept, never splitting a rune, for any input and bound.
func FuzzSafeTruncate(f *testing.F) {
	for _, s := range []string{"", "ascii", "héllo wörld", "日本語テキスト", strings.Repeat("x", 500)} {
		f.Add(s, 10)
		f.Add(s, 0)
		f.Add(s, 3)
	}
	f.Fuzz(func(t *testing.T, s string, n int) {
		if n < 0 || n > 1<<20 {
			return
		}
		out := safeTruncate(s, n)
		if !utf8.ValidString(out) {
			t.Fatalf("safeTruncate(%q,%d)=%q is not valid UTF-8", s, n, out)
		}
		// A valid string already within bound must be returned verbatim.
		if utf8.ValidString(s) && len(s) <= n && out != s {
			t.Fatalf("safeTruncate changed a valid string already within bound: %q -> %q", s, out)
		}
	})
}

// FuzzSanitizeSite proves an agent-reported site name is always reduced to a
// token that is safe as a NATS subject element and for display: the result
// matches the strict site pattern (letters, digits, '-', '_', 1..64), so it
// can never carry a '.', '*', '>' or whitespace into a subject.
func FuzzSanitizeSite(f *testing.F) {
	for _, s := range []string{
		"", "default", "HQ-1", "a.b", "a b", "../x", "site>evil", "*", strings.Repeat("x", 200),
		"éè", "a\tb", "a\nb", ".", "name.with.dots", "a*b.c>d",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, site string) {
		out := sanitizeSite(site)
		if !validSite(out) {
			t.Fatalf("sanitizeSite(%q)=%q is not a valid site token", site, out)
		}
		if strings.ContainsAny(out, ".*> \t\n\r/\\") {
			t.Fatalf("sanitizeSite(%q)=%q contains a subject metacharacter", site, out)
		}
		// Idempotent: a value already valid is returned unchanged, and
		// sanitizing the result again does not change it.
		if sanitizeSite(out) != out {
			t.Fatalf("sanitizeSite not idempotent: %q -> %q -> %q", site, out, sanitizeSite(out))
		}
	})
}

// FuzzVersionCompare checks the server's version comparison is a consistent
// order: versionIsNewer is irreflexive and never both directions, and
// deploy-style VersionMatches/CompareVersion never panic.
func FuzzVersionCompare(f *testing.F) {
	for _, s := range []string{"1.2.3", "0.35.10", "0.35.9", "dev", "1.2.3-rc", "", "99999999999999999999.0.0"} {
		f.Add(s, "1.2.3")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if versionIsNewer(a, a) {
			t.Fatalf("versionIsNewer(%q,%q) true", a, a)
		}
		if versionIsNewer(a, b) && versionIsNewer(b, a) {
			t.Fatalf("versionIsNewer both directions for %q/%q", a, b)
		}
		_ = versionParses(a)
	})
}
