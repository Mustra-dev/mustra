package osv

import (
	"strings"
	"testing"
)

func TestSummaryOfFallsBackToDetails(t *testing.T) {
	for _, c := range []struct{ summary, details, want string }{
		{"glibc - security update", "", "glibc - security update"},
		{"", "A buffer overflow was discovered in ld.so.\nIt could allow a local attacker to gain root.", "A buffer overflow was discovered in ld.so."},
		{"", "  One   line\nwithout a full stop", "One line without a full stop"},
		{"", "", ""},
	} {
		if got := summaryOf(c.summary, c.details); got != c.want {
			t.Errorf("summaryOf(%q, %q) = %q, want %q", c.summary, c.details, got, c.want)
		}
	}
	long := summaryOf("", strings.Repeat("word ", 100))
	if r := []rune(long); len(r) != 200 || !strings.HasSuffix(long, "…") {
		t.Errorf("long details: %d runes, %q", len(r), long)
	}
}
