package server

import (
	"strings"
	"testing"
)

func TestNormalizeVersionTag(t *testing.T) {
	cases := []struct{ in, want string }{
		{"v0.71.2", "0.71.2"},
		{"0.71.2", "0.71.2"},
		{" v1.0.0 ", "1.0.0"},
		{"v2.3.4-rc1", "2.3.4-rc1"},
		// Not a version this can rank, so it must say so rather than
		// guessing: a wrong answer here tells somebody to upgrade to
		// something that is not newer, or that they are current when they
		// are not.
		{"nightly", ""},
		{"release-2026-09", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeVersionTag(c.in); got != c.want {
			t.Errorf("normalizeVersionTag(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The three verdicts the About page renders, pinned against the comparison
// it actually uses. Being ahead of the newest release is normal for a build
// from source and must not read as "out of date".
func TestUpdateVerdicts(t *testing.T) {
	cases := []struct {
		running, latest string
		wantNewer       bool
		note            string
	}{
		{"0.71.2", "0.72.0", true, "a newer release is available"},
		{"0.71.2", "0.71.2", false, "exactly current"},
		{"0.72.0", "0.71.2", false, "built from source, ahead of the release"},
		{"0.71.2", "1.0.0", true, "a major bump is still just newer"},
		{"0.71.2", "0.71.10", true, "0.71.10 is after 0.71.2, not before it"},
	}
	for _, c := range cases {
		if got := versionIsNewer(c.latest, c.running); got != c.wantNewer {
			t.Errorf("%s: running %s, latest %s -> newer=%v, want %v",
				c.note, c.running, c.latest, got, c.wantNewer)
		}
	}
}

func TestTruncateNotesKeepsItShort(t *testing.T) {
	if got := truncateNotes("  short body  "); got != "short body" {
		t.Errorf("a short body should come back trimmed and whole, got %q", got)
	}

	long := ""
	for i := 0; i < 400; i++ {
		long += "a line of release notes\n"
	}
	got := truncateNotes(long)
	if len(got) > releaseNotesLimit+8 {
		t.Errorf("truncated notes are %d bytes, want <= %d", len(got), releaseNotesLimit+8)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a truncated body should say it was cut; got tail %q", got[max(0, len(got)-12):])
	}
}
