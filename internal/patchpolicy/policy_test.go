package patchpolicy

import (
	"testing"
	"time"
)

func TestEvaluateNoListsIsUnrestricted(t *testing.T) {
	pending := []Patch{{Name: "openssl"}, {Name: "curl"}}
	d := Evaluate(pending, nil, time.Now())
	if len(d.Allowed) != 2 || d.Restricted || len(d.Blocked) != 0 {
		t.Fatalf("no lists should allow everything: %+v", d)
	}
}

func TestEvaluateAllowAndBlock(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	old := now.Add(-10 * 24 * time.Hour)
	pending := []Patch{
		{Name: "openssl", Severity: "security", OS: "linux", FirstSeen: old},
		{Name: "linux-image-6.1.0-30-amd64", Severity: "security", OS: "linux", FirstSeen: old},
		{Name: "curl", Severity: "", OS: "linux", FirstSeen: old},
		{Name: "libfoo", Severity: "security", OS: "linux", FirstSeen: now.Add(-time.Hour)},
	}
	lists := []List{
		{ID: "a", Name: "Security only, a week old", Kind: "allow", Enabled: true, Rules: Rules{Severities: []string{"security"}, MinAgeDays: 7}},
		{ID: "b", Name: "No kernels", Kind: "block", Enabled: true, Rules: Rules{NamePatterns: []string{"linux-image-*"}}},
		{ID: "c", Name: "disabled block", Kind: "block", Enabled: false, Rules: Rules{NamePatterns: []string{"openssl"}}},
	}
	d := Evaluate(pending, lists, now)
	if len(d.Allowed) != 1 || d.Allowed[0].Name != "openssl" {
		t.Fatalf("allowed = %+v", d.Allowed)
	}
	if d.Blocked["linux-image-6.1.0-30-amd64"] != "blocked by No kernels" {
		t.Errorf("kernel block reason = %q", d.Blocked["linux-image-6.1.0-30-amd64"])
	}
	if d.Blocked["curl"] != "not in any patch list" {
		t.Errorf("curl reason = %q", d.Blocked["curl"])
	}
	if d.Blocked["libfoo"] != "not in any patch list" {
		t.Errorf("a patch younger than the age rule must not be admitted: %q", d.Blocked["libfoo"])
	}
	if !d.Restricted {
		t.Error("lists changed the outcome, so the decision is restricted")
	}
}

func TestPatternsAreCaseInsensitiveAndSubstringWithoutWildcards(t *testing.T) {
	r := Rules{NamePatterns: []string{"cumulative", "KB50*"}}
	now := time.Now()
	for name, want := range map[string]bool{
		"2026-09 Cumulative Update for Windows 11 (KB5060001)": true,
		"KB5012345 Security Update":                            true,
		"kb4999999 old":                                        false,
		"Microsoft Defender definitions":                       false,
	} {
		if got := r.Match(Patch{Name: name}, now); got != want {
			t.Errorf("%q matched=%v, want %v", name, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.10", -1},
		{"1:2.0", "1.9", 1},
		{"3.0.15-1~deb12u1", "3.0.14-1~deb12u2", 1},
		{"2.0~rc1", "2.0", -1},
		{"6.1.0-30", "6.1.0-9", 1},
		{"1.0", "1.0", 0},
		{"1.0a", "1.0", 1},
		{"0.42.0", "0.42.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestMarkSuperseded(t *testing.T) {
	ps := []Patch{
		{OS: "linux", Name: "openssl", NewVersion: "3.0.14-1~deb12u2"},
		{OS: "linux", Name: "openssl", NewVersion: "3.0.15-1~deb12u1"},
		{OS: "linux", Name: "openssl", NewVersion: "3.0.15-1~deb12u1"},
		{OS: "windows", Name: "openssl", NewVersion: ""},
		{OS: "linux", Name: "curl", NewVersion: "8.0"},
	}
	MarkSuperseded(ps)
	if !ps[0].Superseded || ps[1].Superseded || ps[2].Superseded || ps[3].Superseded || ps[4].Superseded {
		t.Errorf("superseded flags: %v %v %v %v %v", ps[0].Superseded, ps[1].Superseded, ps[2].Superseded, ps[3].Superseded, ps[4].Superseded)
	}
}
