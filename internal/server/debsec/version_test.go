package debsec

import "testing"

// Cases taken from deb-version(7) and from the shapes that actually occur
// in Debian's archive. This function decides whether a vulnerability is
// suppressed as already fixed, so a wrong answer either hides a real
// finding or keeps a fixed one on the list forever.
func TestCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},

		// Numeric runs compare as numbers, not strings: this is the case a
		// naive string compare gets wrong, and it is extremely common.
		{"1.9", "1.10", -1},
		{"1.10", "1.9", 1},
		{"2.4.9", "2.4.10", -1},

		// A tilde sorts before everything, including the empty string, so
		// a release candidate is older than the release.
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~~", "1.0~", -1},

		// Epochs dominate everything after them.
		{"1:1.0", "2.0", 1},
		{"2.0", "1:1.0", -1},
		{"1:1.0", "1:1.0", 0},

		// Debian revisions, including the backport case this whole feature
		// exists for: a security fix bumps the revision, not upstream.
		{"7.88.1-10", "7.88.1-10+deb12u5", -1},
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u8", -1},
		{"7.88.1-10+deb12u8", "7.88.1-10+deb12u8", 0},

		// An upstream version may contain hyphens; only the last one
		// separates the revision.
		{"1.0-beta-1", "1.0-beta-2", -1},

		// Missing revision is older than having one.
		{"1.0", "1.0-1", -1},
	} {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		// Antisymmetry: if a < b then b > a, always.
		if got := Compare(tc.b, tc.a); got != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, got, -tc.want)
		}
	}
}

// OSV prefixes distribution advisories; the tracker does not. Getting this
// wrong makes every lookup miss silently, which is what shipped first and
// showed up as "suppressed_by_debian=0" on a fleet where hundreds of
// findings should have matched.
func TestNormalizeCVE(t *testing.T) {
	for in, want := range map[string]string{
		"DEBIAN-CVE-2026-66486": "CVE-2026-66486",
		"UBUNTU-CVE-2023-4911":  "CVE-2023-4911",
		"CVE-2023-4911":         "CVE-2023-4911",
		// An advisory ID is not a CVE; stripping it would produce nonsense.
		"DSA-5678-1": "DSA-5678-1",
		"DLA-3456-1": "DLA-3456-1",
		"GHSA-abcd":  "GHSA-abcd",
		"":           "",
	} {
		if got := NormalizeCVE(in); got != want {
			t.Errorf("NormalizeCVE(%q) = %q, want %q", in, got, want)
		}
	}
}
