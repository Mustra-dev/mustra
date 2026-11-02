package debsec

import "strings"

// Debian version comparison, per deb-version(7).
//
// This decides whether a vulnerability is suppressed as already-fixed, so
// getting it wrong either hides a real finding or keeps a fixed one
// forever. It is implemented rather than shelled out to
// `dpkg --compare-versions` because the server has no dpkg — it runs in an
// Alpine container — and because a subprocess per comparison across
// thousands of findings would be absurd.
//
// Format: [epoch:]upstream_version[-debian_revision]
//
// The subtle part is the string ordering: comparison alternates between
// non-digit and digit runs; digit runs compare numerically (so 10 > 9),
// and non-digit runs compare with a modified ASCII in which '~' sorts
// before everything including the empty string. That '~' rule is what
// makes 1.0~rc1 correctly older than 1.0.

// Compare returns -1, 0 or 1 as a is older, equal or newer than b.
func Compare(a, b string) int {
	ae, au, ar := split(a)
	be, bu, br := split(b)

	if c := compareInt(ae, be); c != 0 {
		return c
	}
	if c := compareFragment(au, bu); c != 0 {
		return c
	}
	return compareFragment(ar, br)
}

// split breaks a version into epoch, upstream and revision.
func split(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, ":"); i >= 0 {
		epoch = atoiSafe(v[:i])
		v = v[i+1:]
	}
	// The revision is after the *last* hyphen: an upstream version may
	// legitimately contain hyphens, the revision may not.
	if i := strings.LastIndex(v, "-"); i >= 0 {
		revision = v[i+1:]
		v = v[:i]
	}
	return epoch, v, revision
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareFragment compares one version fragment (upstream or revision).
func compareFragment(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		// Non-digit run.
		ai, bi := 0, 0
		for ai < len(a) && !isDigit(a[ai]) {
			ai++
		}
		for bi < len(b) && !isDigit(b[bi]) {
			bi++
		}
		if c := compareAlpha(a[:ai], b[:bi]); c != 0 {
			return c
		}
		a, b = a[ai:], b[bi:]

		// Digit run, compared as a number so 10 sorts after 9.
		ai, bi = 0, 0
		for ai < len(a) && isDigit(a[ai]) {
			ai++
		}
		for bi < len(b) && isDigit(b[bi]) {
			bi++
		}
		if c := compareNumeric(a[:ai], b[:bi]); c != 0 {
			return c
		}
		a, b = a[ai:], b[bi:]
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// order gives each byte its Debian sort weight. '~' sorts before the end
// of string, letters before non-letters, which is what makes a tilde
// version a pre-release of the version it precedes.
func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func compareAlpha(a, b string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		ac, bc := 0, 0
		if i < len(a) {
			ac = order(a[i])
		}
		if i < len(b) {
			bc = order(b[i])
		}
		if ac != bc {
			return compareInt(ac, bc)
		}
	}
	return 0
}

func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return compareInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}
