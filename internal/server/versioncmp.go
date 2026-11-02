package server

import (
	"regexp"
	"strconv"

	"github.com/mustra-dev/mustra/internal/updatesig"
)

// Comparing agent versions.
//
// The Self Service window learned this the hard way: it decided "behind" by
// testing two version strings for inequality, which offered an endpoint
// ahead of the control plane an update that would move it backwards, read
// 0.35.10 as older than 0.35.9, and prompted the whole fleet whenever the
// control plane reported an unstamped "dev". The same comparison is needed
// server-side to decide applicability, so it is written once here with the
// same rule: answer no whenever it cannot tell.

var versionRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(.*)$`)

func parseVersion(v string) ([3]int, bool) {
	out, _, ok := parseVersionParts(v)
	return out, ok
}

// parseVersionParts also returns whatever follows the numeric triple, which
// is what separates a pre-release from the release it precedes: 0.41.8-rc is
// not 0.41.8, and reporting an endpoint running one as "already on" the other
// leaves it stuck on a build nobody meant to keep.
func parseVersionParts(v string) (nums [3]int, pre string, ok bool) {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, "", false
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, "", false
		}
		nums[i] = n
	}
	return nums, m[4], true
}

// versionParses reports whether a version string can be compared at all.
func versionParses(v string) bool {
	_, ok := parseVersion(v)
	return ok
}

// versionIsNewer reports whether a is strictly newer than b, and false
// whenever either side cannot be parsed.
//
// The asymmetry is deliberate and matches the console: an unknown version
// producing no offer costs somebody a click, while an unknown version
// producing an offer costs an endpoint a downgrade.
func versionIsNewer(a, b string) bool {
	// The agent decides the same thing before it accepts an update, so
	// both ask the one function: if they disagreed, the console would
	// offer updates that every endpoint then refuses.
	return updatesig.Newer(a, b)
}
