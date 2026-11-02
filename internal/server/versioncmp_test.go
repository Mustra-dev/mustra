package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestVersionIsNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
		why  string
	}{
		{"0.37.0", "0.36.2", true, "an ordinary release"},
		{"0.36.2", "0.36.2", false, "the same build is not an update"},
		{"0.36.2", "0.37.0", false, "an endpoint ahead of the control plane must not be downgraded"},
		{"0.36.10", "0.36.9", true, "10 is newer than 9, which a string compare gets backwards"},
		{"1.0.0", "0.99.99", true, "major wins"},
		{"dev", "0.36.2", false, "an unstamped build must not make the whole fleet eligible"},
		{"0.36.2", "", false, "an endpoint with no reported version"},
		{"", "", false, "nothing known either way"},
		{"0.36.2-rc1", "0.36.1", true, "a suffix does not stop the numbers being readable"},
	} {
		if got := versionIsNewer(c.a, c.b); got != c.want {
			t.Errorf("versionIsNewer(%q, %q) = %v, want %v — %s", c.a, c.b, got, c.want, c.why)
		}
	}
}

// A pre-release is not the release it precedes. An endpoint left on an rc
// build reported as "already on" the final version stays on the rc forever:
// the update package hides it as current, so nothing offers it the real one.
func TestVersionPreRelease(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
		why  string
	}{
		{"0.41.8", "0.41.8-rc", true, "the release is newer than its own rc"},
		{"0.41.8-rc", "0.41.8", false, "the rc is not newer than the release"},
		{"0.41.8-rc", "0.41.8-rc", false, "the same rc is not newer than itself"},
		{"0.105.1-24-gc9cd30b", "0.105.1-19-g245cdb1", true, "a source build further past the tag is newer"},
		{"0.105.1-19-g245cdb1", "0.105.1-24-gc9cd30b", false, "and an earlier one is not"},
		{"0.105.1-24-gc9cd30b", "0.105.1", true, "a source build after a release is newer than it"},
		{"0.105.1", "0.105.1-24-gc9cd30b", false, "the release is not newer than a build after it"},
		{"0.105.1-24-gc9cd30b-dirty", "0.105.1-19-g245cdb1", true, "a dirty tree still counts its commits"},
		{"0.105.2", "0.105.1-24-gc9cd30b", true, "the next release is newer than any build before it"},
		{"0.105.1-24-gc9cd30b", "0.105.1-rc", false, "against a pre-release of the same version it stays unranked, as pre-releases are"},
		{"0.41.8-rc2", "0.41.8-rc", false, "two pre-releases of one version are not ranked"},
		{"0.41.8-rc", "0.41.8-rc2", false, "and not in the other direction either"},
		{"0.41.9-rc", "0.41.8", true, "a higher number still wins, pre-release or not"},
		{"0.41.8", "0.41.9-rc", false, "and a lower one still loses"},
		{"0.41.8", "0.41.8", false, "equal releases are equal"},
	}
	for _, tc := range cases {
		if got := versionIsNewer(tc.a, tc.b); got != tc.want {
			t.Errorf("versionIsNewer(%q, %q) = %v, want %v -- %s", tc.a, tc.b, got, tc.want, tc.why)
		}
	}
}

// The rc endpoint has to come out of applicability as something to update,
// which is the whole point of the comparison change.
func TestAgentVersionStatePreRelease(t *testing.T) {
	ops := store.SoftwareOps{Update: "install.ps1"}
	state, found, reason := agentVersionState("0.41.8", "0.41.8-rc", ops, "windows")
	if state != stateUpdateEligible {
		t.Fatalf("an endpoint on 0.41.8-rc = %q (%s), want update_eligible", state, reason)
	}
	if found != "0.41.8-rc" {
		t.Errorf("found version = %q, want the rc string unchanged", found)
	}
}
