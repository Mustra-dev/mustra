package server

import (
	"slices"
	"testing"
)

// A briefing names the package the scan read from dpkg or rpm; the pending
// update is named by apt or dnf. The same package must match across the
// architecture qualifiers each adds, and nothing else may.
func TestOnlyPatchesMatchesThePackageNotItsNeighbours(t *testing.T) {
	for name, want := range map[string]string{
		"openssl-libs.x86_64": "openssl-libs",
		"libssl3t64:amd64":    "libssl3t64",
		"OpenSSL":             "openssl",
		"python3.12":          "python3.12", // a version, not an architecture
		"kernel.noarch":       "kernel",
	} {
		if got := basePackageName(name); got != want {
			t.Errorf("basePackageName(%q) = %q, want %q", name, got, want)
		}
	}
	allowed := []string{"libssl3t64", "openssl", "openssl-provider-legacy", "curl", "openssl-libs.x86_64"}
	got := onlyPatches(allowed, []string{"openssl", "openssl-libs"})
	if !slices.Equal(got, []string{"openssl", "openssl-libs.x86_64"}) {
		t.Fatalf("onlyPatches = %v", got)
	}
	if got := onlyPatches(allowed, []string{"zlib1g"}); len(got) != 0 {
		t.Fatalf("a package with no pending update matched %v", got)
	}
	if got := onlyPatches(allowed, nil); len(got) != 0 {
		t.Fatalf("no packages named must select nothing, got %v", got)
	}
}
