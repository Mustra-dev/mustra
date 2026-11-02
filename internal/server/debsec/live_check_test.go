package debsec

import (
	"context"
	"os"
	"testing"
)

// A live check against Debian's real tracker. Skipped by default — it
// downloads ~70 MB — but it is the only way to know the parser matches
// what Debian actually publishes rather than what the docs describe.
// Run with: MUSTRA_LIVE_DEBSEC=1 go test ./internal/server/debsec/ -run Live -v
func TestLiveTrackerShapes(t *testing.T) {
	if os.Getenv("MUSTRA_LIVE_DEBSEC") == "" {
		t.Skip("set MUSTRA_LIVE_DEBSEC=1 to run the live tracker check")
	}
	ix := NewIndex()
	if err := ix.Refresh(context.Background(), map[string]bool{
		"curl": true, "openssl": true, "glibc": true, "bash": true, "systemd": true,
	}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	t.Logf("indexed %d packages", ix.Len())
	if ix.Len() == 0 {
		t.Fatal("filtered index came back empty — the filter or the parse is wrong")
	}

	for _, tc := range []struct{ pkg, cve, ver string }{
		{"curl", "CVE-2003-1605", "7.88.1-10+deb12u5"},
		{"glibc", "CVE-2023-4911", "2.36-9+deb12u1"},
		{"bash", "CVE-2019-18276", "5.2.15-2+b7"},
	} {
		v := ix.Lookup(tc.pkg, tc.cve, "bookworm", tc.ver)
		t.Logf("%-8s %-16s known=%-5v actionable=%-5v %s",
			tc.pkg, tc.cve, v.Known, v.Actionable(), v.Suppressed())
	}

	// The property that matters: an ancient CVE against a current package
	// must not still read as actionable.
	if v := ix.Lookup("curl", "CVE-2003-1605", "bookworm", "7.88.1-10+deb12u5"); v.Known && v.Actionable() {
		t.Error("a 2003 CVE against current curl should not be actionable on bookworm")
	}
}
