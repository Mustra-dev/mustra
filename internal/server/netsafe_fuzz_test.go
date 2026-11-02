package server

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzPathWithin proves the containment guard behind every on-disk path
// built from request or agent input: a path it returns is always inside the
// base directory, with no "../" escape, whatever the fuzzed element.
func FuzzPathWithin(f *testing.F) {
	for _, s := range []string{
		"pf-0123", "..", "../etc", "a/b", "a%2Fb", ".", "....//", "a\\b", "", "con",
		"....", "..\x00/", "foo/../..", "a/../../b", strings.Repeat("a", 200),
	} {
		f.Add(s)
	}
	base := "/srv/mustra/packages"
	cleanBase := filepath.Clean(base)
	f.Fuzz(func(t *testing.T, elem string) {
		got, err := pathWithin(base, elem)
		if err != nil {
			return // refused, which is always safe
		}
		// Accepted: the result must be strictly inside the base.
		if got != cleanBase && !strings.HasPrefix(got, cleanBase+string(filepath.Separator)) {
			t.Fatalf("pathWithin(%q) escaped base: %q", elem, got)
		}
		if got == cleanBase {
			t.Fatalf("pathWithin(%q) returned the base itself", elem)
		}
		rel, rerr := filepath.Rel(cleanBase, got)
		if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			t.Fatalf("pathWithin(%q)=%q is not contained (rel=%q)", elem, got, rel)
		}
		// A safe segment also means safePathSegment agreed.
		if !safePathSegment(elem) {
			t.Fatalf("pathWithin accepted %q that safePathSegment rejects", elem)
		}
	})
}

// FuzzBlockedAddr checks the SSRF address screen never misclassifies a
// private/loopback/link-local/CGNAT/metadata address as public. It parses
// fuzzed address text (covering IPv4-mapped IPv6, zone IDs and odd forms)
// and asserts blockedAddr agrees with netip's own category predicates.
func FuzzBlockedAddr(f *testing.F) {
	for _, s := range []string{
		"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:169.254.169.254",
		"100.64.0.1", "192.168.1.1", "8.8.8.8", "::ffff:10.0.0.1", "fe80::1%eth0",
		"fc00::1", "0.0.0.0", "224.0.0.1", "::ffff:8.8.8.8", "2001:4860:4860::8888",
		"64:ff9b::808:808", "198.18.0.1", "192.0.0.1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		blocked := blockedAddr(a)
		u := a.Unmap()
		// Anything netip itself calls non-global-unicast must be blocked:
		// if any of these is true, blockedAddr must say true.
		mustBlock := !u.IsValid() || u.IsLoopback() || u.IsPrivate() || u.IsLinkLocalUnicast() ||
			u.IsLinkLocalMulticast() || u.IsMulticast() || u.IsUnspecified() || u.IsInterfaceLocalMulticast()
		if mustBlock && !blocked {
			t.Fatalf("blockedAddr(%q=%v) returned false for a non-public address", s, u)
		}
		// The IPv4-mapped form must classify like its underlying IPv4: a
		// mapped private address must not sneak through as public.
		if a.Is4In6() {
			if blockedAddr(a) != blockedAddr(u) {
				t.Fatalf("mapped/unmapped disagree for %q: %v vs %v", s, blockedAddr(a), blockedAddr(u))
			}
		}
	})
}
