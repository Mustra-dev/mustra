//go:build linux

package agent

import (
	"reflect"
	"testing"
)

func TestParseDpkgBroken(t *testing.T) {
	out := "grafana\tinstall\thalf-configured\tok\n" +
		"libc6:amd64\tinstall\tinstalled\tok\n" +
		"ifupdown\tdeinstall\tconfig-files\tok\n" +
		"netdata\tinstall\tinstalled\treinstreq\n" +
		"broken line\n"
	want := [][2]string{{"grafana", "half-configured"}, {"netdata", "installed"}}
	if got := parseDpkgBroken(out); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCountAptUpgrades(t *testing.T) {
	origins := map[string]aptOrigin{}
	for _, r := range []string{
		"Origin: Debian\nLabel: Debian\nSuite: stable\nCodename: trixie\n",
		"Origin: Debian\nLabel: Debian-Security\nSuite: stable-security\nCodename: trixie-security\n",
		"Origin: Grafana\nSuite: stable\nCodename: stable\n",
	} {
		o := parseReleaseFile([]byte(r))
		if o.suite == "stable" && o.origin == "Grafana" {
			continue // a second "stable" would replace Debian's; apt list cannot tell them apart either
		}
		origins[o.suite], origins[o.codename] = o, o
	}
	listing := "Listing... Done\n" +
		"libssl3t64/stable-security 3.5.4-1~deb13u1 amd64 [upgradable from: 3.5.1-1]\n" +
		"openssl/stable-security,stable 3.5.4-1~deb13u1 amd64 [upgradable from: 3.5.1-1]\n" +
		"tzdata/stable 2025b-4+deb13u1 all [upgradable from: 2025b-4]\n" +
		"mystery/unknown-suite 1.0 amd64 [upgradable from: 0.9]\n"
	pending, held := countAptUpgrades(listing, origins, map[string]bool{"tzdata": true})
	wantPending := map[[2]string]int{
		{"Debian:trixie-security/stable-security", "amd64"}:                      1,
		{"Debian:trixie-security/stable-security,Debian:trixie/stable", "amd64"}: 1,
		{"Debian:trixie/stable", "all"}:                                          1,
		{":/unknown-suite", "amd64"}:                                             1,
	}
	if !reflect.DeepEqual(pending, wantPending) {
		t.Errorf("pending %v, want %v", pending, wantPending)
	}
	if want := (map[[2]string]int{{"Debian:trixie/stable", "all"}: 1}); !reflect.DeepEqual(held, want) {
		t.Errorf("held %v, want %v", held, want)
	}
}

func TestParseReleaseFileStopsAtSignature(t *testing.T) {
	b := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\nSuite: testing\nCodename: forky\n" +
		"-----BEGIN PGP SIGNATURE-----\n\nSuite: bogus\n"
	if got, want := parseReleaseFile([]byte(b)), (aptOrigin{"Debian", "forky", "testing"}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
