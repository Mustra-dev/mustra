package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestScanSource(t *testing.T) {
	for _, c := range []struct {
		app           proto.InstalledApp
		name, version string
	}{
		{proto.InstalledApp{Name: "libssl3t64", Version: "3.5.7-1~deb13u3", Source: "openssl", SourceVersion: "3.5.7-1~deb13u3"}, "openssl", "3.5.7-1~deb13u3"},
		// A binNMU: the binary's version is not the source's.
		{proto.InstalledApp{Name: "libfoo1", Version: "1.2-3+b1", Source: "foo", SourceVersion: "1.2-3"}, "foo", "1.2-3"},
		// An older agent reports no source.
		{proto.InstalledApp{Name: "openssl", Version: "3.0.11-1~deb12u2"}, "openssl", "3.0.11-1~deb12u2"},
	} {
		if n, v := scanSource(c.app); n != c.name || v != c.version {
			t.Errorf("scanSource(%+v) = %s %s, want %s %s", c.app, n, v, c.name, c.version)
		}
	}
}

func TestOSVEcosystem(t *testing.T) {
	for _, c := range []struct{ eco, ver, want string }{
		{"Alpine", "3.22.0", "Alpine:v3.22"},
		{"Alpine", "3.20", "Alpine:v3.20"},
		{"Alpine", "", "Alpine"},
		{"Debian", "13.1", "Debian"},
		{"Ubuntu", "24.04", "Ubuntu:24.04"},
		{"Ubuntu", "25.10", "Ubuntu:25.10"},
		{"Ubuntu", "", "Ubuntu"},
	} {
		if got := osvEcosystem(c.eco, c.ver); got != c.want {
			t.Errorf("osvEcosystem(%s, %s) = %s, want %s", c.eco, c.ver, got, c.want)
		}
	}
}

func TestKernelBuildOnly(t *testing.T) {
	for _, c := range []struct {
		name, source string
		skip         bool
	}{
		{"linux-libc-dev", "linux", true},
		{"bpftool", "linux", true},
		{"linux-headers-6.17.0-41-generic", "linux", true},
		{"linux-image-6.12.48+deb13-amd64", "linux-signed-amd64", false},
		{"linux-image-6.17.0-41-generic", "linux", false},
		{"linux-lts", "linux-lts", false},
		{"linux-lts-dev", "linux-lts", true},
		{"openssl", "openssl", false},
		{"linux-libc-dev", "", false}, // an older agent sends no source
	} {
		if got := kernelBuildOnly(proto.InstalledApp{Name: c.name, Source: c.source}); got != c.skip {
			t.Errorf("%s from %q: skip=%v, want %v", c.name, c.source, got, c.skip)
		}
	}
}

func TestUbuntuSeverity(t *testing.T) {
	p := func(s string) *string { return &s }
	for _, c := range []struct {
		priority *string
		want     string
		ok       bool
	}{
		{p("high"), "high", true},
		{p("medium"), "medium", true},
		{p("negligible"), "low", true},
		{p(""), "", false},          // no priority published: CVSS stands
		{p("untriaged"), "", false}, // not a grade
		{nil, "", false},            // not recorded
	} {
		if got, ok := ubuntuSeverity(c.priority); got != c.want || ok != c.ok {
			t.Errorf("ubuntuSeverity(%v) = %q, %v; want %q, %v", c.priority, got, ok, c.want, c.ok)
		}
	}
}
