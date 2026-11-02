package server

import (
	"testing"
	"time"
)

const ubuntuCyclesFixture = `[
 {"cycle":"26.04","codename":"Resolute Raccoon","eol":"2031-05-29","lts":true},
 {"cycle":"25.10","codename":"Questing Quokka","eol":"2026-07-01","lts":false},
 {"cycle":"27.04","codename":"Next","eol":false},
 {"cycle":"14.10","eol":true}
]`

func TestParseOSCycles(t *testing.T) {
	cycles, err := parseOSCycles([]byte(ubuntuCyclesFixture))
	if err != nil || len(cycles) != 4 {
		t.Fatalf("parse: %v %+v", err, cycles)
	}
	if c := cycles[1]; c.Cycle != "25.10" || c.Codename != "Questing Quokka" || !c.EOL.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) || c.Ended {
		t.Errorf("25.10: %+v", c)
	}
	if c := cycles[2]; !c.EOL.IsZero() || c.Ended {
		t.Errorf("no end announced: %+v", c)
	}
	if c := cycles[3]; !c.Ended {
		t.Errorf("ended without a date: %+v", c)
	}
	// A product listing its cycle as a number.
	if c, err := parseOSCycles([]byte(`[{"cycle":13,"eol":"2030-06-30"}]`)); err != nil || c[0].Cycle != "13" {
		t.Errorf("numeric cycle: %+v %v", c, err)
	}
}

func TestOSCycleFor(t *testing.T) {
	for _, c := range []struct{ platform, version, want string }{
		{"ubuntu", "25.10", "25.10"}, {"ubuntu", "24.04", "24.04"},
		{"debian", "13.1", "13"}, {"debian", "12", "12"}, {"raspbian", "12.5", "12"},
		{"alpine", "3.22.0", "3.22"}, {"darwin", "27.0.1", "27"}, {"darwin", "10.15.7", "10.15"},
		{"ubuntu", "", ""}, {"alpine", "3", ""},
	} {
		if got := osCycleFor(c.platform, c.version); got != c.want {
			t.Errorf("osCycleFor(%s, %s) = %q, want %q", c.platform, c.version, got, c.want)
		}
	}
}

func TestOSSupportFor(t *testing.T) {
	cycles, _ := parseOSCycles([]byte(ubuntuCyclesFixture))
	s := &Server{osLifecycle: newOSLifecycleCache()}
	s.osLifecycle.products["ubuntu"] = cycles
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	sup, ok := s.osSupportFor("Ubuntu", "25.10", now)
	if !ok || !sup.Ended || sup.Release != "Ubuntu 25.10" {
		t.Fatalf("25.10: %+v %v", sup, ok)
	}
	if want := "Ubuntu 25.10 reached end of life on 2026-07-01: its vulnerabilities will not be fixed for this release. Upgrade the OS release."; sup.eolReason() != want {
		t.Errorf("reason %q", sup.eolReason())
	}
	if sup, ok := s.osSupportFor("ubuntu", "26.04", now); !ok || sup.Ended || sup.daysLeft(now) < 1000 {
		t.Errorf("26.04: %+v", sup)
	}
	if _, ok := s.osSupportFor("ubuntu", "18.04", now); ok {
		t.Error("a release missing from the list is not known")
	}
	if _, ok := s.osSupportFor("windows", "10.0.26100", now); ok {
		t.Error("windows is not tracked")
	}
	// Exactly on the end date it has ended.
	if sup, _ := s.osSupportFor("ubuntu", "25.10", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)); !sup.Ended {
		t.Error("on the end date it has ended")
	}
}
