package server

import (
	"reflect"
	"sort"
	"testing"
)

// Every starter check names both NIST catalogues, and no mapping names a
// check that no longer exists.
func TestStarterChecksAreMapped(t *testing.T) {
	ids := map[string]bool{}
	for _, c := range starterLinuxPolicy {
		ids[c.ID] = true
		if len(c.Controls["nist_800_53"]) == 0 || len(c.Controls["nist_800_171"]) == 0 {
			t.Errorf("%s has no NIST mapping: %v", c.ID, c.Controls)
		}
	}
	for id := range starterControls {
		if !ids[id] {
			t.Errorf("starterControls maps %q, which is not a starter check", id)
		}
	}
}

func TestControlFamilyAndOrder(t *testing.T) {
	for _, c := range []struct{ fw, id, fam, name string }{
		{"nist_800_53", "AC-6", "AC", "Access Control"},
		{"nist_800_53", "si-2(2)", "SI", "System and Information Integrity"},
		{"nist_800_171", "3.13.6", "3.13", "System and Communications Protection"},
		{"nist_800_171", "3.1.5", "3.1", "Access Control"},
		{"cmmc", "CM.L2-3.4.7", "CM", "Configuration Management"},
		{"hipaa", "164.308.a.1", "164", ""},
	} {
		fam, name := controlFamily(c.fw, c.id)
		if fam != c.fam || name != c.name {
			t.Errorf("controlFamily(%s, %s) = %q %q, want %q %q", c.fw, c.id, fam, name, c.fam, c.name)
		}
	}
	ids := []string{"AC-11", "AC-2", "AC-6(1)", "AC-6", "3.1.10", "3.1.2", "3.13.1", "3.4.7"}
	sort.Slice(ids, func(i, j int) bool { return controlLess(ids[i], ids[j]) })
	want := []string{"3.1.2", "3.1.10", "3.4.7", "3.13.1", "AC-2", "AC-6", "AC-6(1)", "AC-11"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("order %v, want %v", ids, want)
	}
}
