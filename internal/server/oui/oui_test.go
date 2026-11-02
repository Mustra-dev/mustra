package oui

import "testing"

func TestLookup(t *testing.T) {
	if Size() < 30000 {
		t.Fatalf("registry has %d prefixes; the embedded file is missing or truncated", Size())
	}
	for mac, want := range map[string]string{
		"28:70:4E:c5:b9:a5": "Ubiquiti", "50-de-06-60-5d-c9": "Apple", "00:17:88:6c:54:c1": "Philips Lighting",
	} {
		if got := Lookup(mac); got != want {
			t.Errorf("%s: got %q want %q", mac, got, want)
		}
	}
	if Lookup("2a:70:4e:85:41:62") != "" || Lookup("x") != "" {
		t.Error("unregistered or short MACs must return empty")
	}
}
