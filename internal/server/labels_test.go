package server

import "testing"

func TestDisplayLabel(t *testing.T) {
	cases := []struct{ column, in, want string }{
		// The one that started this: no other platform carries a vendor
		// prefix, and it was long enough to push the label out of a legend.
		{"platform", "microsoft windows server 2025 standard", "Windows Server 2025 Standard"},
		{"platform", "microsoft windows 11 pro", "Windows 11 Pro"},
		// Mapped names as their own projects write them.
		{"platform", "debian", "Debian"},
		{"platform", "raspbian", "Raspberry Pi OS"},
		{"platform", "opensuse", "openSUSE"},
		{"os", "linux", "Linux"},
		{"os", "darwin", "macOS"},
		{"os", "windows", "Windows"},
		// A name that already carries capitals keeps them.
		{"platform", "Pop!_OS", "Pop!_OS"},
		// Microsoft something that is not Windows keeps its name.
		{"platform", "microsoft defender", "Microsoft Defender"},
		// The console's word for a blank is not a value to tidy.
		{"platform", notSetLabel, notSetLabel},
		{"os", notSetLabel, notSetLabel},
		{"platform", "", ""},
		// A column with no opinion is left exactly alone: inventing a
		// prettier hostname is how a label stops naming its own row.
		{"hostname", "web-01", "web-01"},
		{"site", "main-office", "main-office"},
		{"agent_version", "0.51.0", "0.51.0"},
	}
	for _, c := range cases {
		if got := displayLabel(c.column, c.in); got != c.want {
			t.Errorf("displayLabel(%q, %q) = %q, want %q", c.column, c.in, got, c.want)
		}
	}
}

// A drill-down link is built from the key, so every tidied label has to
// carry the value it was tidied from, and an untouched one must not waste
// a field saying the same thing twice.
func TestSeriesKeyRoundTripsTheRawValue(t *testing.T) {
	tidied := newSeriesPoint("platform", "microsoft windows 11 pro", 3, 50)
	if tidied.Label != "Windows 11 Pro" {
		t.Errorf("label = %q", tidied.Label)
	}
	if seriesKey(tidied) != "microsoft windows 11 pro" {
		t.Errorf("key = %q; a link built from this would match no endpoint", seriesKey(tidied))
	}

	untouched := newSeriesPoint("site", "main-office", 1, 10)
	if untouched.Key != "" {
		t.Errorf("key = %q, want empty when the label already is the value", untouched.Key)
	}
	if seriesKey(untouched) != "main-office" {
		t.Errorf("seriesKey = %q, want the label back", seriesKey(untouched))
	}
}
