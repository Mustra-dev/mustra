package server

import "testing"

// A PTR answer is fully qualified, with the root's trailing dot. The scan
// shows the host's name, and the console pushes to it and records it in
// the deployment history, so the dot is dropped. An answer that is not a
// name (a router's MAC in hex) is passed over, as network discovery does.
func TestScanHostnameDropsThePTRTrailingDot(t *testing.T) {
	for _, tc := range []struct {
		names []string
		want  string
	}{
		{[]string{"web-03.corp.example.com."}, "web-03.corp.example.com"},
		{[]string{"web-03.corp.example.com"}, "web-03.corp.example.com"},
		{[]string{"first.example.", "second.example."}, "first.example"},
		{[]string{"a1b2c3d4e5f6.lan.", "printer-2.lan."}, "printer-2.lan"},
		{[]string{"a1b2c3d4e5f6.lan."}, ""},
		{nil, ""},
	} {
		if got := scanHostname(tc.names); got != tc.want {
			t.Errorf("scanHostname(%q) = %q, want %q", tc.names, got, tc.want)
		}
	}
}
