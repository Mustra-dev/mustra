package server

import "testing"

func TestCleanShortcuts(t *testing.T) {
	got := cleanShortcuts(map[string]string{
		"ask": "Ctrl+/", "endpoints": "Ctrl+Shift+E", "dashboards": "Ctrl+/", // taken by ask
		"links": "Alt+.", "bogus": "Ctrl+K",
	})
	if got["ask"] != "Ctrl+/" || got["endpoints"] != "Ctrl+Shift+E" || got["links"] != "Alt+." {
		t.Fatalf("kept the wrong ones: %v", got)
	}
	if _, ok := got["dashboards"]; ok {
		t.Error("a combination already taken was kept")
	}
	if _, ok := got["bogus"]; ok {
		t.Error("an unknown mode was kept")
	}
	for _, bad := range []string{"K", "Shift+K", "Ctrl+", "Ctrl+<script>", "Ctrl+KK", "ctrl+k"} {
		if c := cleanShortcuts(map[string]string{"ask": bad}); c != nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if cleanShortcuts(nil) != nil {
		t.Error("nil should stay nil")
	}
}
