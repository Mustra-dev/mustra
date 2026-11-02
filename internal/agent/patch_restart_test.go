package agent

import (
	"context"
	"strings"
	"testing"
)

// The decision, without touching the machine: only paths that do not
// schedule a restart are exercised here.
func TestPatchRestartNote(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		mode         string
		required, ok bool
		want         string
	}{
		{"", true, true, ""},
		{"always", true, false, "did not finish cleanly"},
		{"if_required", true, false, "did not finish cleanly"},
		{"if_required", false, true, "No restart needed"},
	} {
		if got := patchRestartNote(ctx, c.mode, 5, c.required, c.ok); !strings.Contains(got, c.want) || (c.want == "" && got != "") {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

func TestParsePatchStep(t *testing.T) {
	stage, detail, ok := parsePatchStep("STEP installing 3 7 2026-10 Cumulative Update for Windows 11 (KB5050001)")
	if !ok || stage != "installing" || detail != "3 of 7: 2026-10 Cumulative Update for Windows 11 (KB5050001)" {
		t.Errorf("got %q %q %v", stage, detail, ok)
	}
	if _, _, ok := parsePatchStep("STEP installing 9 7 x"); ok {
		t.Error("9 of 7 accepted")
	}
}

func TestParseWindowsInstalled(t *testing.T) {
	for _, c := range []struct {
		line, title string
		ok          bool
	}{
		{"installed 2026-10 .NET Framework Security Update (KB5127694): result code 2, reboot required: True", "2026-10 .NET Framework Security Update (KB5127694)", true},
		{"installed Update: Windows Security platform - KB5007651 (Version 10.0.29628.1000): result code 3, reboot required: False", "Update: Windows Security platform - KB5007651 (Version 10.0.29628.1000)", true},
		{"installed Intel Corporation - HDC - 16.8.4.1011: result code 4, reboot required: False", "", false},
		{"STEP installing 1 6 KB5007651", "", false},
		{"not downloaded: KB5007651", "", false},
	} {
		title, ok := parseWindowsInstalled(c.line)
		if ok != c.ok || title != c.title {
			t.Errorf("%q: got (%q, %v), want (%q, %v)", c.line, title, ok, c.title, c.ok)
		}
	}
}
