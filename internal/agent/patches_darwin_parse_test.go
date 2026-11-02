package agent

import (
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestParseSoftwareUpdateList(t *testing.T) {
	out := `Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Tahoe 26.7.1-25G241
	Title: macOS Tahoe 26.7.1, Version: 26.7.1, Size: 3912000KiB, Recommended: YES, Action: restart,
* Label: Safari27.0TahoeAuto-27.0
	Title: Safari, Version: 27.0, Size: 120540KiB, Recommended: YES,
* Label: Command Line Tools for Xcode-16.4
	Title: Command Line Tools for Xcode, 16.4, Version: 16.4, Size: 751000KiB, Recommended: YES,
   * Safari13.0.4MojaveAuto-13.0.4
	Safari (13.0.4), 69012K [recommended] [restart]
`
	got := parseSoftwareUpdateList(out)
	want := []struct {
		label, name, version string
		restart              bool
	}{
		{"macOS Tahoe 26.7.1-25G241", "macOS Tahoe 26.7.1", "26.7.1", true},
		{"Safari27.0TahoeAuto-27.0", "Safari", "27.0", false},
		{"Command Line Tools for Xcode-16.4", "Command Line Tools for Xcode, 16.4", "16.4", false},
		{"Safari13.0.4MojaveAuto-13.0.4", "Safari", "13.0.4", true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d updates, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Label != w.label || g.Name != w.name || g.NewVersion != w.version || g.RestartRequired != w.restart {
			t.Errorf("%d: got label=%q name=%q version=%q restart=%v, want %+v", i, g.Label, g.Name, g.NewVersion, g.RestartRequired, w)
		}
	}
	if parseSoftwareUpdateList("No new software available.\n") != nil {
		t.Error("nothing pending should be no updates")
	}
}

func TestParseAptKeptBack(t *testing.T) {
	out := `Calculating upgrade...
The following packages have been kept back:
  linux-base-rpi-2712 linux-base-rpi-v8 linux-headers-rpi-2712
  linux-headers-rpi-v8 linux-image-rpi-2712 linux-image-rpi-v8
0 upgraded, 0 newly installed, 0 to remove and 6 not upgraded.
`
	got := parseAptKeptBack(out)
	if len(got) != 6 || got[0] != "linux-base-rpi-2712" || got[5] != "linux-image-rpi-v8" {
		t.Fatalf("got %v", got)
	}
	if parseAptKeptBack("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n") != nil {
		t.Error("nothing kept back")
	}
}

func TestPatchesStillPending(t *testing.T) {
	after := []proto.PatchInfo{{Name: "pve-firewall"}, {Name: "macOS Tahoe 26.7.1", RestartRequired: true}, {Name: "unrelated"}}
	r, n := patchesStillPending([]string{"pve-firewall", "macOS Tahoe 26.7.1", "jq"}, after)
	if len(r) != 1 || r[0] != "macOS Tahoe 26.7.1" || len(n) != 1 || n[0] != "pve-firewall" {
		t.Fatalf("restart=%v notInstalled=%v", r, n)
	}
}

// Output from an Ubuntu 25.10 machine whose Netdata repository has no
// release for it: the job must carry on with the repositories that answered.
func TestParseAptUpdateErrors(t *testing.T) {
	out := `Hit:1 https://packages.broadcom.com/artifactory/saltproject-deb stable InRelease
Ign:2 http://repository.netdata.cloud/repos/stable/ubuntu questing/ InRelease
Hit:3 http://archive.ubuntu.com/ubuntu questing InRelease
Err:8 http://repository.netdata.cloud/repos/stable/ubuntu questing/ Release
  404  Not Found [IP: 104.20.22.2 80]
Reading package lists...
E: The repository 'http://repository.netdata.cloud/repos/stable/ubuntu questing/ Release' no longer has a Release file.
E: Some index files failed to download. They have been ignored, or old ones used instead.
`
	got := parseAptUpdateErrors(out)
	if len(got) != 1 || !strings.Contains(got[0], "repository.netdata.cloud") {
		t.Fatalf("got %q", got)
	}
	if !aptUpdateReachedAny(out) {
		t.Error("two repositories answered")
	}
	offline := "Err:1 http://deb.debian.org/debian trixie InRelease\n  Temporary failure resolving 'deb.debian.org'\n"
	if aptUpdateReachedAny(offline) {
		t.Error("no repository answered")
	}
}

func TestAptUnmetReason(t *testing.T) {
	out := `The following packages have unmet dependencies:
 intel-opencl-icd : Depends: libstdc++6 (>= 16) but 14.2.0-19 is to be installed
                    Depends: libigc2 (>= 2.40.14) but it is not going to be installed
E: Unable to correct problems, you have held broken packages.
`
	if got := aptUnmetReason(out); got != "Depends: libstdc++6 (>= 16) but 14.2.0-19 is to be installed" {
		t.Errorf("got %q", got)
	}
	if got := aptUnmetReason("E: Unable to locate package nope\n"); got != "Unable to locate package nope" {
		t.Errorf("got %q", got)
	}
}

// The real failure from a MacBook: thousands of progress lines, then the
// reason. The reason must survive.
func TestWithoutProgress(t *testing.T) {
	out := "Password: Software Update Tool\n\nFinding available software\nDownloading macOS Tahoe 26.7.1\n" +
		strings.Repeat("Downloading: 41.00%\n", 3000) + "Downloaded: macOS Tahoe 26.7.1\nFailed to authenticate\n"
	got := withoutProgress(out)
	if strings.Contains(got, "Downloading: 41") || !strings.Contains(got, "Failed to authenticate") || len(got) > 200 {
		t.Fatalf("got %d bytes: %q", len(got), got)
	}
	if l := lastLine(out, nil); l != "Failed to authenticate" {
		t.Errorf("lastLine = %q", l)
	}
}

// Lines from the MacBook's softwareupdated while it prepared macOS 27.0.1.
func TestParseMacUpdateProgress(t *testing.T) {
	out := `2026-10-17 23:05:19.560 Df softwareupdated[714:361b0] [com.apple.SoftwareUpdateMacController:SU] [SUMacControllerProgressManager] Reported progress (inter): phase:DOWNLOADING_UPDATE stalled:NO portionComplete:0.213437 estimatedTimeRemaining:536.006470 task:(null)
2026-10-17 23:05:22.176 Df softwareupdated[714:361b0] [com.apple.SoftwareUpdateMacController:SU] [SUMacControllerProgressManager] Reported progress (inter): phase:PREPARING_UPDATE stalled:NO portionComplete:0.897795 estimatedTimeRemaining:600.000000 task:(null) actionText:(null)
`
	p, ok := parseMacUpdateProgress(out)
	if !ok || p.Phase != "PREPARING_UPDATE" || p.Percent < 89.7 || p.Percent > 89.8 || p.Stalled || p.At != "2026-10-17 23:05:22.176" {
		t.Fatalf("got %+v %v", p, ok)
	}
	if _, ok := parseMacUpdateProgress("Filtering the log data using ...\n"); ok {
		t.Error("no progress line, no progress")
	}
}
