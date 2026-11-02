package server

import (
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// The AvailableOSUpdates answer from the MacBook, trimmed.
const availableOSUpdatesPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>AvailableOSUpdates</key><array>
<dict><key>AllowsInstallLater</key><true/><key>HumanReadableName</key><string>macOS Tahoe 26.7.1</string>
<key>IsCritical</key><false/><key>ProductKey</key><string>MSU_UPDATE_25G241_patch_26.7.1_minor</string>
<key>RestartRequired</key><true/><key>Version</key><string>26.7.1</string></dict>
<dict><key>HumanReadableName</key><string>macOS 27.0.1</string><key>IsMajorOSUpdate</key><true/>
<key>ProductKey</key><string>MSU_UPDATE_26A434_patch_27.0.1_major</string><key>Version</key><string>27.0.1</string></dict>
</array>
<key>CommandUUID</key><string>575867F6</string><key>Status</key><string>Acknowledged</string>
</dict></plist>`

func TestAvailableOSUpdatesAndPick(t *testing.T) {
	v, err := parsePlist([]byte(availableOSUpdatesPlist))
	if err != nil {
		t.Fatal(err)
	}
	ups := availableOSUpdates(v.(map[string]any))
	if len(ups) != 2 || ups[0].Major || !ups[1].Major || ups[0].ProductKey != "MSU_UPDATE_25G241_patch_26.7.1_minor" {
		t.Fatalf("got %+v", ups)
	}
	pending := []proto.PatchInfo{
		{Name: "macOS Tahoe 26.7.1", NewVersion: "26.7.1", RestartRequired: true},
		{Name: "macOS 27.0.1", NewVersion: "27.0.1", RestartRequired: true},
	}
	all := func(string) bool { return true }
	if u, ok := pickMacOSUpdate(ups, pending, all, false); !ok || u.Version != "26.7.1" {
		t.Errorf("minor only: %+v %v", u, ok)
	}
	if u, ok := pickMacOSUpdate(ups, pending, all, true); !ok || u.Version != "27.0.1" {
		t.Errorf("major allowed: %+v %v", u, ok)
	}
	if _, ok := pickMacOSUpdate(ups, pending, func(n string) bool { return n == "macOS 27.0.1" }, false); ok {
		t.Error("patch lists allow only the major upgrade, which is off: nothing to install")
	}
	if _, ok := pickMacOSUpdate(ups, pending[1:], all, false); ok {
		t.Error("the agent no longer reports 26.7.1 pending")
	}
	// No inventory yet (just after an agent update): the Mac's list decides.
	if u, ok := pickMacOSUpdate(ups, nil, all, false); !ok || u.Version != "26.7.1" {
		t.Errorf("no inventory: %+v %v", u, ok)
	}
}

func TestErrorChain(t *testing.T) {
	v, _ := parsePlist([]byte(`<plist><dict><key>ErrorChain</key><array><dict><key>LocalizedDescription</key>` +
		`<string>The bootstrap token is not available</string></dict></array></dict></plist>`))
	if got := errorChain(v.(map[string]any)); got != "The bootstrap token is not available" {
		t.Errorf("got %q", got)
	}
}

func TestCommandUUIDAndEscape(t *testing.T) {
	id := commandUUID()
	if len(id) != 36 || id[14] != '4' || strings.ToUpper(id) != id {
		t.Errorf("bad uuid %q", id)
	}
	if xmlEscape("a<b&c") != "a&lt;b&amp;c" {
		t.Error("escape")
	}
	if validateFleetURL("ftp://x") == nil || validateFleetURL("http://10.0.0.36:8412") != nil || validateFleetURL("") != nil {
		t.Error("url validation")
	}
}
