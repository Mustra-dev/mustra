package swinventory

import (
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	cases := []struct{ in, pub, os, name, vendor string }{
		{"Google Chrome", "Google LLC", "windows", "Google Chrome", "Google"},
		{"Python 3.12.1 (64-bit)", "Python Software Foundation", "windows", "Python", "Python Software Foundation"},
		{"7-Zip 23.01 (x64)", "Igor Pavlov", "windows", "7-Zip", "Igor Pavlov"},
		{"Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130", "Microsoft Corporation", "windows", "Microsoft Visual C++ 2015-2022 Redistributable", "Microsoft"},
		{"Mozilla Firefox (x64 en-US)", "Mozilla", "windows", "Mozilla Firefox", "Mozilla"},
		{"Notepad++ (64-bit x64)", "Notepad++ Team", "windows", "Notepad++", "Notepad++ Team"},
		{"Microsoft Edge", "", "windows", "Microsoft Edge", "Microsoft"},
		{"libc6:amd64", "", "linux", "libc6", ""},
		{"curl", "", "linux", "curl", "curl project"},
		{"Visual Studio Code", "", "darwin", "Visual Studio Code", "Microsoft"},
		{"zoom.us", "", "darwin", "zoom.us", "Zoom"},
		{"Slack", "Slack Technologies, Inc.", "darwin", "Slack", "Slack Technologies"},
		{"Windows 10 Update Assistant v1.4", "", "windows", "Windows 10 Update Assistant", ""},
	}
	for _, c := range cases {
		p := Normalize(c.in, c.pub, c.os)
		if p.Name != c.name || p.Vendor != c.vendor {
			t.Errorf("Normalize(%q,%q,%s) = %q/%q, want %q/%q", c.in, c.pub, c.os, p.Name, p.Vendor, c.name, c.vendor)
		}
	}
	if Normalize("Google Chrome 128.0.6613.120", "", "windows").Key != Normalize("Google Chrome", "", "darwin").Key {
		t.Fatal("same product on two platforms should share a key")
	}
	if Key("Notepad++") != "notepad" || Key("  7-Zip ") != "7 zip" {
		t.Fatalf("keys: %q %q", Key("Notepad++"), Key("7-Zip"))
	}
}

func TestExecutables(t *testing.T) {
	got := Executables(Normalize("Google Chrome", "", "windows"), `C:\Program Files\Google\Chrome\Application\chrome.exe`, []string{"CHROME.EXE", "chrome_proxy"})
	want := map[string]bool{"chrome": true, "chrome_proxy": true, "google chrome": true, "googlechrome": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, e := range got {
		if !want[e] {
			t.Fatalf("unexpected %q in %v", e, got)
		}
	}
	if ExeKey(`/usr/bin/Firefox.EXE`) != "firefox" {
		t.Fatal(ExeKey(`/usr/bin/Firefox.EXE`))
	}
}

func TestIsComponent(t *testing.T) {
	for _, n := range []string{"libc6", "python3-requests", "linux-image-6.8.0-45-generic", "fonts-dejavu-core", "Microsoft Visual C++ 2015-2022 Redistributable", "Microsoft Edge WebView2 Runtime", "vim-common", "bash-doc"} {
		if !IsComponent(n, "linux") && !IsComponent(n, "windows") {
			t.Errorf("%q should be a component", n)
		}
	}
	for _, n := range []string{"curl", "Google Chrome", "vim", "Docker Desktop", "7-Zip", "Slack"} {
		if IsComponent(n, "windows") || IsComponent(n, "linux") {
			t.Errorf("%q should not be a component", n)
		}
	}
}

func TestUsageLevel(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	if l := UsageLevel(20, 30, now, now, true); l != UsageHeavy {
		t.Fatal(l)
	}
	if l := UsageLevel(6, 30, now, now, true); l != UsageModerate {
		t.Fatal(l)
	}
	if l := UsageLevel(2, 30, now, now, true); l != UsageLight {
		t.Fatal(l)
	}
	if l := UsageLevel(0, 30, now.Add(-10*24*time.Hour), now, true); l != UsageLight {
		t.Fatal("a last-used inside the window counts as light use: " + l)
	}
	if l := UsageLevel(0, 30, now.Add(-40*24*time.Hour), now, true); l != UsageUnused {
		t.Fatal(l)
	}
	if l := UsageLevel(0, 30, time.Time{}, now, false); l != UsageUnknown {
		t.Fatal(l)
	}
}
