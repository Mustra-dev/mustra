package agent

import "testing"

func TestDisplayOSName(t *testing.T) {
	cases := []struct{ goos, platform, version, want string }{
		{"darwin", "darwin", "26.5.2", "macOS 26.5.2"},
		{"darwin", "", "", "macOS"},
		{"windows", "Microsoft Windows 11 Pro", "10.0.26100.4652 Build 26100.4652", "Windows 11 Pro"},
		{"windows", "microsoft windows server 2025 standard", "10.0.26100", "Windows Server 2025 Standard"},
		{"linux", "ubuntu", "24.04", "Ubuntu 24.04"},
		{"linux", "debian", "12.11", "Debian 12.11"},
		{"linux", "opensuse-leap", "15.6", "openSUSE Leap 15.6"},
		{"linux", "nixos", "25.05", "Nixos 25.05"},
		{"linux", "haos", "18.3", "Home Assistant OS 18.3"},
		{"linux", "", "", "Linux"},
		{"freebsd", "", "", "freebsd"},
	}
	for _, c := range cases {
		if got := displayOSName(c.goos, c.platform, c.version); got != c.want {
			t.Errorf("displayOSName(%q, %q, %q) = %q, want %q", c.goos, c.platform, c.version, got, c.want)
		}
	}
}
