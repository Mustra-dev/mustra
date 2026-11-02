package agent

import (
	"context"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/host"
)

// The operating system as people name it, for the Self Service window.
//
// The window showed runtime.GOOS, so a Mac read "darwin": the right value
// for the protocol and for group rules, and not a word anyone at the Mac
// uses. This is presentation only. Everything that matches or stores the OS
// still uses the GOOS value. The names follow the console's platformLabel and
// osDisplay in static/app.js, so a machine reads the same in both places.

// platformNames holds distro names as their projects write them. Anything
// unrecognized is title-cased.
var platformNames = map[string]string{
	"debian": "Debian", "ubuntu": "Ubuntu", "raspbian": "Raspberry Pi OS", "rhel": "RHEL",
	"redhat": "Red Hat", "centos": "CentOS", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
	"fedora": "Fedora", "opensuse": "openSUSE", "opensuse-leap": "openSUSE Leap",
	"suse": "SUSE", "sles": "SLES", "arch": "Arch Linux", "alpine": "Alpine", "gentoo": "Gentoo",
	"amzn": "Amazon Linux", "ol": "Oracle Linux", "linuxmint": "Linux Mint", "pop": "Pop!_OS",
	"darwin": "macOS", "macos": "macOS", "windows": "Windows", platformHAOS: "Home Assistant OS",
}

var goosNames = map[string]string{"linux": "Linux", "darwin": "macOS", "windows": "Windows"}

var microsoftPrefix = regexp.MustCompile(`(?i)^microsoft\s+`)

// displayOSName builds the name from gopsutil's platform and version,
// falling back to the GOOS name when there is no platform.
func displayOSName(goos, platform, version string) string {
	platform = strings.TrimSpace(platform)
	if platform == "" {
		if n, ok := goosNames[goos]; ok {
			return n
		}
		return goos
	}
	name, ok := platformNames[strings.ToLower(platform)]
	if !ok {
		// gopsutil reports Windows as the product string, "Microsoft
		// Windows 11 Pro", which already carries its version.
		words := strings.Fields(microsoftPrefix.ReplaceAllString(platform, ""))
		for i, w := range words {
			if w == strings.ToLower(w) {
				words[i] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
		name = strings.Join(words, " ")
	}
	if strings.ContainsAny(name, "0123456789") {
		return name
	}
	if v := strings.TrimSpace(version); v != "" {
		return name + " " + v
	}
	return name
}

// osName is looked up once: it cannot change without a reboot, and the
// window asks for it every time it opens.
var osName = sync.OnceValue(func() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var platform, version string
	if hi, err := host.InfoWithContext(ctx); err == nil {
		platform, version = hi.Platform, hi.PlatformVersion
	}
	if h := haosHostInfo(ctx); h != nil {
		platform, version = platformHAOS, h.OSVersion
	}
	return displayOSName(runtime.GOOS, platform, version)
})
