// Package swinventory turns the fleet's raw installed-application rows into
// products — one name per thing regardless of platform packaging — and
// grades how much each one is used from the process starts the fleet
// already reports.
//
// The normalisation is deliberately conservative: a display name loses its
// trailing version, architecture and per-user markers, and a publisher
// loses its corporate suffix, but two things are only merged when their
// cleaned names agree exactly. Over-merging ("Microsoft Visual C++" swallowing
// six redistributables) is worse than a duplicate row, because usage and
// cost are counted per product.
package swinventory

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Product is a normalised installed application.
type Product struct {
	Name   string
	Vendor string
	// Key identifies the product across platforms and versions: the
	// cleaned name lower-cased with runs of punctuation collapsed.
	Key string
}

var (
	// "Google Chrome 128.0.6613.120", "Python 3.12.1 (64-bit)", "7-Zip 23.01 (x64)",
	// "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130".
	// A whole parenthesised marker first ("(x64 en-US)", "(Machine - x64)"),
	// then bare tokens.
	reArchParen = regexp.MustCompile(`(?i)\s*[\(\[]\s*(x64|x86|amd64|arm64|64[- ]?bits?|32[- ]?bits?|machine\s*-\s*x64|machine-wide|user|current user|all users)[^)\]]*[\)\]]\s*`)
	reArch      = regexp.MustCompile(`(?i)\s+(x64|x86|amd64|arm64|64[- ]?bits?|32[- ]?bits?)\s*$`)
	reVerTail   = regexp.MustCompile(`(?i)[\s\-–:]*\b(v(?:er(?:sion)?)?\.?\s*)?\d+(\.\d+){1,4}[a-z0-9\-]*\s*$`)
	reVerParen  = regexp.MustCompile(`(?i)\s*\((v(?:er(?:sion)?)?\.?\s*)?\d+(\.\d+){1,4}[^)]*\)\s*$`)
	reSpaces    = regexp.MustCompile(`\s+`)
	reKeyPunct  = regexp.MustCompile(`[^a-z0-9]+`)
	reSuffix    = regexp.MustCompile(`(?i)[,\s]+(inc\.?|incorporated|llc\.?|ltd\.?|limited|corp\.?|corporation|co\.?|gmbh|s\.?a\.?|plc|ag|b\.?v\.?|pty|s\.?r\.?l\.?|the)\s*$`)
)

// Normalize returns the product for one raw inventory row. os is the
// agent's GOOS value; it only matters where a platform's packaging has a
// convention worth undoing (dpkg's ":arch" qualifier).
func Normalize(name, publisher, os string) Product {
	n := strings.TrimSpace(name)
	if os == "linux" {
		if i := strings.Index(n, ":"); i > 0 { // "libc6:amd64"
			n = n[:i]
		}
	} else {
		n = reArchParen.ReplaceAllString(n, " ")
		n = reVerParen.ReplaceAllString(n, "")
		n = reArch.ReplaceAllString(n, "")
		n = reVerTail.ReplaceAllString(n, "")
		n = strings.TrimRight(strings.TrimSpace(n), " -–:,")
	}
	n = strings.TrimSpace(reSpaces.ReplaceAllString(n, " "))
	if n == "" {
		n = strings.TrimSpace(name)
	}
	v := cleanVendor(publisher)
	if v == "" {
		v = inferVendor(n)
	}
	return Product{Name: n, Vendor: v, Key: Key(n)}
}

// Key is the cross-platform identity of a product name.
func Key(name string) string {
	k := strings.ToLower(strings.TrimSpace(name))
	k = reKeyPunct.ReplaceAllString(k, " ")
	return strings.TrimSpace(k)
}

func cleanVendor(p string) string {
	v := strings.TrimSpace(p)
	for i := 0; i < 3; i++ { // "Google LLC", "Oracle Corporation, Inc."
		nv := strings.TrimSpace(reSuffix.ReplaceAllString(v, ""))
		nv = strings.TrimRight(nv, ",. ")
		if nv == v {
			break
		}
		v = nv
	}
	return v
}

// vendorByPrefix catches names that carry their vendor ("Microsoft Edge",
// "Mozilla Firefox"); vendorByName is for the ones that do not.
var vendorByPrefix = []string{"Microsoft", "Google", "Mozilla", "Adobe", "Apple", "Oracle", "Amazon", "Cisco", "Citrix", "VMware", "Autodesk", "Intel", "NVIDIA", "AMD", "Dell", "HP", "Lenovo", "Logitech", "Zoom", "Slack", "Atlassian", "JetBrains", "Docker", "Canonical", "Red Hat", "Proxmox", "Tailscale"}

var vendorByName = map[string]string{
	"safari": "Apple", "xcode": "Apple", "numbers": "Apple", "pages": "Apple", "keynote": "Apple", "garageband": "Apple", "imovie": "Apple", "terminal": "Apple",
	"chrome": "Google", "chromium": "Google", "firefox": "Mozilla", "thunderbird": "Mozilla",
	"visual studio code": "Microsoft", "teams": "Microsoft", "outlook": "Microsoft", "onedrive": "Microsoft", "edge": "Microsoft", "powershell": "Microsoft", "windows terminal": "Microsoft",
	"slack": "Slack", "zoom us": "Zoom", "discord": "Discord", "spotify": "Spotify", "1password": "AgileBits", "docker": "Docker", "docker desktop": "Docker",
	"iterm": "iTerm2", "iterm2": "iTerm2", "vlc": "VideoLAN", "vlc media player": "VideoLAN", "7 zip": "Igor Pavlov", "notepad": "Notepad++ Team", "putty": "Simon Tatham",
	"git": "Software Freedom Conservancy", "curl": "curl project", "vim": "Bram Moolenaar", "python": "Python Software Foundation", "node": "OpenJS Foundation", "nodejs": "OpenJS Foundation",
	"tailscale": "Tailscale", "wireguard": "WireGuard", "postgresql": "PostgreSQL Global Development Group", "nginx": "F5", "apache2": "Apache Software Foundation",
	"claude": "Anthropic", "cursor": "Anysphere", "figma": "Figma", "notion": "Notion Labs", "obsidian": "Dynalist", "postman": "Postman", "tableplus": "TablePlus", "rectangle": "Ryan Hanson",
}

func inferVendor(name string) string {
	k := Key(name)
	if v, ok := vendorByName[k]; ok {
		return v
	}
	for _, p := range vendorByPrefix {
		if strings.HasPrefix(strings.ToLower(k+" "), strings.ToLower(p)+" ") {
			return p
		}
	}
	return ""
}

// knownExecutables maps a product key to the process names its use shows
// up as. Windows names are without ".exe"; macOS bundles usually run as the
// bundle name, which the fallback below covers.
var knownExecutables = map[string][]string{
	"google chrome": {"chrome", "google chrome"}, "chromium": {"chromium", "chromium-browser", "chrome"},
	"microsoft edge": {"msedge", "microsoft edge"}, "mozilla firefox": {"firefox", "firefox-bin", "firefox-esr"}, "firefox": {"firefox", "firefox-bin", "firefox-esr"}, "firefox esr": {"firefox-esr", "firefox"},
	"visual studio code": {"code", "code - insiders", "electron"}, "microsoft visual studio code": {"code"},
	"microsoft teams": {"teams", "ms-teams", "msteams"}, "microsoft office": {"winword", "excel", "powerpnt", "outlook", "onenote", "msaccess"},
	"microsoft 365 apps for enterprise": {"winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "teams"}, "microsoft 365": {"winword", "excel", "powerpnt", "outlook", "onenote"},
	"microsoft onedrive": {"onedrive"}, "onedrive": {"onedrive"}, "microsoft outlook": {"outlook", "olk"},
	"adobe acrobat": {"acrobat", "acrord32", "adobe acrobat"}, "adobe acrobat reader": {"acrord32", "acrobat"}, "adobe acrobat dc": {"acrobat", "acrord32"},
	"7 zip": {"7zfm", "7z", "7zg"}, "notepad": {"notepad++", "notepad"}, "vlc media player": {"vlc"}, "vlc": {"vlc"},
	"putty": {"putty", "plink", "pscp"}, "winscp": {"winscp"}, "git": {"git", "git-bash", "bash"}, "python": {"python", "python3", "pythonw"}, "python launcher": {"py"},
	"node js": {"node"}, "nodejs": {"node"}, "docker desktop": {"docker desktop", "com.docker.backend", "docker"}, "docker ce": {"dockerd", "docker"}, "docker io": {"dockerd", "docker"}, "containerd io": {"containerd"},
	"zoom": {"zoom", "zoom us", "cpthost"}, "zoom us": {"zoom", "zoom us"}, "slack": {"slack"}, "discord": {"discord"}, "spotify": {"spotify"}, "1password": {"1password"},
	"iterm": {"iterm2"}, "iterm2": {"iterm2"}, "terminal": {"terminal"}, "safari": {"safari"}, "xcode": {"xcode"},
	"tailscale": {"tailscaled", "tailscale"}, "wireguard": {"wireguard", "wg", "wg-quick"}, "openssh server": {"sshd"}, "openssh client": {"ssh", "scp", "sftp"},
	"postgresql": {"postgres", "psql"}, "nginx": {"nginx"}, "apache2": {"apache2", "httpd"}, "mariadb server": {"mariadbd", "mysqld"}, "mysql server": {"mysqld"}, "redis server": {"redis-server"},
	"cron": {"cron", "crond"}, "rsync": {"rsync"}, "vim": {"vim", "vi"}, "vim tiny": {"vi", "vim.tiny"}, "nano": {"nano"}, "tmux": {"tmux"}, "screen": {"screen"}, "htop": {"htop"}, "curl": {"curl"}, "wget": {"wget"},
	"sudo": {"sudo"}, "systemd": {"systemctl", "systemd", "journalctl"}, "openssl": {"openssl"}, "gnupg": {"gpg", "gpg-agent"}, "unattended upgrades": {"unattended-upgrade", "unattended-upgrades"},
	"proxmox backup client": {"proxmox-backup-client"}, "salt minion": {"salt-minion"}, "netdata": {"netdata"}, "prometheus node exporter": {"prometheus-node-exporter", "node_exporter"},
	"claude": {"claude"}, "cursor": {"cursor"}, "windows terminal": {"windowsterminal", "wt"}, "powershell": {"pwsh", "powershell"},
	"google chrome enterprise": {"chrome"}, "sysinternals": {"procexp", "procmon"}, "wireshark": {"wireshark"}, "microsoft sql server management studio": {"ssms"},
}

// Executables lists the process names whose start counts as use of the
// product. explicit is what the endpoint reported (Windows DisplayIcon,
// CFBundleExecutable); extra is what an operator added on a tracked product.
// Names come back lower-cased without ".exe" — the same form the usage
// rollup stores.
func Executables(p Product, explicit string, extra []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = ExeKey(n)
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, e := range extra {
		add(e)
	}
	add(explicit)
	for _, e := range knownExecutables[p.Key] {
		add(e)
	}
	// The fallbacks: the product name as a process ("Google Chrome" on
	// macOS, "firefox" on Linux) and it squeezed together ("notepad++").
	add(p.Name)
	add(strings.ReplaceAll(p.Name, " ", ""))
	return out
}

// ExeKey normalises a process name the way the usage rollup does:
// lower-case, no directory, no ".exe".
func ExeKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	n = strings.TrimSuffix(n, ".exe")
	n = strings.TrimSuffix(n, ".app")
	return strings.TrimSpace(n)
}

// componentPrefixes and componentSuffixes mark packages that are not
// programs anyone launches — libraries, headers, data, runtimes, drivers.
// Their "usage" is meaningless, so they are inventoried but never graded
// unused, and never offered for removal.
var componentPrefixes = []string{"lib", "python3-", "python-", "perl-", "ruby-", "php-", "fonts-", "linux-image", "linux-headers", "linux-modules", "gcc-", "g++-", "cpp-", "xserver-", "x11-", "gir1.2-", "golang-", "node-", "texlive-", "r-cran-", "r-base", "openjdk-", "adoptium-", "dictionaries-", "hunspell-", "aspell-", "ca-certificates", "tzdata", "locales", "keyboard-configuration", "console-setup", "base-", "init-system", "dpkg", "apt-", "debian-", "ubuntu-", "microsoft visual c++", "microsoft .net", "microsoft asp.net", "windows sdk", "microsoft windows desktop runtime", "microsoft edge webview2", "microsoft edge update", "microsoft update health", "update for ", "security update for", "hotfix for", "kb", "intel(r)", "nvidia graphics", "realtek", "vc_redist", "vcredist", "msvc", "directx"}
var componentSuffixes = []string{"-dev", "-doc", "-docs", "-data", "-common", "-l10n", "-locale", "-locales", "-dbg", "-dbgsym", "-headers", "-modules", "-plugins", "-theme", "-themes", "-icons", "-icon-theme", "-utils-common", " redistributable", " runtime", " sdk", " driver", " drivers", " webview2 runtime", " update helper", " update service", " language pack"}

// IsComponent reports whether a product is a library, runtime, driver or
// data package rather than a program.
func IsComponent(name, os string) bool {
	k := strings.ToLower(strings.TrimSpace(name))
	for _, p := range componentPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	for _, s := range componentSuffixes {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	if os == "linux" && (strings.Contains(k, "-lib") || strings.HasPrefix(k, "lib")) {
		return true
	}
	return false
}

// Usage levels. Graded on days-with-a-launch inside the window, not raw
// launch counts: a browser that restarts its helpers every minute is not
// "used" more than one opened every morning.
const (
	UsageHeavy    = "heavy"    // half the days in the window or more
	UsageModerate = "moderate" // more than one day a week
	UsageLight    = "light"    // at least once
	UsageUnused   = "unused"   // executables known, none started in the window
	UsageUnknown  = "unknown"  // a component, or no way to tell what would run
)

// UsageLevel grades one product on one endpoint. daysUsed is how many
// distinct days inside a window of windowDays saw a launch; lastUsed is the
// most recent use from any source (zero when none); trackable says whether
// use could have been seen at all.
func UsageLevel(daysUsed, windowDays int, lastUsed time.Time, now time.Time, trackable bool) string {
	if !trackable {
		return UsageUnknown
	}
	if windowDays <= 0 {
		windowDays = 30
	}
	inWindow := !lastUsed.IsZero() && now.Sub(lastUsed) <= time.Duration(windowDays)*24*time.Hour
	switch {
	case daysUsed*2 >= windowDays:
		return UsageHeavy
	case daysUsed*7 > windowDays:
		return UsageModerate
	case daysUsed > 0 || inWindow:
		return UsageLight
	default:
		return UsageUnused
	}
}

// HasKnownExecutables reports whether the built-in table knows what a
// product runs as — the difference between "unused" and "unknown" on a
// platform that did not report an executable.
func HasKnownExecutables(key string) bool {
	_, ok := knownExecutables[key]
	return ok
}

// CompareVersions orders two dotted version strings numerically where it
// can, lexically where it cannot; 0 when equal or either is empty.
func CompareVersions(a, b string) int {
	if a == "" || b == "" {
		return 0
	}
	as, bs := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '~' }), strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '~' })
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an > bn {
					return 1
				}
				return -1
			}
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return len(as) - len(bs)
}
