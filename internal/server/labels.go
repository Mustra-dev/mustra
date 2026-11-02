package server

// Display labels for grouped values.
//
// A dashboard groups endpoints by a column and shows the raw value it found:
// "debian", "darwin", "microsoft windows server 2025 standard". The console
// has always tidied those on its own pages -- Debian, macOS, Windows Server
// 2025 Standard -- so the same fleet read two different ways depending on
// which panel you were looking at, and one of the two shouted a vendor name
// no other platform carries.
//
// The tidying happens here rather than at ingest because the raw value is
// what targeting rules, saved queries and exports match on. A group whose
// rule says `platform equals debian` has to keep matching after this, and a
// drill-down link built from a panel has to carry the raw value too -- which
// is why seriesPoint has both a Key and a Label.
//
// Kept deliberately in step with platformLabel and osLabel in
// static/app.js. Two implementations is one more than anybody wants; the
// alternative is the server sending display strings the console cannot
// reproduce for data it renders itself, which is worse.

import "strings"

// notSetLabel is what a blank group value is shown as.
const notSetLabel = "(not set)"

// osLabels are the kernel/OS values the agent reports.
var osLabels = map[string]string{
	"linux": "Linux", "darwin": "macOS", "windows": "Windows",
}

// platformLabels are distributions as their own projects write them. RHEL
// and openSUSE are not "Rhel" and "Opensuse".
var platformLabels = map[string]string{
	"debian": "Debian", "ubuntu": "Ubuntu", "raspbian": "Raspberry Pi OS",
	"rhel": "RHEL", "redhat": "Red Hat", "centos": "CentOS", "rocky": "Rocky Linux",
	"almalinux": "AlmaLinux", "fedora": "Fedora", "opensuse": "openSUSE",
	"opensuse-leap": "openSUSE Leap", "suse": "SUSE", "sles": "SLES",
	"arch": "Arch Linux", "alpine": "Alpine", "gentoo": "Gentoo",
	"amzn": "Amazon Linux", "ol": "Oracle Linux", "linuxmint": "Linux Mint",
	"pop": "Pop!_OS", "darwin": "macOS", "windows": "Windows",
	"haos": "Home Assistant OS",
}

// displayLabel renders one grouped value for a person. Columns it has no
// opinion about are returned unchanged: inventing a prettier form of an
// arbitrary string is how a label stops matching the thing it names.
func displayLabel(column, value string) string {
	// "(not set)" is the console's own word for a blank, not a value the
	// fleet reported. Tidying it produced "(not Set)".
	if value == "" || value == notSetLabel {
		return value
	}
	switch column {
	case "os":
		if l, ok := osLabels[strings.ToLower(value)]; ok {
			return l
		}
	case "platform":
		if l, ok := platformLabels[strings.ToLower(value)]; ok {
			return l
		}
		return prettyProductName(value)
	}
	return value
}

// prettyProductName tidies an unmapped platform string. gopsutil reports
// Windows as a whole lowercase product name, and the vendor prefix is the
// part that made it too long to fit a legend cell -- no other platform here
// carries one. Words that already have capitals keep them, so a name that
// arrives correctly cased is not "corrected".
func prettyProductName(value string) string {
	value = trimPrefixFold(value, "microsoft ")
	words := strings.Split(value, " ")
	for i, w := range words {
		if w != "" && w == strings.ToLower(w) {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// trimPrefixFold removes prefix case-insensitively, and only when what
// follows is "windows" -- a platform that merely begins with the word
// Microsoft keeps its name.
func trimPrefixFold(value, prefix string) string {
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return value
	}
	rest := value[len(prefix):]
	if !strings.HasPrefix(strings.ToLower(rest), "windows") {
		return value
	}
	return rest
}

// newSeriesPoint pairs a display label with the raw value behind it.
func newSeriesPoint(column, raw string, value int, share float64) seriesPoint {
	return seriesPoint{
		Label: displayLabel(column, raw),
		Key:   rawKey(column, raw),
		Value: value,
		Share: share,
	}
}

// rawKey is the original value, or empty when the label already is it --
// the common case, and not worth a byte on the wire per point.
func rawKey(column, raw string) string {
	if displayLabel(column, raw) == raw {
		return ""
	}
	return raw
}

// seriesKey is the raw value a point was built from. Key is empty whenever
// the label is already the raw value, so this is where that is unpacked.
func seriesKey(sp seriesPoint) string {
	if sp.Key != "" {
		return sp.Key
	}
	return sp.Label
}
