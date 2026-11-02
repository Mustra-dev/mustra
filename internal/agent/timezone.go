package agent

import "time"

// hostZone is this host's IANA time zone name when it can be found (""
// otherwise) and its current offset from UTC in seconds. The server uses
// them to read maintenance windows in endpoint local time; the offset is
// the fallback for a zone it cannot name.
func hostZone() (string, int) {
	_, offset := time.Now().Zone()
	name := ianaZone()
	if name != "" {
		loc, err := time.LoadLocation(name)
		if err != nil {
			return "", offset
		}
		// The named zone's offset, not time.Local's: on a host whose
		// /etc/localtime points at zoneinfo that is not installed, Go's
		// local time falls back to UTC while the (embedded) name is right.
		_, offset = time.Now().In(loc).Zone()
	}
	return name, offset
}
