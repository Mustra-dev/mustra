package agent

import (
	"testing"
	"time"
)

// Windows' arp -a: dashes in the MAC, plus broadcast and multicast entries
// that are addresses rather than devices.
func TestNeighborsFromWindowsArp(t *testing.T) {
	out := `
Interface: 10.0.10.103 --- 0x11
  Internet Address      Physical Address      Type
  10.0.10.1            74-ac-b9-11-22-33     dynamic
  10.0.10.143          26-29-fa-a6-99-9e     dynamic
  10.0.10.255          ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
`
	var got []string
	for _, line := range splitLines(out) {
		ip := ipPattern.FindString(line)
		mac := normalizeMAC(macPattern.FindString(line))
		if ip == "" || mac == "" || notADevice(ip, mac) {
			continue
		}
		got = append(got, ip+"="+mac)
	}
	if len(got) != 2 || got[0] != "10.0.10.1=74:ac:b9:11:22:33" || got[1] != "10.0.10.143=26:29:fa:a6:99:9e" {
		t.Fatalf("got %v", got)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func TestParseQuser(t *testing.T) {
	out := " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\r\n" +
		">alexe                 console             1  Active      none   10/17/2026 9:02 PM\r\n" +
		" bob                                       2  Disc        1:05   10/16/2026 8:10 AM\r\n"
	loc := time.FixedZone("PDT", -7*3600)
	got := parseQuser(out, loc)
	if len(got) != 2 || got[0].User != "alexe" || got[0].Terminal != "console" || got[0].Started != "2026-10-18T04:02:00Z" ||
		got[1].User != "bob" || got[1].Terminal != "disconnected" {
		t.Fatalf("got %+v", got)
	}
	// The session id and state are what shadowing a session needs.
	if got[0].SessionID != 1 || got[0].State != "Active" || got[1].SessionID != 2 || got[1].State != "Disc" {
		t.Fatalf("session id/state: %+v", got)
	}
	// A two-digit id, as a terminal server has, still parses.
	wide := " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\r\n" +
		" carol                 rdp-tcp#12         14  Active       3   10/17/2026 9:02 PM\r\n"
	if w := parseQuser(wide, loc); len(w) != 1 || w[0].SessionID != 14 || w[0].State != "Active" || w[0].Terminal != "rdp-tcp#12" {
		t.Fatalf("wide: %+v", w)
	}
	if len(parseQuser("No User exists for *\r\n", loc)) != 0 {
		t.Error("nobody signed in")
	}
}
