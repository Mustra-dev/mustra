package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Discover, layer 1: what does this endpoint already know about its
// neighbours?
//
// Every machine keeps an ARP/NDP table of the hosts it has recently talked
// to. Reading it costs one command and puts *zero* packets on the wire —
// no sweep, no SYNs, nothing an IDS will flag — and across a fleet the
// union of those tables covers a network surprisingly completely, because
// anything that talks to anything shows up in someone's table.
//
// That makes this the cheapest possible answer to "what is on my network
// that mustra doesn't manage?", and it is strictly better than a scan for
// the devices that matter most: a printer or a camera that never answers
// ping still appears in the ARP table of whatever it last spoke to.

// arpLine matches the shared shape of `ip neigh` and `arp -an` output well
// enough to pull an address and a MAC out of either without parsing each
// platform's full grammar.
var (
	ipPattern = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	// Colons on Linux and macOS, dashes in Windows' `arp -a`
	// (00-11-22-33-44-55): with colons only, Windows reported no neighbours.
	macPattern = regexp.MustCompile(`\b([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b`)
)

func collectNeighbors(ctx context.Context) ([]proto.NeighborInfo, error) {
	out, err := neighborTable(ctx)
	if err != nil {
		return nil, err
	}

	// The endpoint's own addresses are not neighbours, and including them
	// would make every agent look like an unmanaged device to every other.
	own := ownAddresses()

	seen := map[string]bool{}
	neighbors := []proto.NeighborInfo{}
	for _, line := range strings.Split(out, "\n") {
		ip := ipPattern.FindString(line)
		if ip == "" || own[ip] {
			continue
		}
		mac := normalizeMAC(macPattern.FindString(line))
		// An entry with no MAC is an incomplete/failed ARP resolution —
		// the address was asked about but never answered, so reporting it
		// would invent a device that may not exist.
		if mac == "" || mac == "00:00:00:00:00:00" || notADevice(ip, mac) {
			continue
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true
		neighbors = append(neighbors, proto.NeighborInfo{
			IP:        ip,
			MAC:       mac,
			Interface: interfaceFrom(line),
			State:     stateFrom(line),
		})
	}
	return neighbors, nil
}

func neighborTable(ctx context.Context) (string, error) {
	type attempt struct {
		bin  string
		args []string
	}
	var attempts []attempt
	switch runtime.GOOS {
	case "linux":
		attempts = []attempt{
			{"ip", []string{"neigh", "show"}},
			{"arp", []string{"-an"}},
		}
	case "darwin":
		attempts = []attempt{
			{"arp", []string{"-an"}},
			{"ndp", []string{"-an"}},
		}
	case "windows":
		attempts = []attempt{
			{"arp", []string{"-a"}},
		}
	}
	var lastErr error
	var combined strings.Builder
	for _, a := range attempts {
		path, err := exec.LookPath(a.bin)
		if err != nil {
			lastErr = err
			continue
		}
		out, err := exec.CommandContext(ctx, path, a.args...).Output()
		if err != nil {
			lastErr = err
			continue
		}
		combined.Write(out)
		combined.WriteString("\n")
	}
	// Minimal images (RHEL UBI, containers) often have neither ip nor arp,
	// and the sensor then failed on every cycle. The kernel's own table has
	// the IPv4 half of the answer.
	if combined.Len() == 0 && runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/proc/net/arp"); err == nil {
			return procNetARP(string(raw)), nil
		}
	}
	if combined.Len() == 0 && lastErr != nil {
		return "", lastErr
	}
	return combined.String(), nil
}

// procNetARP rewrites /proc/net/arp rows ("IP HWtype Flags MAC Mask Dev")
// into the `ip neigh` shape the parser reads ("IP dev DEV lladdr MAC").
func procNetARP(raw string) string {
	var b strings.Builder
	for i, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 6 {
			continue // header, or a short line
		}
		fmt.Fprintf(&b, "%s dev %s lladdr %s\n", f[0], f[5], f[3])
	}
	return b.String()
}

// ownAddresses is every address on this machine, so the agent doesn't
// report itself as a neighbour of itself.
func ownAddresses() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			out[ipnet.IP.String()] = true
		}
	}
	return out
}

// normalizeMAC pads each octet to two digits, because BSD arp prints
// "0:1e:c9:..." where Linux prints "00:1e:c9:...". Without this the same
// device reported by a Mac and a Linux box looks like two devices.
// notADevice drops the broadcast and multicast entries Windows keeps in its
// ARP table (ff-ff-ff-ff-ff-ff, 01-00-5e-…, 224.0.0.0/4): addresses, not
// machines on the network.
func notADevice(ip, mac string) bool {
	if mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e:") || strings.HasPrefix(mac, "33:33:") {
		return true
	}
	first, _, _ := strings.Cut(ip, ".")
	n, err := strconv.Atoi(first)
	return err == nil && n >= 224 || strings.HasSuffix(ip, ".255")
}

func normalizeMAC(mac string) string {
	if mac == "" {
		return ""
	}
	parts := strings.Split(strings.ReplaceAll(mac, "-", ":"), ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
		parts[i] = strings.ToLower(parts[i])
	}
	return strings.Join(parts, ":")
}

func interfaceFrom(line string) string {
	// Linux: "... dev eth0 ...";  BSD: "... on en0 ..."
	for _, key := range []string{" dev ", " on "} {
		if i := strings.Index(line, key); i >= 0 {
			rest := strings.Fields(line[i+len(key):])
			if len(rest) > 0 {
				return rest[0]
			}
		}
	}
	return ""
}

func stateFrom(line string) string {
	for _, s := range []string{"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"} {
		if strings.Contains(line, s) {
			return strings.ToLower(s)
		}
	}
	if strings.Contains(line, "permanent") {
		return "permanent"
	}
	return ""
}

var _ = context.Background
