package agent

import (
	"strings"
	"testing"
)

// Minimal Linux images have neither ip nor arp; the kernel's table is
// rewritten into the shape the parser already reads.
func TestProcNetARPFallback(t *testing.T) {
	raw := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.0.2.1        0x1         0x2         00:11:22:33:44:55     *        eth0\n" +
		"192.0.2.9        0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	got := procNetARP(raw)
	if got != "192.0.2.1 dev eth0 lladdr 00:11:22:33:44:55\n192.0.2.9 dev eth0 lladdr 00:00:00:00:00:00\n" {
		t.Fatalf("procNetARP = %q", got)
	}
	line := strings.Split(got, "\n")[0]
	if ipPattern.FindString(line) != "192.0.2.1" || interfaceFrom(line) != "eth0" || macPattern.FindString(line) == "" {
		t.Errorf("rewritten line does not parse: %q", line)
	}
}
