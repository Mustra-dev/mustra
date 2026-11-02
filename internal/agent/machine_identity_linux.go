//go:build linux

package agent

import (
	"context"
	"os"
	"strings"
)

func readIdentity(context.Context) machineIdentity {
	dmi := func(f string) string {
		b, _ := os.ReadFile("/sys/class/dmi/id/" + f)
		return strings.TrimSpace(string(b))
	}
	id := machineIdentity{Manufacturer: dmi("sys_vendor"), Model: dmi("product_name"), Serial: dmi("product_serial"),
		BIOSDate: normalizeBIOSDate(dmi("bios_date")), Chassis: chassisName(dmi("chassis_type"))}
	if cleanIdentity(id.Serial) == "" {
		id.Serial = dmi("board_serial")
	}
	// Single-board computers have no DMI; the device tree names the board
	// and the CPU's serial identifies it.
	if cleanIdentity(id.Model) == "" {
		if b, err := os.ReadFile("/proc/device-tree/model"); err == nil {
			id.Model = strings.TrimRight(string(b), "\x00\n ")
			if strings.HasPrefix(id.Model, "Raspberry Pi") {
				id.Manufacturer = "Raspberry Pi"
			}
			id.Chassis = "single-board"
			if c, err := os.ReadFile("/proc/cpuinfo"); err == nil {
				for _, line := range strings.Split(string(c), "\n") {
					if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "Serial" {
						id.Serial = strings.TrimLeft(strings.TrimSpace(v), "0")
					}
				}
			}
		}
	}
	return id
}
