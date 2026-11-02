package agent

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/sensors"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Inventory sensors beyond the original four. Everything here comes from
// gopsutil, which is already a dependency and already cross-platform — no
// per-OS shelling out, unlike services/installed apps/patches.
//
// These are modeled as sensors rather than facts on purpose: a sensor is
// JSONB, so adding a property later costs nothing, while a new fact would
// mean a column and a migration every time.

const bytesPerGB = 1024 * 1024 * 1024
const bytesPerMB = 1024 * 1024

// collectDisks lists mounted filesystems and how full they are. Pseudo
// filesystems (tmpfs, proc, cgroup, overlay layers) are skipped: they'd
// bury the real volumes, which are what anyone is actually asking about.
func collectDisks(ctx context.Context) ([]proto.DiskInfo, error) {
	// In the HAOS add-on the only mounts are the container's own; the
	// host's data disk is known only to the Supervisor.
	if inHAOSAddon() {
		if d := haosDataDisk(ctx); d != nil {
			return []proto.DiskInfo{*d}, nil
		}
	}
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("list partitions: %w", err)
	}
	skipFS := map[string]bool{
		"tmpfs": true, "devtmpfs": true, "proc": true, "sysfs": true, "cgroup": true,
		"cgroup2": true, "devpts": true, "squashfs": true, "overlay": true, "autofs": true,
		"debugfs": true, "tracefs": true, "fusectl": true, "configfs": true, "securityfs": true,
		"pstore": true, "bpf": true, "hugetlbfs": true, "mqueue": true, "ramfs": true,
	}
	var out []proto.DiskInfo
	for _, p := range partitions {
		if skipFS[strings.ToLower(p.Fstype)] {
			continue
		}
		usage, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil || usage == nil || usage.Total == 0 {
			continue // an unreadable or empty mount isn't worth reporting
		}
		out = append(out, proto.DiskInfo{
			Device:      p.Device,
			Mountpoint:  p.Mountpoint,
			FSType:      p.Fstype,
			TotalGB:     round2(float64(usage.Total) / bytesPerGB),
			FreeGB:      round2(float64(usage.Free) / bytesPerGB),
			UsedGB:      round2(float64(usage.Used) / bytesPerGB),
			UsedPercent: round2(usage.UsedPercent),
		})
	}
	return out, nil
}

// collectNetworkInterfaces lists interfaces with their addresses. Loopback
// is included — "does this box have an unexpected interface" is a real
// question, and filtering it out would hide the answer.
func collectNetworkInterfaces(ctx context.Context) ([]proto.NetworkInterfaceInfo, error) {
	ifaces, err := net.InterfacesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := make([]proto.NetworkInterfaceInfo, 0, len(ifaces))
	for _, i := range ifaces {
		addrs := make([]string, 0, len(i.Addrs))
		for _, a := range i.Addrs {
			addrs = append(addrs, a.Addr)
		}
		up := false
		for _, f := range i.Flags {
			if strings.EqualFold(f, "up") {
				up = true
				break
			}
		}
		out = append(out, proto.NetworkInterfaceInfo{
			Name: i.Name, MAC: i.HardwareAddr, Addresses: addrs, MTU: i.MTU, Up: up,
		})
	}
	return out, nil
}

// collectLoggedInUsers reports active login sessions — who is on this box
// right now, which is the question behind most "why did this change" moments.
func collectLoggedInUsers(ctx context.Context) ([]proto.LoggedInUser, error) {
	if runtime.GOOS == "windows" {
		// gopsutil has no Windows implementation, so Windows endpoints
		// reported nobody signed in, ever. quser lists the sessions.
		out, _ := exec.CommandContext(ctx, "quser").Output() // exits 1 when nobody is signed in
		return parseQuser(string(out), time.Local), nil
	}
	users, err := host.UsersWithContext(ctx)
	if err != nil {
		// Not every platform/container can answer this (no utmp, for
		// instance). An empty list is the honest result, not an error that
		// would mark the whole sensor as failing forever.
		return []proto.LoggedInUser{}, nil
	}
	out := make([]proto.LoggedInUser, 0, len(users))
	for _, u := range users {
		started := ""
		if u.Started > 0 {
			started = time.Unix(int64(u.Started), 0).UTC().Format(time.RFC3339)
		}
		out = append(out, proto.LoggedInUser{
			User: u.User, Terminal: u.Terminal, Host: u.Host, Started: started,
		})
	}
	return out, nil
}

// collectHardware gathers the machine's fixed characteristics plus a few
// live gauges. Every field is best-effort: a missing piece leaves its zero
// value rather than failing the whole snapshot, since these come from a
// dozen independent sources and any one of them can be unavailable in a
// container or on a locked-down host.
func collectHardware(ctx context.Context) ([]proto.HardwareInfo, error) {
	var h proto.HardwareInfo

	if info, err := host.InfoWithContext(ctx); err == nil && info != nil {
		h.HostID = info.HostID
		h.OSFamily = info.PlatformFamily
		if inHAOSAddon() {
			h.OSFamily = platformHAOS
		}
		h.KernelArch = info.KernelArch
		h.VirtualizationSystem = info.VirtualizationSystem
		h.VirtualizationRole = info.VirtualizationRole
		h.UptimeHours = round2(float64(info.Uptime) / 3600)
		if info.BootTime > 0 {
			h.BootTime = time.Unix(int64(info.BootTime), 0).UTC().Format(time.RFC3339)
		}
	}
	if cpus, err := cpu.InfoWithContext(ctx); err == nil && len(cpus) > 0 {
		h.CPUModel = cpus[0].ModelName
		h.CPUVendor = cpus[0].VendorID
		h.CPUMHz = round2(cpus[0].Mhz)
	}
	if n, err := cpu.CountsWithContext(ctx, false); err == nil {
		h.CPUCoresPhysical = n
	}
	if n, err := cpu.CountsWithContext(ctx, true); err == nil {
		h.CPUCoresLogical = n
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil && vm != nil {
		h.MemTotalMB = vm.Total / bytesPerMB
		h.MemAvailableMB = vm.Available / bytesPerMB
		h.MemUsedPercent = round2(vm.UsedPercent)
	}
	if sm, err := mem.SwapMemoryWithContext(ctx); err == nil && sm != nil {
		h.SwapTotalMB = sm.Total / bytesPerMB
	}
	if avg, err := load.AvgWithContext(ctx); err == nil && avg != nil {
		h.LoadAvg1, h.LoadAvg5, h.LoadAvg15 = round2(avg.Load1), round2(avg.Load5), round2(avg.Load15)
	}
	if temps, err := sensors.TemperaturesWithContext(ctx); err == nil {
		for _, t := range temps {
			if t.Temperature > h.TempMaxC {
				h.TempMaxC = round2(t.Temperature)
			}
		}
	}

	// A container sees its host's firmware tables; reporting those as its
	// own would give every container on a node the node's serial number.
	if !(h.VirtualizationRole == "guest" && (h.VirtualizationSystem == "lxc" || h.VirtualizationSystem == "docker" || h.VirtualizationSystem == "podman")) && !inHAOSAddon() {
		id := cachedIdentity(ctx)
		h.Manufacturer, h.Model, h.Serial, h.BIOSDate, h.Chassis = id.Manufacturer, id.Model, id.Serial, id.BIOSDate, id.Chassis
		if h.VirtualizationRole == "guest" {
			h.Chassis = "virtual"
		}
	} else {
		h.Chassis = "container"
	}

	// A single row, so the group-rule engine can address it the same way it
	// addresses every other sensor (hardware.cpu_model, hardware.uptime_hours).
	return []proto.HardwareInfo{h}, nil
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

// parseQuser reads `quser` (query user), whose columns line up under its
// header rather than being delimited:
//
//	 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
//	>alex                  console             1  Active      none   10/17/2026 9:02 PM
//	 bob                                       2  Disc        1:05   10/16/2026 8:10 AM
func parseQuser(out string, loc *time.Location) []proto.LoggedInUser {
	users := []proto.LoggedInUser{}
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	if len(lines) == 0 {
		return users
	}
	head := lines[0]
	sess, id, logon := strings.Index(head, "SESSIONNAME"), strings.Index(head, " ID "), strings.Index(head, "LOGON TIME")
	state, idle := strings.Index(head, "STATE"), strings.Index(head, "IDLE TIME")
	if sess < 0 || id < 0 || logon < 0 {
		return users
	}
	col := func(line string, from, to int) string {
		if from >= len(line) {
			return ""
		}
		if to > len(line) || to < 0 {
			to = len(line)
		}
		return strings.TrimSpace(line[from:to])
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name := strings.TrimLeft(col(line, 0, sess), "> ")
		if name == "" {
			continue
		}
		terminal := col(line, sess, id)
		if terminal == "" {
			terminal = "disconnected"
		}
		started := ""
		if t, err := time.ParseInLocation("1/2/2006 3:04 PM", col(line, logon, -1), loc); err == nil {
			started = t.UTC().Format(time.RFC3339)
		}
		u := proto.LoggedInUser{User: name, Terminal: terminal, Started: started}
		// The ID column is right-aligned under " ID ", so it may start
		// before the header's column; the number ends where STATE begins.
		if state > 0 {
			u.SessionID, _ = strconv.Atoi(col(line, id, state))
			if idle > state {
				u.State = col(line, state, idle)
			}
		}
		users = append(users, u)
	}
	return users
}
