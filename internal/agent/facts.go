package agent

import (
	"context"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectFacts gathers a gopsutil-derived snapshot of this host. It is
// deliberately narrow (the "core 80%" named in the project brief) and
// side-effect-free so it's cheap to call both on a timer and on demand for
// a live query.
func collectFacts(ctx context.Context, agentID string, info proto.AgentInfo, agentVersion string) (proto.Facts, error) {
	f := proto.Facts{
		AgentID:   agentID,
		Timestamp: time.Now().UTC(),
		Hostname:  info.Hostname,
		OS:        info.OS,
		Arch:      info.Arch,
		Site:      info.Site,
		AgentVer:  agentVersion,
		IPs:       collectIPs(),
	}
	name, offset := hostZone()
	f.Timezone, f.UTCOffsetSeconds = name, &offset

	if hi, err := host.InfoWithContext(ctx); err == nil {
		f.Platform = hi.Platform
		f.PlatformVer = hi.PlatformVersion
		f.KernelVer = hi.KernelVersion
		f.UptimeSec = hi.Uptime
	}
	if h := haosHostInfo(ctx); h != nil {
		f.Platform, f.PlatformVer = platformHAOS, h.OSVersion
		if h.Kernel != "" {
			f.KernelVer = h.Kernel
		}
	}
	if counts, err := cpu.CountsWithContext(ctx, true); err == nil {
		f.CPUCount = counts
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		f.MemTotalMB = vm.Total / (1024 * 1024)
	}

	return f, nil
}

// collectIPs returns non-loopback IP addresses across all up interfaces.
// gopsutil's net package targets IO counters, not addressing, so this uses
// the standard library directly — one fewer syscall path through gopsutil
// keeps the agent's footprint down.
func collectIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips
}

// localAgentInfo builds the static identity this agent presents at
// registration, from the running host — cheap enough to call once at
// startup.
func localAgentInfo(site, agentVersion string) (proto.AgentInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	// Inside the HAOS add-on, the container's name is not the endpoint's.
	if h := haosHostInfo(context.Background()); h != nil && h.Hostname != "" {
		hostname = h.Hostname
	}
	return proto.AgentInfo{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Site:     site,
		Version:  agentVersion,
	}, nil
}
