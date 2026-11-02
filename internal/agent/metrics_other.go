//go:build !linux

package agent

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

// On macOS and Windows the same node_exporter names are filled from
// gopsutil, so one dashboard covers the fleet. What a platform does not have
// (load average on Windows, iowait outside Linux) is simply not sent.
func collectHostMetrics(ctx context.Context, on map[string]bool) *metricSet {
	m := newMetricSet()
	if on["cpu"] {
		if times, err := cpu.TimesWithContext(ctx, true); err == nil {
			for i, t := range times {
				c := fmt.Sprint(i)
				for mode, v := range map[string]float64{"user": t.User, "system": t.System, "idle": t.Idle, "nice": t.Nice,
					"iowait": t.Iowait, "irq": t.Irq, "softirq": t.Softirq, "steal": t.Steal} {
					if v > 0 || mode == "user" || mode == "system" || mode == "idle" {
						m.counter("node_cpu_seconds_total", v, "cpu", c, "mode", mode)
					}
				}
			}
		}
	}
	if on["memory"] {
		if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
			m.gauge("node_memory_MemTotal_bytes", float64(v.Total))
			m.gauge("node_memory_MemAvailable_bytes", float64(v.Available))
			m.gauge("node_memory_MemFree_bytes", float64(v.Free))
			if v.Cached > 0 {
				m.gauge("node_memory_Cached_bytes", float64(v.Cached))
			}
		}
		if s, err := mem.SwapMemoryWithContext(ctx); err == nil {
			m.gauge("node_memory_SwapTotal_bytes", float64(s.Total))
			m.gauge("node_memory_SwapFree_bytes", float64(s.Free))
		}
	}
	if on["load"] && runtime.GOOS != "windows" {
		if l, err := load.AvgWithContext(ctx); err == nil {
			m.gauge("node_load1", l.Load1)
			m.gauge("node_load5", l.Load5)
			m.gauge("node_load15", l.Load15)
		}
	}
	if on["filesystem"] {
		if parts, err := disk.PartitionsWithContext(ctx, false); err == nil {
			for _, p := range parts {
				u, err := disk.UsageWithContext(ctx, p.Mountpoint)
				if err != nil || u.Total == 0 {
					continue
				}
				lb := []string{"device", p.Device, "device_error", "", "fstype", strings.ToLower(p.Fstype), "mountpoint", p.Mountpoint}
				m.gauge("node_filesystem_size_bytes", float64(u.Total), lb...)
				m.gauge("node_filesystem_free_bytes", float64(u.Free), lb...)
				m.gauge("node_filesystem_avail_bytes", float64(u.Free), lb...)
				if u.InodesTotal > 0 {
					m.gauge("node_filesystem_files", float64(u.InodesTotal), lb...)
					m.gauge("node_filesystem_files_free", float64(u.InodesFree), lb...)
				}
				ro := 0.0
				for _, o := range p.Opts {
					if o == "ro" {
						ro = 1
					}
				}
				m.gauge("node_filesystem_readonly", ro, lb...)
			}
		}
	}
	if on["diskstats"] {
		if io, err := disk.IOCountersWithContext(ctx); err == nil {
			for d, c := range io {
				m.counter("node_disk_reads_completed_total", float64(c.ReadCount), "device", d)
				m.counter("node_disk_read_bytes_total", float64(c.ReadBytes), "device", d)
				m.counter("node_disk_read_time_seconds_total", float64(c.ReadTime)/1000, "device", d)
				m.counter("node_disk_writes_completed_total", float64(c.WriteCount), "device", d)
				m.counter("node_disk_written_bytes_total", float64(c.WriteBytes), "device", d)
				m.counter("node_disk_write_time_seconds_total", float64(c.WriteTime)/1000, "device", d)
				m.counter("node_disk_io_time_seconds_total", float64(c.IoTime)/1000, "device", d)
			}
		}
	}
	if on["netdev"] {
		if nics, err := psnet.IOCountersWithContext(ctx, true); err == nil {
			for _, n := range nics {
				m.counter("node_network_receive_bytes_total", float64(n.BytesRecv), "device", n.Name)
				m.counter("node_network_receive_packets_total", float64(n.PacketsRecv), "device", n.Name)
				m.counter("node_network_receive_errs_total", float64(n.Errin), "device", n.Name)
				m.counter("node_network_receive_drop_total", float64(n.Dropin), "device", n.Name)
				m.counter("node_network_transmit_bytes_total", float64(n.BytesSent), "device", n.Name)
				m.counter("node_network_transmit_packets_total", float64(n.PacketsSent), "device", n.Name)
				m.counter("node_network_transmit_errs_total", float64(n.Errout), "device", n.Name)
				m.counter("node_network_transmit_drop_total", float64(n.Dropout), "device", n.Name)
			}
		}
	}
	if on["stat"] {
		if bt, err := host.BootTimeWithContext(ctx); err == nil {
			m.gauge("node_boot_time_seconds", float64(bt))
		}
	}
	if on["uname"] {
		if h, err := host.InfoWithContext(ctx); err == nil {
			m.gauge("node_uname_info", 1, "sysname", h.OS, "release", h.KernelVersion, "version", h.PlatformVersion,
				"machine", h.KernelArch, "nodename", h.Hostname, "domainname", "")
		}
	}
	if on["time"] {
		m.gauge("node_time_seconds", float64(time.Now().UnixNano())/1e9)
	}
	return m
}
