//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The node_exporter names, units and labels, from a fixed /proc and /sys.
func TestLinuxHostMetricsMatchNodeExporter(t *testing.T) {
	proc, sys := t.TempDir(), t.TempDir()
	writeFixture(t, proc, map[string]string{
		"stat":           "cpu  100 2 30 4000 5 0 1 0 0 0\ncpu0 100 2 30 4000 5 0 1 0 7 0\nintr 12345 0 0\nctxt 999\nbtime 1793000000\nprocesses 4242\nprocs_running 3\nprocs_blocked 1\n",
		"meminfo":        "MemTotal:       16384 kB\nMemAvailable:    8192 kB\nActive(anon):     100 kB\nHugePages_Total:       0\n",
		"loadavg":        "0.50 0.40 0.30 2/300 12345\n",
		"diskstats":      "   8       0 sda 100 5 2000 50 200 6 4000 70 0 120 150\n   8       1 sda1 1 0 8 1 1 0 8 1 0 1 1\n   7       0 loop0 1 0 2 0 0 0 0 0 0 0 0\n",
		"net/dev":        "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\nveth1a2b: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n",
		"1/mounts":       "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\noverlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n",
		"sys/fs/file-nr": "1024\t0\t9223372036854775807\n",
	})
	writeFixture(t, sys, map[string]string{
		"class/net/eth0/operstate":       "up\n",
		"class/hwmon/hwmon0/name":        "coretemp\n",
		"class/hwmon/hwmon0/temp1_input": "45000\n",
		"class/hwmon/hwmon0/temp1_label": "Package id 0\n",
	})
	oldProc, oldSys := procRoot, sysRoot
	procRoot, sysRoot = proc, sys
	defer func() { procRoot, sysRoot = oldProc, oldSys }()

	set := collectHostMetrics(context.Background(), enabledCollectors(nil))
	got := map[string]float64{}
	for _, f := range set.families() {
		for _, s := range f.Samples {
			key := f.Name
			for i, l := range f.Labels {
				key += "|" + l + "=" + s.Values[i]
			}
			got[key] = s.Value
		}
	}
	for key, want := range map[string]float64{
		"node_cpu_seconds_total|cpu=0|mode=user":             1,
		"node_cpu_seconds_total|cpu=0|mode=idle":             40,
		"node_cpu_seconds_total|cpu=0|mode=softirq":          0.01,
		"node_cpu_guest_seconds_total|cpu=0|mode=user":       0.07,
		"node_context_switches_total":                        999,
		"node_boot_time_seconds":                             1793000000,
		"node_forks_total":                                   4242,
		"node_procs_running":                                 3,
		"node_intr_total":                                    12345,
		"node_memory_MemTotal_bytes":                         16384 * 1024,
		"node_memory_MemAvailable_bytes":                     8192 * 1024,
		"node_memory_Active_anon_bytes":                      100 * 1024,
		"node_memory_HugePages_Total":                        0,
		"node_load1":                                         0.5,
		"node_load15":                                        0.3,
		"node_disk_read_bytes_total|device=sda":              2000 * 512,
		"node_disk_io_time_seconds_total|device=sda":         0.12,
		"node_network_receive_bytes_total|device=eth0":       1000,
		"node_network_transmit_packets_total|device=eth0":    20,
		"node_network_up|device=eth0":                        1,
		"node_filefd_allocated":                              1024,
		"node_hwmon_temp_celsius|chip=coretemp|sensor=temp1": 45,
	} {
		if v, ok := got[key]; !ok || abs(v-want) > 1e-9 {
			t.Errorf("%s = %v (present %v), want %v", key, v, ok, want)
		}
	}
	for key := range got {
		for _, bad := range []string{"device=sda1", "device=loop0", "device=veth1a2b", "mountpoint=/proc", "mountpoint=/var/lib/docker"} {
			if strings.Contains(key, bad) {
				t.Errorf("%s should have been left out", key)
			}
		}
	}
	if _, ok := got["node_filesystem_size_bytes|device=/dev/sda1|device_error=|fstype=ext4|mountpoint=/"]; !ok {
		t.Errorf("root filesystem missing; have %d series", len(got))
	}
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// A collector switched off is not collected.
func TestEnabledCollectors(t *testing.T) {
	on := enabledCollectors([]string{"cpu", " Memory "})
	if !on["cpu"] || !on["memory"] || on["netdev"] {
		t.Fatalf("on = %v", on)
	}
	if all := enabledCollectors(nil); len(all) != len(metricCollectors) {
		t.Fatalf("empty list should mean all, got %v", all)
	}
}
