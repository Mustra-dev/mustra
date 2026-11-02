//go:build linux

package agent

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// procRoot and sysRoot are where the collectors read; tests point them at a
// fixture tree.
var (
	procRoot = "/proc"
	sysRoot  = "/sys"
)

// userHZ is the kernel's clock tick for /proc/stat times. It is 100 on
// every Linux architecture mustra builds for.
const userHZ = 100

func collectHostMetrics(ctx context.Context, on map[string]bool) *metricSet {
	m := newMetricSet()
	if on["cpu"] || on["stat"] {
		readProcStat(m, on)
	}
	if on["memory"] {
		readMeminfo(m)
	}
	if on["load"] {
		readLoadavg(m)
	}
	if on["filesystem"] {
		readFilesystems(ctx, m)
	}
	if on["diskstats"] {
		readDiskstats(m)
	}
	if on["netdev"] {
		readNetdev(m)
	}
	if on["uname"] {
		var u unix.Utsname
		if unix.Uname(&u) == nil {
			s := func(b []byte) string { return strings.TrimRight(string(b), "\x00") }
			m.gauge("node_uname_info", 1, "sysname", s(u.Sysname[:]), "release", s(u.Release[:]), "version", s(u.Version[:]),
				"machine", s(u.Machine[:]), "nodename", s(u.Nodename[:]), "domainname", s(u.Domainname[:]))
		}
	}
	if on["time"] {
		m.gauge("node_time_seconds", float64(time.Now().UnixNano())/1e9)
	}
	if on["hwmon"] {
		readHwmon(m)
	}
	if on["filefd"] {
		if f := fields(procRoot + "/sys/fs/file-nr"); len(f) >= 3 {
			m.gauge("node_filefd_allocated", atof(f[0]))
			m.gauge("node_filefd_maximum", atof(f[2]))
		}
	}
	if on["health"] {
		addHealthMetrics(m)
	}
	collectMoreHostMetrics(m, on)
	return m
}

func atof(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }

func fields(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

var cpuModes = []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

func readProcStat(m *metricSet, on map[string]bool) {
	f, err := os.Open(procRoot + "/stat")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 2 {
			continue
		}
		switch {
		case strings.HasPrefix(p[0], "cpu") && p[0] != "cpu" && on["cpu"]:
			cpu := strings.TrimPrefix(p[0], "cpu")
			for i, mode := range cpuModes {
				if i+1 < len(p) {
					m.counter("node_cpu_seconds_total", atof(p[i+1])/userHZ, "cpu", cpu, "mode", mode)
				}
			}
			// guest time is already counted in user and nice.
			if len(p) > 10 {
				m.counter("node_cpu_guest_seconds_total", atof(p[9])/userHZ, "cpu", cpu, "mode", "user")
				m.counter("node_cpu_guest_seconds_total", atof(p[10])/userHZ, "cpu", cpu, "mode", "nice")
			}
		case !on["stat"]:
		case p[0] == "intr":
			m.counter("node_intr_total", atof(p[1]))
		case p[0] == "ctxt":
			m.counter("node_context_switches_total", atof(p[1]))
		case p[0] == "btime":
			m.gauge("node_boot_time_seconds", atof(p[1]))
		case p[0] == "processes":
			m.counter("node_forks_total", atof(p[1]))
		case p[0] == "procs_running":
			m.gauge("node_procs_running", atof(p[1]))
		case p[0] == "procs_blocked":
			m.gauge("node_procs_blocked", atof(p[1]))
		}
	}
}

func readMeminfo(m *metricSet) {
	f, err := os.Open(procRoot + "/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		p := strings.Fields(rest)
		if len(p) == 0 {
			continue
		}
		v := atof(p[0])
		hasUnit := len(p) > 1 && p[1] == "kB"
		if hasUnit {
			v *= 1024
		}
		m.gauge(meminfoMetricName(strings.TrimSpace(key), hasUnit), v)
	}
}

func readLoadavg(m *metricSet) {
	if f := fields(procRoot + "/loadavg"); len(f) >= 3 {
		m.gauge("node_load1", atof(f[0]))
		m.gauge("node_load5", atof(f[1]))
		m.gauge("node_load15", atof(f[2]))
	}
}

// Filesystems node_exporter leaves out by default: kernel and container
// plumbing, not storage anyone runs out of.
var (
	fsTypesIgnored  = regexp.MustCompile(`^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|erofs|sysfs|tracefs)$`)
	mountsIgnored   = regexp.MustCompile(`^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)`)
	diskDevsIgnored = regexp.MustCompile(`^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$`)
)

func readFilesystems(ctx context.Context, m *metricSet) {
	f, err := os.Open(procRoot + "/1/mounts")
	if err != nil {
		if f, err = os.Open(procRoot + "/self/mounts"); err != nil {
			return
		}
	}
	defer f.Close()
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 4 {
			continue
		}
		dev, mnt, fstype, opts := p[0], unescapeMount(p[1]), p[2], p[3]
		if fsTypesIgnored.MatchString(fstype) || mountsIgnored.MatchString(mnt) || seen[mnt] {
			continue
		}
		seen[mnt] = true
		st, ok := statfsTimeout(ctx, mnt, 2*time.Second)
		// node_exporter 1.x carries device_error on every filesystem series
		// (empty when the statfs worked); without it a rule matching on
		// labels would see a different series.
		lb := []string{"device", dev, "device_error", "", "fstype", fstype, "mountpoint", mnt}
		if !ok {
			// An NFS mount that does not answer is reported, not waited on.
			lb[3] = "statfs timed out"
			m.gauge("node_filesystem_device_error", 1, lb...)
			continue
		}
		m.gauge("node_filesystem_device_error", 0, lb...)
		bs := float64(st.Bsize)
		if st.Frsize > 0 {
			bs = float64(st.Frsize)
		}
		m.gauge("node_filesystem_size_bytes", float64(st.Blocks)*bs, lb...)
		m.gauge("node_filesystem_free_bytes", float64(st.Bfree)*bs, lb...)
		m.gauge("node_filesystem_avail_bytes", float64(st.Bavail)*bs, lb...)
		m.gauge("node_filesystem_files", float64(st.Files), lb...)
		m.gauge("node_filesystem_files_free", float64(st.Ffree), lb...)
		ro := 0.0
		for _, o := range strings.Split(opts, ",") {
			if o == "ro" {
				ro = 1
			}
		}
		m.gauge("node_filesystem_readonly", ro, lb...)
	}
}

// unescapeMount undoes /proc/mounts' octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func statfsTimeout(ctx context.Context, path string, d time.Duration) (unix.Statfs_t, bool) {
	type res struct {
		st unix.Statfs_t
		ok bool
	}
	ch := make(chan res, 1)
	go func() {
		var st unix.Statfs_t
		err := unix.Statfs(path, &st)
		ch <- res{st, err == nil}
	}()
	select {
	case r := <-ch:
		return r.st, r.ok
	case <-time.After(d):
	case <-ctx.Done():
	}
	return unix.Statfs_t{}, false
}

func readDiskstats(m *metricSet) {
	f, err := os.Open(procRoot + "/diskstats")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 14 || diskDevsIgnored.MatchString(p[2]) {
			continue
		}
		d := p[2]
		v := func(i int) float64 { return atof(p[i]) }
		m.counter("node_disk_reads_completed_total", v(3), "device", d)
		m.counter("node_disk_reads_merged_total", v(4), "device", d)
		m.counter("node_disk_read_bytes_total", v(5)*512, "device", d)
		m.counter("node_disk_read_time_seconds_total", v(6)/1000, "device", d)
		m.counter("node_disk_writes_completed_total", v(7), "device", d)
		m.counter("node_disk_writes_merged_total", v(8), "device", d)
		m.counter("node_disk_written_bytes_total", v(9)*512, "device", d)
		m.counter("node_disk_write_time_seconds_total", v(10)/1000, "device", d)
		m.gauge("node_disk_io_now", v(11), "device", d)
		m.counter("node_disk_io_time_seconds_total", v(12)/1000, "device", d)
		m.counter("node_disk_io_time_weighted_seconds_total", v(13)/1000, "device", d)
	}
}

var (
	netdevRecv  = []string{"bytes", "packets", "errs", "drop", "fifo", "frame", "compressed", "multicast"}
	netdevTrans = []string{"bytes", "packets", "errs", "drop", "fifo", "colls", "carrier", "compressed"}
)

func readNetdev(m *metricSet) {
	f, err := os.Open(procRoot + "/net/dev")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		dev := strings.TrimSpace(name)
		p := strings.Fields(rest)
		// A container host's veth pairs come and go with every container;
		// as series they are churn, and the container's own traffic is
		// reported from inside it.
		if len(p) < 16 || strings.HasPrefix(dev, "veth") {
			continue
		}
		for i, n := range netdevRecv {
			m.counter("node_network_receive_"+n+"_total", atof(p[i]), "device", dev)
		}
		for i, n := range netdevTrans {
			m.counter("node_network_transmit_"+n+"_total", atof(p[8+i]), "device", dev)
		}
		up := 0.0
		if b, err := os.ReadFile(sysRoot + "/class/net/" + dev + "/operstate"); err == nil && strings.TrimSpace(string(b)) == "up" {
			up = 1
		}
		m.gauge("node_network_up", up, "device", dev)
	}
}

func readHwmon(m *metricSet) {
	chips, _ := filepath.Glob(sysRoot + "/class/hwmon/hwmon*")
	for _, c := range chips {
		name := strings.TrimSpace(readFileString(filepath.Join(c, "name")))
		if name == "" {
			name = filepath.Base(c)
		}
		chip := name
		if dev, err := filepath.EvalSymlinks(filepath.Join(c, "device")); err == nil {
			chip = strings.NewReplacer(":", "_", ".", "_", "-", "_").Replace(filepath.Base(filepath.Dir(dev)) + "_" + filepath.Base(dev))
		}
		temps, _ := filepath.Glob(filepath.Join(c, "temp*_input"))
		for _, t := range temps {
			sensor := strings.TrimSuffix(filepath.Base(t), "_input")
			raw := strings.TrimSpace(readFileString(t))
			if raw == "" {
				continue
			}
			m.gauge("node_hwmon_temp_celsius", atof(raw)/1000, "chip", chip, "sensor", sensor)
			for suffix, metric := range map[string]string{"crit": "node_hwmon_temp_crit_celsius", "max": "node_hwmon_temp_max_celsius",
				"min": "node_hwmon_temp_min_celsius", "crit_alarm": "node_hwmon_temp_crit_alarm_celsius", "alarm": "node_hwmon_temp_alarm"} {
				if v := strings.TrimSpace(readFileString(strings.TrimSuffix(t, "_input") + "_" + suffix)); v != "" {
					val := atof(v)
					if !strings.HasSuffix(suffix, "alarm") {
						val /= 1000
					}
					m.gauge(metric, val, "chip", chip, "sensor", sensor)
				}
			}
			if l := strings.TrimSpace(readFileString(strings.TrimSuffix(t, "_input") + "_label")); l != "" {
				m.gauge("node_hwmon_sensor_label", 1, "chip", chip, "sensor", sensor, "label", l)
			}
		}
		if name != "" {
			m.gauge("node_hwmon_chip_names", 1, "chip", chip, "chip_name", name)
		}
	}
}

func readFileString(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}
