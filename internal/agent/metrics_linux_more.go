//go:build linux

package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// More node_exporter collectors, with its names, labels and default
// filters: pressure stall information, vmstat (OOM kills, paging),
// netstat and sockstat, timex (NTP sync), conntrack, ZFS, CPU frequency,
// OS release, thermal zones and cooling devices, entropy and ARP entries.

func collectMoreHostMetrics(m *metricSet, on map[string]bool) {
	if on["pressure"] {
		readPressure(m)
	}
	if on["vmstat"] {
		readVmstat(m)
	}
	if on["netstat"] {
		readNetstat(m)
	}
	if on["sockstat"] {
		readSockstat(m)
	}
	if on["timex"] {
		readTimex(m)
	}
	if on["conntrack"] {
		if v := strings.TrimSpace(readFileString(procRoot + "/sys/net/netfilter/nf_conntrack_count")); v != "" {
			m.gauge("node_nf_conntrack_entries", atof(v))
			m.gauge("node_nf_conntrack_entries_limit", atof(strings.TrimSpace(readFileString(procRoot+"/sys/net/netfilter/nf_conntrack_max"))))
		}
	}
	if on["zfs"] {
		readZFS(m)
	}
	if on["cpufreq"] {
		readCPUFreq(m)
	}
	if on["os"] {
		readOSRelease(m)
	}
	if on["thermal"] {
		readThermal(m)
	}
	if on["entropy"] {
		if v := strings.TrimSpace(readFileString(procRoot + "/sys/kernel/random/entropy_avail")); v != "" {
			m.gauge("node_entropy_available_bits", atof(v))
			m.gauge("node_entropy_pool_size_bits", atof(strings.TrimSpace(readFileString(procRoot+"/sys/kernel/random/poolsize"))))
		}
	}
	if on["arp"] {
		readARP(m)
	}
	if on["systemd"] {
		addSystemdMetrics(m)
	}
	if on["netclass"] {
		readNetClass(m)
	}
}

// readNetClass is node_exporter's netclass collector: each interface's
// link state from /sys/class/net.
func readNetClass(m *metricSet) {
	devs, _ := filepath.Glob(sysRoot + "/class/net/*")
	for _, d := range devs {
		dev := filepath.Base(d)
		num := func(file string) (float64, bool) {
			v := strings.TrimSpace(readFileString(filepath.Join(d, file)))
			if v == "" {
				return 0, false
			}
			if strings.HasPrefix(v, "0x") {
				n, err := strconv.ParseUint(v[2:], 16, 64)
				return float64(n), err == nil
			}
			f, err := strconv.ParseFloat(v, 64)
			return f, err == nil
		}
		for file, metric := range map[string]string{
			"carrier": "node_network_carrier", "dormant": "node_network_dormant", "flags": "node_network_flags",
			"ifindex": "node_network_iface_id", "iflink": "node_network_iface_link", "link_mode": "node_network_iface_link_mode",
			"mtu": "node_network_mtu_bytes", "type": "node_network_protocol_type", "tx_queue_len": "node_network_transmit_queue_length",
			"addr_assign_type": "node_network_address_assign_type", "name_assign_type": "node_network_name_assign_type",
			"dev_id": "node_network_device_id", "netdev_group": "node_network_net_dev_group",
		} {
			if v, ok := num(file); ok {
				m.gauge(metric, v, "device", dev)
			}
		}
		for file, metric := range map[string]string{
			"carrier_changes": "node_network_carrier_changes_total", "carrier_up_count": "node_network_carrier_up_changes_total",
			"carrier_down_count": "node_network_carrier_down_changes_total",
		} {
			if v, ok := num(file); ok {
				m.counter(metric, v, "device", dev)
			}
		}
		// speed is Mbit/s, and -1 when unknown, which node_exporter omits.
		if v, ok := num("speed"); ok && v >= 0 {
			m.gauge("node_network_speed_bytes", v*1000*1000/8, "device", dev)
		}
	}
}

// readPressure: the "some" line is time any task waited, "full" time all
// did; node_exporter reports cpu some, and memory and io both.
func readPressure(m *metricSet) {
	for _, res := range []string{"cpu", "memory", "io"} {
		b, err := os.ReadFile(procRoot + "/pressure/" + res)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 5 || !strings.HasPrefix(f[4], "total=") {
				continue
			}
			secs := atof(strings.TrimPrefix(f[4], "total=")) / 1e6
			switch {
			case f[0] == "some":
				m.counter("node_pressure_"+res+"_waiting_seconds_total", secs)
			case f[0] == "full" && res != "cpu":
				m.counter("node_pressure_"+res+"_stalled_seconds_total", secs)
			}
		}
	}
}

var vmstatFields = regexp.MustCompile(`^(oom_kill|pgpg|pswp|pg.*fault).*`)

func readVmstat(m *metricSet) {
	b, err := os.ReadFile(procRoot + "/vmstat")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && vmstatFields.MatchString(f[0]) {
			m.gauge("node_vmstat_"+f[0], atof(f[1]))
		}
	}
}

var netstatFields = regexp.MustCompile(`^(.*_(InErrors|InErrs)|Ip_Forwarding|Ip(6|Ext)_(InOctets|OutOctets)|Icmp6?_(InMsgs|OutMsgs)|TcpExt_(Listen.*|Syncookies.*|TCPSynRetrans|TCPTimeouts|TCPOFOQueue|TCPRcvQDrop)|Tcp_(ActiveOpens|InSegs|OutSegs|OutRsts|PassiveOpens|RetransSegs|CurrEstab)|Udp6?_(InDatagrams|OutDatagrams|NoPorts|RcvbufErrors|SndbufErrors))$`)

func readNetstat(m *metricSet) {
	vals := map[string]string{}
	for _, f := range []string{"/net/netstat", "/net/snmp"} {
		parseNetstatPairs(readFileString(procRoot+f), vals)
	}
	// snmp6 is one "Ip6InReceives 123" per line; the protocol is the
	// leading run up to the first upper-case letter after a digit.
	for _, line := range strings.Split(readFileString(procRoot+"/net/snmp6"), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		for _, p := range []string{"UdpLite6", "Icmp6", "Udp6", "Ip6"} {
			if strings.HasPrefix(f[0], p) {
				vals[p+"_"+strings.TrimPrefix(f[0], p)] = f[1]
				break
			}
		}
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if netstatFields.MatchString(k) {
			m.gauge("node_netstat_"+k, atof(vals[k]))
		}
	}
}

// parseNetstatPairs reads /proc/net/{netstat,snmp}: a header line of
// names and a line of values, both prefixed "Proto:".
func parseNetstatPairs(s string, into map[string]string) {
	lines := strings.Split(s, "\n")
	for i := 0; i+1 < len(lines); i += 2 {
		names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		if len(names) != len(values) || len(names) < 2 || names[0] != values[0] {
			continue
		}
		proto := strings.TrimSuffix(names[0], ":")
		for j := 1; j < len(names); j++ {
			into[proto+"_"+names[j]] = values[j]
		}
	}
}

func readSockstat(m *metricSet) {
	page := float64(os.Getpagesize())
	for _, f := range []string{"/net/sockstat", "/net/sockstat6"} {
		for _, line := range strings.Split(readFileString(procRoot+f), "\n") {
			proto, rest, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			kv := strings.Fields(rest)
			for i := 0; i+1 < len(kv); i += 2 {
				if proto == "sockets" {
					m.gauge("node_sockstat_sockets_"+kv[i], atof(kv[i+1]))
					continue
				}
				m.gauge("node_sockstat_"+proto+"_"+kv[i], atof(kv[i+1]))
				if kv[i] == "mem" {
					m.gauge("node_sockstat_"+proto+"_mem_bytes", atof(kv[i+1])*page)
				}
			}
		}
	}
}

// readTimex is node_exporter's timex collector: the kernel clock's NTP
// discipline state from adjtimex.
func readTimex(m *metricSet) {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return
	}
	div := 1e6 // microseconds, unless STA_NANO
	if tx.Status&unix.STA_NANO != 0 {
		div = 1e9
	}
	sync := 1.0
	if state == unix.TIME_ERROR {
		sync = 0
	}
	m.gauge("node_timex_sync_status", sync)
	m.gauge("node_timex_offset_seconds", float64(tx.Offset)/div)
	m.gauge("node_timex_frequency_adjustment_ratio", 1+float64(tx.Freq)/65536/1e6)
	m.gauge("node_timex_maxerror_seconds", float64(tx.Maxerror)/1e6)
	m.gauge("node_timex_estimated_error_seconds", float64(tx.Esterror)/1e6)
	m.gauge("node_timex_status", float64(tx.Status))
	m.gauge("node_timex_loop_time_constant", float64(tx.Constant))
	m.gauge("node_timex_tick_seconds", float64(tx.Tick)/1e6)
	m.gauge("node_timex_pps_frequency_hertz", float64(tx.Ppsfreq)/65536/1e6)
	m.gauge("node_timex_pps_jitter_seconds", float64(tx.Jitter)/div)
	m.gauge("node_timex_pps_shift_seconds", float64(int64(1)<<uint(tx.Shift)))
	m.gauge("node_timex_pps_stability_hertz", float64(tx.Stabil)/65536/1e6)
	m.counter("node_timex_pps_jitter_total", float64(tx.Jitcnt))
	m.counter("node_timex_pps_calibration_total", float64(tx.Calcnt))
	m.counter("node_timex_pps_error_total", float64(tx.Errcnt))
	m.counter("node_timex_pps_stability_exceeded_total", float64(tx.Stbcnt))
	m.gauge("node_timex_tai_offset_seconds", float64(tx.Tai))
}

// zfsKstats are the kstat files node_exporter reads, by the subsystem
// name its metrics use.
var zfsKstats = map[string]string{
	"abdstats": "abd", "arcstats": "arc", "dbufstats": "dbuf", "dmu_tx": "dmu_tx", "dnodestats": "dnode",
	"fm": "fm", "vdev_mirror_stats": "vdev_mirror", "zfetchstats": "zfetch", "zil": "zil",
}

var zpoolStates = []string{"online", "degraded", "faulted", "offline", "removed", "unavail", "suspended"}

func readZFS(m *metricSet) {
	dir := procRoot + "/spl/kstat/zfs"
	for file, sub := range zfsKstats {
		f, err := os.Open(filepath.Join(dir, file))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		started := false
		for sc.Scan() {
			p := strings.Fields(sc.Text())
			if !started {
				started = len(p) == 3 && p[0] == "name" && p[1] == "type" && p[2] == "data"
				continue
			}
			if len(p) != 3 {
				continue
			}
			v, err := strconv.ParseFloat(p[2], 64)
			if err != nil {
				continue
			}
			m.gauge("node_zfs_"+sub+"_"+strings.NewReplacer("-", "_", ".", "_").Replace(p[0]), v)
		}
		f.Close()
	}
	states, _ := filepath.Glob(dir + "/*/state")
	for _, s := range states {
		pool := filepath.Base(filepath.Dir(s))
		cur := strings.ToLower(strings.TrimSpace(readFileString(s)))
		for _, st := range zpoolStates {
			v := 0.0
			if st == cur {
				v = 1
			}
			m.gauge("node_zfs_zpool_state", v, "state", st, "zpool", pool)
		}
	}
}

func readCPUFreq(m *metricSet) {
	dirs, _ := filepath.Glob(sysRoot + "/devices/system/cpu/cpu[0-9]*/cpufreq")
	for _, d := range dirs {
		cpu := strings.TrimPrefix(filepath.Base(filepath.Dir(d)), "cpu")
		khz := func(name string) (float64, bool) {
			v := strings.TrimSpace(readFileString(filepath.Join(d, name)))
			if v == "" {
				return 0, false
			}
			return atof(v) * 1000, true
		}
		for file, metric := range map[string]string{
			"cpuinfo_cur_freq": "node_cpu_frequency_hertz", "cpuinfo_max_freq": "node_cpu_frequency_max_hertz",
			"cpuinfo_min_freq": "node_cpu_frequency_min_hertz", "scaling_cur_freq": "node_cpu_scaling_frequency_hertz",
			"scaling_max_freq": "node_cpu_scaling_frequency_max_hertz", "scaling_min_freq": "node_cpu_scaling_frequency_min_hertz",
		} {
			if v, ok := khz(file); ok {
				m.gauge(metric, v, "cpu", cpu)
			}
		}
		cur := strings.TrimSpace(readFileString(filepath.Join(d, "scaling_governor")))
		for _, g := range strings.Fields(readFileString(filepath.Join(d, "scaling_available_governors"))) {
			v := 0.0
			if g == cur {
				v = 1
			}
			m.gauge("node_cpu_scaling_governor", v, "cpu", cpu, "governor", g)
		}
	}
}

var osVersionNumber = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?`)

func readOSRelease(m *metricSet) {
	raw := readFileString("/etc/os-release")
	if raw == "" {
		raw = readFileString("/usr/lib/os-release")
	}
	if raw == "" {
		return
	}
	kv := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if u, err := strconv.Unquote(v); err == nil {
			v = u
		} else {
			v = strings.Trim(v, `"'`)
		}
		kv[k] = v
	}
	m.gauge("node_os_info", 1, "build_id", kv["BUILD_ID"], "id", kv["ID"], "id_like", kv["ID_LIKE"],
		"image_id", kv["IMAGE_ID"], "image_version", kv["IMAGE_VERSION"], "name", kv["NAME"],
		"pretty_name", kv["PRETTY_NAME"], "variant", kv["VARIANT"], "variant_id", kv["VARIANT_ID"],
		"version", kv["VERSION"], "version_codename", kv["VERSION_CODENAME"], "version_id", kv["VERSION_ID"])
	if v := osVersionNumber.FindString(kv["VERSION_ID"]); v != "" {
		m.gauge("node_os_version", atof(v), "id", kv["ID"], "id_like", kv["ID_LIKE"], "name", kv["NAME"])
	}
}

func readThermal(m *metricSet) {
	zones, _ := filepath.Glob(sysRoot + "/class/thermal/thermal_zone*")
	for _, z := range zones {
		t := strings.TrimSpace(readFileString(filepath.Join(z, "temp")))
		if t == "" {
			continue
		}
		m.gauge("node_thermal_zone_temp", atof(t)/1000,
			"type", strings.TrimSpace(readFileString(filepath.Join(z, "type"))),
			"zone", strings.TrimPrefix(filepath.Base(z), "thermal_zone"))
	}
	devs, _ := filepath.Glob(sysRoot + "/class/thermal/cooling_device*")
	for _, d := range devs {
		cur := strings.TrimSpace(readFileString(filepath.Join(d, "cur_state")))
		if cur == "" {
			continue
		}
		name := strings.TrimPrefix(filepath.Base(d), "cooling_device")
		typ := strings.TrimSpace(readFileString(filepath.Join(d, "type")))
		m.gauge("node_cooling_device_cur_state", atof(cur), "name", name, "type", typ)
		if mx := strings.TrimSpace(readFileString(filepath.Join(d, "max_state"))); mx != "" {
			m.gauge("node_cooling_device_max_state", atof(mx), "name", name, "type", typ)
		}
	}
}

func readARP(m *metricSet) {
	lines := strings.Split(readFileString(procRoot+"/net/arp"), "\n")
	counts := map[string]int{}
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.Fields(line)
		if len(f) >= 6 {
			counts[f[5]]++
		}
	}
	devs := make([]string, 0, len(counts))
	for d := range counts {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	for _, d := range devs {
		m.gauge("node_arp_entries", float64(counts[d]), "device", d)
	}
}
