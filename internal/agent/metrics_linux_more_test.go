//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseSystemdUnits(t *testing.T) {
	out := "Id=ssh.service\nType=notify\nActiveState=active\nLoadState=loaded\n\n" +
		"Id=fstrim.timer\nType=\nActiveState=inactive\nLoadState=loaded\n\n" +
		"Id=gone.service\nType=simple\nActiveState=inactive\nLoadState=not-found\n"
	want := []systemdUnit{{"ssh.service", "notify", "active"}, {"fstrim.timer", "", "inactive"}}
	if got := parseSystemdUnits(out); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if v, n, ok := parseSystemdVersion("systemd 257 (257.13-1~deb13u1)\n+PAM +AUDIT"); !ok || v != "257.13-1~deb13u1" || n != 257.13 {
		t.Errorf("version %q %v %v", v, n, ok)
	}
	if v, n, ok := parseSystemdVersion("systemd 252\n"); !ok || v != "252" || n != 252 {
		t.Errorf("bare version %q %v %v", v, n, ok)
	}
}

func TestMoreProcCollectors(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("pressure/cpu", "some avg10=0.00 avg60=0.00 avg300=0.00 total=2500000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n")
	write("pressure/memory", "some avg10=0.00 avg60=0.00 avg300=0.00 total=3000000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n")
	write("vmstat", "nr_free_pages 100\noom_kill 3\npgmajfault 7\npswpin 0\n")
	write("net/snmp", "Tcp: RtoAlgorithm ActiveOpens CurrEstab InErrs\nTcp: 1 42 5 2\nUdp: InDatagrams NoPorts\nUdp: 9 1\n")
	write("net/netstat", "TcpExt: SyncookiesSent ListenDrops TCPLostRetransmit\nTcpExt: 0 4 8\n")
	write("net/snmp6", "Ip6InOctets 1000\nUdp6InErrors 2\nIcmp6InMsgs 3\n")
	write("net/sockstat", "sockets: used 396\nTCP: inuse 30 orphan 0 tw 2 alloc 808 mem 3\n")
	write("net/arp", "IP address HW type Flags HW address Mask Device\n10.0.0.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n10.0.0.2 0x1 0x2 aa:bb:cc:dd:ee:00 * eth0\n")
	write("spl/kstat/zfs/fm", "0 1 0x01 4 1088 1 2\nname type data\nerpt-dropped 4 18\n")
	write("spl/kstat/zfs/tank/state", "ONLINE\n")
	old := procRoot
	procRoot = dir
	defer func() { procRoot = old }()
	m := newMetricSet()
	collectMoreHostMetrics(m, map[string]bool{"pressure": true, "vmstat": true, "netstat": true, "sockstat": true, "arp": true, "zfs": true})
	got := map[string]float64{}
	for _, f := range m.families() {
		for _, s := range f.Samples {
			key := f.Name
			for i, l := range f.Labels {
				key += "," + l + "=" + s.Values[i]
			}
			got[key] = s.Value
		}
	}
	for k, v := range map[string]float64{
		"node_pressure_cpu_waiting_seconds_total":        2.5,
		"node_pressure_memory_waiting_seconds_total":     3,
		"node_pressure_memory_stalled_seconds_total":     1,
		"node_vmstat_oom_kill":                           3,
		"node_vmstat_pgmajfault":                         7,
		"node_vmstat_pswpin":                             0,
		"node_netstat_Tcp_ActiveOpens":                   42,
		"node_netstat_Tcp_CurrEstab":                     5,
		"node_netstat_Tcp_InErrs":                        2,
		"node_netstat_Udp_NoPorts":                       1,
		"node_netstat_TcpExt_ListenDrops":                4,
		"node_netstat_TcpExt_SyncookiesSent":             0,
		"node_netstat_Ip6_InOctets":                      1000,
		"node_netstat_Udp6_InErrors":                     2,
		"node_netstat_Icmp6_InMsgs":                      3,
		"node_sockstat_sockets_used":                     396,
		"node_sockstat_TCP_tw":                           2,
		"node_sockstat_TCP_mem_bytes":                    3 * float64(os.Getpagesize()),
		"node_arp_entries,device=eth0":                   2,
		"node_zfs_fm_erpt_dropped":                       18,
		"node_zfs_zpool_state,state=online,zpool=tank":   1,
		"node_zfs_zpool_state,state=degraded,zpool=tank": 0,
	} {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %v (present %v), want %v", k, g, ok, v)
		}
	}
	for _, absent := range []string{"node_pressure_cpu_stalled_seconds_total", "node_vmstat_nr_free_pages", "node_netstat_TcpExt_TCPLostRetransmit", "node_netstat_Tcp_RtoAlgorithm"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s collected; node_exporter's filters leave it out", absent)
		}
	}
}
