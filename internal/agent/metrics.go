package agent

import (
	"sort"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Host metrics for the operator's monitoring stack (telemetry.go sends
// them). The names, units and labels are node_exporter's, so the dashboards
// and alert rules people already have for node_exporter work unchanged:
// node_cpu_seconds_total, node_memory_MemAvailable_bytes,
// node_filesystem_avail_bytes and so on. The server adds instance and
// instance_name.

// metricCollectors are the families an agent can collect, by the name a
// telemetry config uses to switch one off.
var metricCollectors = []string{"cpu", "memory", "load", "filesystem", "diskstats", "netdev", "stat", "uname", "time", "hwmon", "filefd", "health",
	"pressure", "vmstat", "netstat", "sockstat", "timex", "conntrack", "zfs", "cpufreq", "os", "thermal", "entropy", "arp", "systemd", "netclass"}

// metricSet accumulates families for one batch.
type metricSet struct {
	fams  map[string]*proto.MetricFamily
	order []string
}

func newMetricSet() *metricSet { return &metricSet{fams: map[string]*proto.MetricFamily{}} }

// add records one sample. labels alternate key, value; a family's label
// keys are fixed by its first sample.
func (m *metricSet) add(name, typ string, value float64, labels ...string) {
	f := m.fams[name]
	if f == nil {
		f = &proto.MetricFamily{Name: name, Type: typ}
		for i := 0; i+1 < len(labels); i += 2 {
			f.Labels = append(f.Labels, labels[i])
		}
		m.fams[name] = f
		m.order = append(m.order, name)
	}
	var values []string
	if len(f.Labels) > 0 {
		values = make([]string, len(f.Labels))
		for i := 0; i+1 < len(labels); i += 2 {
			for j, k := range f.Labels {
				if k == labels[i] {
					values[j] = labels[i+1]
				}
			}
		}
	}
	f.Samples = append(f.Samples, proto.MetricSample{Values: values, Value: value})
}

func (m *metricSet) gauge(name string, v float64, labels ...string) {
	m.add(name, "gauge", v, labels...)
}
func (m *metricSet) counter(name string, v float64, labels ...string) {
	m.add(name, "counter", v, labels...)
}

func (m *metricSet) families() []proto.MetricFamily {
	sort.Strings(m.order)
	out := make([]proto.MetricFamily, 0, len(m.order))
	for _, n := range m.order {
		out = append(out, *m.fams[n])
	}
	return out
}

// enabledCollectors turns a config's list into a set; empty means all.
func enabledCollectors(list []string) map[string]bool {
	on := map[string]bool{}
	if len(list) == 0 {
		for _, c := range metricCollectors {
			on[c] = true
		}
		return on
	}
	for _, c := range list {
		on[strings.ToLower(strings.TrimSpace(c))] = true
	}
	return on
}

// meminfoMetricName is node_exporter's name for a /proc/meminfo field:
// "Active(anon)" becomes node_memory_Active_anon_bytes, and a field with
// no unit (HugePages_Total) drops the _bytes.
func meminfoMetricName(field string, hasUnit bool) string {
	f := strings.NewReplacer("(", "_", ")", "").Replace(field)
	if hasUnit {
		return "node_memory_" + f + "_bytes"
	}
	return "node_memory_" + f
}
