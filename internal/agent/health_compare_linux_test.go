//go:build linux

package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestHealthMatchesTextfiles compares the health collector against the
// textfile collectors' output on a host that runs them. Opt-in:
// MUSTRA_HEALTH_PROM_DIR=/var/lib/prometheus/node-exporter, as root.
func TestHealthMatchesTextfiles(t *testing.T) {
	dir := os.Getenv("MUSTRA_HEALTH_PROM_DIR")
	if dir == "" {
		t.Skip("set MUSTRA_HEALTH_PROM_DIR to a node_exporter textfile directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	got := map[string]string{}
	for _, s := range collectHealth(ctx) {
		got[seriesKey(s.name, s.labels)] = fmt.Sprint(s.value)
	}
	want := map[string]string{}
	for _, f := range []string{"apt.prom", "health_metrics.prom"} {
		b, err := os.ReadFile(dir + "/" + f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" || line[0] == '#' {
				continue
			}
			i := strings.LastIndexByte(line, ' ')
			want[line[:i]] = line[i+1:]
		}
	}
	keys := map[string]bool{}
	for k := range got {
		keys[k] = true
	}
	for k := range want {
		keys[k] = true
	}
	var ks []string
	for k := range keys {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		t.Logf("%-90s mustra=%-14s textfile=%s", k, got[k], want[k])
	}
}

func seriesKey(name string, labels []string) string {
	if len(labels) == 0 {
		return name
	}
	var parts []string
	for i := 0; i+1 < len(labels); i += 2 {
		parts = append(parts, labels[i]+`="`+labels[i+1]+`"`)
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}
