//go:build linux

package agent

import (
	"bufio"
	"context"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCompareWithNodeExporter checks every series this agent produces
// against a node_exporter running on the same machine: same name, same
// labels, close value. Opt-in: MUSTRA_NODE_EXPORTER=http://127.0.0.1:9100.
func TestCompareWithNodeExporter(t *testing.T) {
	url := os.Getenv("MUSTRA_NODE_EXPORTER")
	if url == "" {
		t.Skip("set MUSTRA_NODE_EXPORTER to a node_exporter on this machine")
	}
	resp, err := http.Get(url + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	theirs := map[string]float64{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		i := strings.LastIndex(line, " ")
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		theirs[canonicalSeries(line[:i])] = v
	}
	// The background collectors would carry nothing on a first batch.
	for _, b := range []*backgroundCollector{systemdCollector, healthCollector} {
		b.samples, b.at = b.collect(context.Background()), time.Now()
	}
	set := collectHostMetrics(context.Background(), enabledCollectors(nil))
	var missing, differ []string
	compared := 0
	for _, f := range set.families() {
		for _, s := range f.Samples {
			var lb []string
			for i, l := range f.Labels {
				lb = append(lb, l+`="`+s.Values[i]+`"`)
			}
			key := f.Name
			if len(lb) > 0 {
				sort.Strings(lb)
				key += "{" + strings.Join(lb, ",") + "}"
			}
			// I/Os in flight at this instant: two reads a moment apart differ.
			if f.Name == "node_disk_io_now" {
				continue
			}
			v, ok := theirs[key]
			if !ok {
				missing = append(missing, key)
				continue
			}
			compared++
			// Counters and moving gauges are read a moment apart; 2% or a
			// small absolute gap is the same value.
			if d := math.Abs(v - s.Value); d > 0.02*math.Max(math.Abs(v), 1) && d > 1 {
				differ = append(differ, key+" ours="+strconv.FormatFloat(s.Value, 'g', 6, 64)+" theirs="+strconv.FormatFloat(v, 'g', 6, 64))
			}
		}
	}
	t.Logf("compared %d series; %d not in node_exporter's output; %d differ", compared, len(missing), len(differ))
	for _, m := range missing {
		t.Logf("  not in node_exporter: %s", m)
	}
	for _, d := range differ {
		t.Errorf("  differs: %s", d)
	}
}

// canonicalSeries sorts a series' labels so two writers compare equal.
func canonicalSeries(s string) string {
	i := strings.Index(s, "{")
	if i < 0 {
		return s
	}
	body := strings.TrimSuffix(s[i+1:], "}")
	var parts []string
	for body != "" {
		eq := strings.Index(body, `="`)
		if eq < 0 {
			break
		}
		j := eq + 2
		for j < len(body) && !(body[j] == '"' && body[j-1] != '\\') {
			j++
		}
		parts = append(parts, body[:j+1])
		body = strings.TrimPrefix(body[j+1:], ",")
	}
	sort.Strings(parts)
	return s[:i] + "{" + strings.Join(parts, ",") + "}"
}
