package server

import (
	"encoding/binary"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestExpandBatchServerLabelsWin(t *testing.T) {
	ts := time.UnixMilli(1761573600000)
	b := proto.MetricsBatch{Timestamp: ts, Families: []proto.MetricFamily{
		{Name: "node_load1", Type: "gauge", Samples: []proto.MetricSample{{Value: 0.5}}},
		// An agent naming its own instance must not pass for another host.
		{Name: "node_cpu_seconds_total", Type: "counter", Labels: []string{"cpu", "mode", "instance", "__name__", "bad-name"},
			Samples: []proto.MetricSample{{Values: []string{"0", "idle", "other-host", "x", "y"}, Value: 12.5}}},
		{Name: "bad metric", Samples: []proto.MetricSample{{Value: 1}}},
		{Name: "node_nan", Samples: []proto.MetricSample{{Value: math.NaN()}}},
		// Fewer values than labels: the missing ones are left off.
		{Name: "node_short", Labels: []string{"a", "b"}, Samples: []proto.MetricSample{{Values: []string{"1"}, Value: 2}}},
	}}
	endpoint := [][2]string{{"job", "mustra"}, {"instance", "web01"}, {"instance_name", "web01"}}
	got := expandBatch(b, endpoint)
	want := []telemetrySeries{
		{Name: "node_load1", Type: "gauge", Labels: [][2]string{{"instance", "web01"}, {"instance_name", "web01"}, {"job", "mustra"}}, Value: 0.5, TimeMs: ts.UnixMilli()},
		{Name: "node_cpu_seconds_total", Type: "counter", Labels: [][2]string{{"cpu", "0"}, {"instance", "web01"}, {"instance_name", "web01"}, {"job", "mustra"}, {"mode", "idle"}}, Value: 12.5, TimeMs: ts.UnixMilli()},
		{Name: "node_short", Labels: [][2]string{{"a", "1"}, {"instance", "web01"}, {"instance_name", "web01"}, {"job", "mustra"}}, Value: 2, TimeMs: ts.UnixMilli()},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expandBatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestFormatExposition(t *testing.T) {
	series := []telemetrySeries{
		{Name: "node_load1", Type: "gauge", Labels: [][2]string{{"instance", "b"}}, Value: 1.25, TimeMs: 1000},
		{Name: "node_cpu_seconds_total", Type: "counter", Labels: [][2]string{{"instance", "a"}, {"mode", `say "hi"\` + "\n"}}, Value: 3, TimeMs: 2000},
		{Name: "node_load1", Type: "gauge", Labels: [][2]string{{"instance", "a"}}, Value: 0, TimeMs: 1000},
		{Name: "node_untyped", Labels: [][2]string{{"instance", "a"}}, Value: 7, TimeMs: 3000},
	}
	want := `# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{instance="a",mode="say \"hi\"\\\n"} 3 2000
# TYPE node_load1 gauge
node_load1{instance="b"} 1.25 1000
node_load1{instance="a"} 0 1000
# TYPE node_untyped gauge
node_untyped{instance="a"} 7 3000
`
	if got := formatExposition(series); got != want {
		t.Errorf("formatExposition:\n%s\nwant\n%s", got, want)
	}
}

// pbField reads one protobuf field: its number, wire type, and either the
// length-delimited bytes or the fixed64/varint value.
func pbField(t *testing.T, b []byte) (field, wire int, data []byte, num uint64, rest []byte) {
	t.Helper()
	key, n := binary.Uvarint(b)
	if n <= 0 {
		t.Fatal("bad key")
	}
	b = b[n:]
	field, wire = int(key>>3), int(key&7)
	switch wire {
	case 0:
		v, n := binary.Uvarint(b)
		return field, wire, nil, v, b[n:]
	case 1:
		return field, wire, nil, binary.LittleEndian.Uint64(b[:8]), b[8:]
	case 2:
		l, n := binary.Uvarint(b)
		b = b[n:]
		return field, wire, b[:l], 0, b[l:]
	}
	t.Fatalf("unexpected wire type %d", wire)
	return
}

// The hand-written WriteRequest decodes back to the series it was given,
// in the field numbers of prometheus/prompb.
func TestEncodeWriteRequestRoundTrip(t *testing.T) {
	in := []telemetrySeries{
		{Name: "node_load1", Labels: [][2]string{{"instance", "web01"}, {"job", "mustra"}}, Value: 0.75, TimeMs: 1761573600123},
		{Name: "node_boot_time_seconds", Labels: [][2]string{{"instance", strings.Repeat("h", 200)}}, Value: -1.5, TimeMs: 1},
	}
	type decoded struct {
		labels [][2]string
		value  float64
		ts     int64
	}
	var got []decoded
	b := encodeWriteRequest(in)
	for len(b) > 0 {
		f, w, ts, _, rest := pbField(t, b)
		b = rest
		if f != 1 || w != 2 {
			t.Fatalf("WriteRequest field %d/%d", f, w)
		}
		var d decoded
		for len(ts) > 0 {
			f, w, data, _, rest := pbField(t, ts)
			ts = rest
			switch {
			case f == 1 && w == 2:
				var kv [2]string
				for len(data) > 0 {
					lf, _, s, _, r := pbField(t, data)
					data = r
					kv[lf-1] = string(s)
				}
				d.labels = append(d.labels, kv)
			case f == 2 && w == 2:
				for len(data) > 0 {
					sf, _, _, v, r := pbField(t, data)
					data = r
					if sf == 1 {
						d.value = math.Float64frombits(v)
					} else {
						d.ts = int64(v)
					}
				}
			default:
				t.Fatalf("TimeSeries field %d/%d", f, w)
			}
		}
		got = append(got, d)
	}
	if len(got) != len(in) {
		t.Fatalf("decoded %d series, want %d", len(got), len(in))
	}
	for i, s := range in {
		wantLabels := append([][2]string{{"__name__", s.Name}}, s.Labels...)
		if !reflect.DeepEqual(got[i].labels, wantLabels) || got[i].value != s.Value || got[i].ts != s.TimeMs {
			t.Errorf("series %d: got %+v, want %v %v %d", i, got[i], wantLabels, s.Value, s.TimeMs)
		}
	}
}

func TestRemoteWriteErrorRetryable(t *testing.T) {
	for status, want := range map[int]bool{0: true, 400: false, 401: false, 429: true, 500: true, 503: true} {
		if got := (remoteWriteError{status: status}).retryable(); got != want {
			t.Errorf("status %d retryable=%v, want %v", status, got, want)
		}
	}
	if (remoteWriteError{final: true}).retryable() {
		t.Error("a URL the allowlist refuses was retried")
	}
}

func TestEndpointLabels(t *testing.T) {
	l := telemetryLabels{Job: "mustra", Extra: map[string]string{"env": "lab"}}
	if got, want := endpointLabels(l, "web01", "default", nil), [][2]string{{"job", "mustra"}, {"instance", "web01"}, {"instance_name", "web01"}, {"env", "lab"}, {"site", "default"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// An extra site replaces the endpoint's, once; job and instance stay.
	l.Extra = map[string]string{"site": "home", "job": "x", "instance": "y", "zone": "a"}
	if got, want := endpointLabels(l, "web01", "default", nil), [][2]string{{"job", "mustra"}, {"instance", "web01"}, {"instance_name", "web01"}, {"site", "home"}, {"zone", "a"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// A group's label beats an extra one; it cannot rename the endpoint.
	got := endpointLabels(l, "mbp", "default", map[string]string{"device_class": "laptop", "zone": "b", "instance_name": "x"})
	want := [][2]string{{"job", "mustra"}, {"instance", "mbp"}, {"instance_name", "mbp"}, {"device_class", "laptop"}, {"site", "home"}, {"zone", "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestUpSeries(t *testing.T) {
	now := time.UnixMilli(1761573600000)
	eps := map[string]telemetryEndpoint{
		"a": {Labels: [][2]string{{"job", "mustra"}, {"instance", "web01"}}, Online: true, InScope: true},
		"b": {Labels: [][2]string{{"job", "mustra"}, {"instance", "mbp"}, {"device_class", "laptop"}}, Online: false, InScope: true},
		"c": {Labels: [][2]string{{"job", "mustra"}, {"instance", "kiosk"}}, Online: true, InScope: false},
	}
	got := upSeries(eps, map[string]time.Time{"a": now.Add(-20 * time.Second), "c": now}, now)
	want := []telemetrySeries{
		// Only a has sent metrics (c is out of scope).
		{Name: "mustra_metrics_last_received_timestamp_seconds", Type: "gauge", Labels: [][2]string{{"instance", "web01"}, {"job", "mustra"}}, Value: 1761573580, TimeMs: now.UnixMilli()},
		{Name: "up", Type: "gauge", Labels: [][2]string{{"device_class", "laptop"}, {"instance", "mbp"}, {"job", "mustra"}}, Value: 0, TimeMs: now.UnixMilli()},
		{Name: "up", Type: "gauge", Labels: [][2]string{{"instance", "web01"}, {"job", "mustra"}}, Value: 1, TimeMs: now.UnixMilli()},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("upSeries:\n got %+v\nwant %+v", got, want)
	}
}
