package server

import (
	"encoding/json"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// allSensorKinds is every kind normalizeSnapshotData decodes, plus a custom
// and an unknown one, so the fuzzer drives each type path.
var allSensorKinds = []proto.SensorKind{
	proto.SensorProcesses, proto.SensorServices, proto.SensorInstalledApps,
	proto.SensorPatches, proto.SensorDisks, proto.SensorNetwork, proto.SensorUsers,
	proto.SensorHardware, proto.SensorPrivileges, proto.SensorNeighbors,
	proto.SensorCertificates, proto.SensorPerformance, proto.SensorIntegrity,
	proto.SensorLocalAdmins, proto.SensorSecurityPosture, proto.SensorReveal,
	"custom_abc", "unknown_kind", "custom_bad.kind",
}

// FuzzNormalizeSnapshot drives the agent-snapshot normalizer with arbitrary
// JSON for every sensor kind. This is the stored-XSS barrier: a snapshot is
// decoded into its Go type and re-encoded before storage so the console
// never meets a shape the type does not promise. Properties: it never
// panics, whatever it accepts is valid JSON, and for a custom sensor every
// row value it emits is a JSON scalar (never a nested object/array that
// could carry markup the console renders).
func FuzzNormalizeSnapshot(f *testing.F) {
	for _, raw := range []string{
		`[]`, `[{"pid":1,"ppid":0,"name":"init"}]`,
		`[{"pid":"1\"><img src=x onerror=alert(1)>","name":"x"}]`,
		`[{"a":1,"b":{"x":"<i>"},"c":[1,2]}]`, `{}`, `null`, `[{}]`,
		`[{"name":"<script>","version":"1"}]`, `"string"`, `123`,
	} {
		f.Add(raw, 0)
	}
	f.Fuzz(func(t *testing.T, raw string, kindIdx int) {
		if len(raw) > 1<<16 {
			return
		}
		kind := allSensorKinds[((kindIdx%len(allSensorKinds))+len(allSensorKinds))%len(allSensorKinds)]
		out, err := normalizeSnapshotData(kind, json.RawMessage(raw))
		if err != nil {
			return
		}
		if !json.Valid(out) {
			t.Fatalf("normalizeSnapshotData(%q,%q) produced invalid JSON: %q", kind, raw, out)
		}
		// For a custom sensor, the normalized rows must be flat: every value
		// a scalar, so no nested structure reaches the console unescaped.
		if kind == "custom_abc" {
			var rows []map[string]any
			if json.Unmarshal(out, &rows) != nil {
				t.Fatalf("custom rows did not re-decode: %q", out)
			}
			for _, row := range rows {
				for k, v := range row {
					switch v.(type) {
					case nil, bool, float64, string:
					default:
						t.Fatalf("custom row field %q is not a scalar after normalization: %T (%q)", k, v, raw)
					}
				}
			}
		}
	})
}

// FuzzNormalizeFacts proves the agent-facts bounds: whatever an agent
// reports, normalizeFacts clamps log level, intervals and profile length to
// values a client profile can actually set, and the site to a safe token.
func FuzzNormalizeFacts(f *testing.F) {
	f.Add(`{"site":"HQ","settings":{"log_level":"debug","sensor_interval_seconds":60}}`)
	f.Add(`{"site":"a.b*c","settings":{"log_level":"<script>","sensor_interval_seconds":-5,"random_delay_seconds":999999999,"profile":"x"}}`)
	f.Add(`{}`)
	f.Add(`{"settings":null}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<16 {
			return
		}
		var facts proto.Facts
		if json.Unmarshal([]byte(raw), &facts) != nil {
			return
		}
		normalizeFacts(&facts)
		if facts.Site != "" && !validSite(facts.Site) {
			t.Fatalf("normalizeFacts left an unsafe site %q", facts.Site)
		}
		if facts.Settings != nil {
			st := facts.Settings
			if !validLogLevels[st.LogLevel] {
				t.Fatalf("log level not clamped: %q", st.LogLevel)
			}
			if st.SensorIntervalSeconds < 0 || st.SensorIntervalSeconds > 7*24*3600 {
				t.Fatalf("sensor interval not clamped: %d", st.SensorIntervalSeconds)
			}
			if st.RandomDelaySeconds < 0 || st.RandomDelaySeconds > 24*3600 {
				t.Fatalf("random delay not clamped: %d", st.RandomDelaySeconds)
			}
			if len(st.Profile) > 200 {
				t.Fatalf("profile not clamped: %d bytes", len(st.Profile))
			}
		}
	})
}
