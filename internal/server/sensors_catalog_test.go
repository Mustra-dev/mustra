package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Every sensor the agent publishes must be documented. This is the whole
// point of the catalog: an undocumented sensor is a number in the console
// with no way to find out where it came from, and the failure mode is
// silent — the page simply doesn't mention it. Failing the build instead
// makes documenting a new sensor part of adding one.
func TestEverySensorIsDocumented(t *testing.T) {
	published := []proto.SensorKind{
		proto.SensorActionLogs,
		proto.SensorProcesses,
		proto.SensorServices,
		proto.SensorInstalledApps,
		proto.SensorPatches,
		proto.SensorDisks,
		proto.SensorNetwork,
		proto.SensorUsers,
		proto.SensorHardware,
		proto.SensorPrivileges,
		proto.SensorNeighbors,
		proto.SensorCertificates,
		proto.SensorPerformance,
		proto.SensorIntegrity,
		proto.SensorLocalAdmins,
		proto.SensorDirectory,
		proto.SensorBackups,
		proto.SensorSecurityPosture,
		proto.SensorPatchStatus,
	}

	documented := map[string]sensorDoc{}
	for _, d := range sensorCatalog() {
		if _, dup := documented[d.Kind]; dup {
			t.Errorf("sensor %q is documented twice", d.Kind)
		}
		documented[d.Kind] = d
	}

	for _, kind := range published {
		if _, ok := documented[string(kind)]; !ok {
			t.Errorf("sensor %q is published by the agent but has no catalog entry", kind)
		}
	}
	for kind := range documented {
		found := false
		for _, k := range published {
			if string(k) == kind {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("catalog documents %q, which no agent sensor publishes", kind)
		}
	}
}

// A catalog entry that exists but says nothing is no better than a missing
// one, so the fields that carry the actual explanation are required.
func TestSensorDocsAreSubstantive(t *testing.T) {
	for _, d := range sensorCatalog() {
		t.Run(d.Kind, func(t *testing.T) {
			if strings.TrimSpace(d.Name) == "" {
				t.Error("name is empty")
			}
			if len(d.Summary) < 20 {
				t.Errorf("summary is too short to be useful: %q", d.Summary)
			}
			if len(d.Answers) < 40 {
				t.Errorf("answers is too short to be useful: %q", d.Answers)
			}
			if strings.TrimSpace(d.Returns) == "" {
				t.Error("returns is empty")
			}
			if len(d.Mechanism) == 0 {
				t.Error("no mechanism documented — 'how is it pulling it' is the point of this catalog")
			}
			for _, m := range d.Mechanism {
				if strings.TrimSpace(m.OS) == "" {
					t.Error("mechanism entry has no OS")
				}
				if len(m.How) < 25 {
					t.Errorf("mechanism for %s is too vague: %q", m.OS, m.How)
				}
			}
			if strings.TrimSpace(d.Interval) == "" {
				t.Error("interval is empty")
			}
			if strings.TrimSpace(d.Timeout) == "" {
				t.Error("timeout is empty")
			}
			if strings.TrimSpace(d.Cost) == "" {
				t.Error("cost is empty")
			}
		})
	}
}

func TestBuiltinTemplatesAreValidDisabledDrafts(t *testing.T) {
	for _, d := range sensorCatalog() {
		t.Run(d.Kind, func(t *testing.T) {
			if d.Template == nil {
				t.Fatal("missing editable example")
			}
			c := d.Template.draft(t)
			if c.Enabled {
				t.Fatal("template must be a new disabled draft")
			}
			if len(d.Template.Notes) < 30 {
				t.Fatal("missing explanation of example limitations")
			}
			if c.IntervalSeconds < 60 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > c.IntervalSeconds || c.TimeoutSeconds > 600 {
				t.Fatal("invalid timing")
			}
			if err := validateSensorDefinition(&c); err != nil {
				t.Fatal(err)
			}
			for _, os := range []string{"linux", "darwin", "windows"} {
				if strings.TrimSpace(c.Commands[os]) == "" {
					t.Fatalf("missing %s example", os)
				}
			}
		})
	}
}

func TestBuiltinSourceEndpoint(t *testing.T) {
	s := &Server{}
	for _, d := range sensorCatalog() {
		t.Run(d.Kind, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.SetPathValue("kind", d.Kind)
			w := httptest.NewRecorder()
			s.handleSensorSource(w, r)
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var got struct{ Sources []struct{ Name, Code string } }
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Sources) != len(d.Sources)+1 {
				t.Fatal("missing collector or runtime source")
			}
			for _, source := range got.Sources {
				data, err := os.ReadFile("../../" + source.Name)
				if err != nil {
					t.Fatal(err)
				}
				if source.Code != string(data) {
					t.Fatalf("source differs from checkout: %s", source.Name)
				}
			}
		})
	}
	for _, kind := range []string{"unknown", "../../go.mod", "custom"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.SetPathValue("kind", kind)
		w := httptest.NewRecorder()
		s.handleSensorSource(w, r)
		if w.Code != 404 {
			t.Errorf("%q: status %d", kind, w.Code)
		}
	}
}

// Coverage treats every collected sensor that nobody reports as a gap; a
// sensor that only runs on request must say so or it always looks broken.
func TestOnDemandSensorsAreMarked(t *testing.T) {
	for _, d := range sensorCatalog() {
		if d.Kind == string(proto.SensorActionLogs) && !d.OnDemand {
			t.Fatalf("%s is never collected as inventory and must be OnDemand", d.Kind)
		}
		if d.OnDemand && d.Kind != string(proto.SensorActionLogs) {
			t.Errorf("%s is marked OnDemand; check that it really is never collected", d.Kind)
		}
	}
}

// A template is a custom sensor nobody has saved, so it has no ID,
// creator or times to send: GET /api/sensors used to send them empty and
// as year 1 (#100). What the console's clone reads is all there.
func TestBuiltinTemplatesSendOnlyWhatADraftHas(t *testing.T) {
	for _, d := range sensorCatalog() {
		t.Run(d.Kind, func(t *testing.T) {
			b, err := json.Marshal(d.Template)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"id", "created_by", "created_at", "updated_at"} {
				if v, ok := got[k]; ok {
					t.Errorf("template sends %s: %v", k, v)
				}
			}
			for _, k := range []string{"name", "description", "commands", "interval_seconds", "timeout_seconds",
				"enabled", "platforms", "fields", "max_age_seconds", "notes"} {
				if _, ok := got[k]; !ok {
					t.Errorf("template leaves out %s", k)
				}
			}
		})
	}
}

// draft is the custom sensor the template would save as: what a client
// posting the template's JSON as a new sensor would send.
func (tpl sensorTemplate) draft(t *testing.T) store.CustomSensor {
	t.Helper()
	b, err := json.Marshal(tpl)
	if err != nil {
		t.Fatal(err)
	}
	var c store.CustomSensor
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// sensorTemplate repeats the custom sensor's fields rather than embedding
// it, to leave out what only a saved sensor has. A field added to custom
// sensors must be added to templates too, or the templates' JSON files
// could set it and the field would be silently dropped.
func TestSensorTemplateHasEveryFieldADraftHas(t *testing.T) {
	serverSet := map[string]bool{"id": true, "created_by": true, "created_at": true, "updated_at": true}
	keys := func(v any) map[string]bool {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for k := range m {
			out[k] = true
		}
		return out
	}
	// Non-empty values, so no field is left out by omitempty.
	param := []proto.DeployParameter{{Name: "p"}}
	template := keys(sensorTemplate{Parameters: param})
	for k := range keys(store.CustomSensor{Parameters: param}) {
		if !serverSet[k] && !template[k] {
			t.Errorf("custom sensors have %q and templates do not", k)
		}
	}
}

// sensorTemplate copies store.CustomSensor's editable fields by hand (it
// leaves out the ID, creator and times only a saved sensor has). A field
// added to CustomSensor and not here would be silently missing from every
// template the console clones.
func TestSensorTemplateHasEveryEditableCustomSensorField(t *testing.T) {
	jsonNames := func(typ reflect.Type) map[string]bool {
		out := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" || strings.Contains(f.Tag.Get("api"), "readonly") || name == "id" {
				continue
			}
			out[name] = true
		}
		return out
	}
	tpl := jsonNames(reflect.TypeOf(sensorTemplate{}))
	for name := range jsonNames(reflect.TypeOf(store.CustomSensor{})) {
		if !tpl[name] {
			t.Errorf("store.CustomSensor has %q, sensorTemplate does not", name)
		}
	}
}
