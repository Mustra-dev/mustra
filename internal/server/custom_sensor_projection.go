package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"github.com/mustra-dev/mustra/internal/store"
)

func (s *Server) sensorFields(ctx context.Context) ([]groups.FieldSpec, error) {
	defs, err := s.store.ListCustomSensors(ctx)
	if err != nil {
		return nil, err
	}
	out := groups.Fields()
	for _, c := range defs {
		for _, f := range sensoroutput.Fields(c.Fields) {
			ops := []string{"equals", "not_equals"}
			switch f.Type {
			case "string":
				ops = append(ops, "contains", "not_contains", "starts_with", "ends_with", "regex")
			case "number":
				ops = append(ops, "gt", "gte", "lt", "lte")
			}
			out = append(out, groups.FieldSpec{Field: c.SensorKind() + "." + f.Name, Label: c.Name + " · " + f.Name, Kind: f.Type, Ops: ops})
		}
		out = append(out, groups.FieldSpec{Field: c.SensorKind() + ".count", Label: c.Name + " · count", Kind: "number", Ops: []string{"equals", "gt", "lt", "gte", "lte"}})
		for _, key := range []string{"_status", "_collected_at", "_last_attempt_at", "_historical", "_error"} {
			out = append(out, groups.FieldSpec{Field: c.SensorKind() + "." + key, Label: c.Name + " · " + strings.TrimPrefix(key, "_"), Kind: "string", Ops: []string{"equals", "contains"}})
		}
	}
	return out, nil
}
func (s *Server) validateCustomFields(ctx context.Context, get []string, rules []groups.Rule, record string) error {
	fields, err := s.sensorFields(ctx)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, f := range fields {
		known[f.Field] = true
	}
	var check func(groups.Rule) error
	check = func(r groups.Rule) error {
		if err := r.Validate(); err != nil {
			return err
		}
		if r.Op == "same_row" {
			var children []groups.Rule
			_ = json.Unmarshal([]byte(r.Value), &children)
			for _, child := range children {
				if err := check(child); err != nil {
					return err
				}
			}
			return nil
		}
		if strings.HasPrefix(r.Field, "custom_") && !known[r.Field] {
			return fmt.Errorf("unknown custom sensor field %q", r.Field)
		}
		return nil
	}
	for _, r := range rules {
		if err := check(r); err != nil {
			return err
		}
	}
	for _, f := range get {
		if strings.HasPrefix(f, "custom_") && !known[f] {
			return fmt.Errorf("unknown field %q", f)
		}
	}
	if record != "" {
		for _, f := range get {
			if sensor, key, ok := strings.Cut(f, "."); ok && sensor != record && key != "count" && !strings.HasPrefix(key, "_") {
				return fmt.Errorf("record view supports columns from one sensor; use endpoint summary for multiple sensors")
			}
		}
		found := false
		for _, f := range fields {
			if strings.HasPrefix(f.Field, record+".") {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unknown record sensor")
		}
	}
	return nil
}

func customStatus(def store.CustomSensor, os string, row *store.AgentSensorRow, capability int, now time.Time) (proto.CustomSensorResult, string) {
	if !def.Enabled {
		return proto.CustomSensorResult{}, "disabled"
	}
	if strings.TrimSpace(def.Commands[os]) == "" {
		return proto.CustomSensorResult{}, "not_applicable"
	}
	if (capability < 1 && !def.LegacyCompatible(os)) || (capability < 2 && def.Platform(os).Language == "go") {
		return proto.CustomSensorResult{Error: "agent upgrade required"}, "unsupported"
	}
	if row == nil {
		return proto.CustomSensorResult{}, "never_reported"
	}
	var res proto.CustomSensorResult
	if json.Unmarshal(row.Data, &res) != nil {
		return proto.CustomSensorResult{Error: "invalid cached result"}, "invalid"
	}
	res = store.NormalizeCustomResult(def, os, res)
	if res.TimedOut {
		return res, "timed_out"
	}
	if res.Error != "" || res.ExitCode != 0 {
		return res, "failed"
	}
	if now.Sub(row.CollectedAt) > def.MaxAge() {
		return res, "stale"
	}
	return res, "success"
}
func (s *Server) addCustomMatching(ctx context.Context, devices []groups.Device) error {
	defs, err := s.store.ListCustomSensors(ctx)
	if err != nil {
		return err
	}
	caps, err := s.store.CustomCapabilities(ctx)
	if err != nil {
		return err
	}
	for _, def := range defs {
		history, err := s.store.ListCustomSuccess(ctx, def.SensorKind())
		if err != nil {
			return err
		}
		records, err := s.store.ListSensorDataForSensor(ctx, def.SensorKind())
		if err != nil {
			return err
		}
		byID := map[string]*store.AgentSensorRow{}
		for i := range records {
			byID[records[i].AgentID] = &records[i]
		}
		for i := range devices {
			d := &devices[i]
			row := byID[d.AgentID]
			res, status := customStatus(def, d.OS, row, caps[d.AgentID], time.Now())
			if d.SensorStatus == nil {
				d.SensorStatus = map[string]map[string]string{}
			}
			metadata := map[string]string{"_status": status, "_error": res.Error, "_collected_at": "", "_last_attempt_at": "", "_historical": "false"}
			if row != nil {
				metadata["_collected_at"] = row.CollectedAt.UTC().Format(time.RFC3339)
				metadata["_last_attempt_at"] = metadata["_collected_at"]
			}
			d.SensorStatus[def.SensorKind()] = metadata
			if status != "success" {
				if old, ok := history[d.AgentID]; ok {
					var previous proto.CustomSensorResult
					if json.Unmarshal(old.Data, &previous) == nil {
						historical, compatible := store.HistoricalCustomRows(def, previous)
						if compatible {
							if d.HistoricalSensors == nil {
								d.HistoricalSensors = map[string][]map[string]any{}
							}
							d.HistoricalSensors[def.SensorKind()] = historical
							metadata["_historical"] = "true"
							metadata["_collected_at"] = old.CollectedAt.UTC().Format(time.RFC3339)
						}
					}
				}
			}

			if status == "success" {
				if d.Sensors == nil {
					d.Sensors = map[string][]map[string]any{}
				}
				d.Sensors[def.SensorKind()] = res.Rows
			}
		}
	}
	return nil
}

// parseCustomOutputRequest is the body of POST /api/sensors/custom/parse.
type parseCustomOutputRequest struct {
	Raw    string              `json:"raw"`
	Output proto.SensorOutput  `json:"output"`
	Fields []proto.SensorField `json:"fields"`
}

// parseCustomOutputResponse is what POST /api/sensors/custom/parse answers.
type parseCustomOutputResponse struct {
	Rows []map[string]any `json:"rows"`
}

func (s *Server) handleParseCustomOutput(w http.ResponseWriter, r *http.Request) {
	var body parseCustomOutputRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if err := sensoroutput.Validate(body.Fields, map[string]proto.SensorPlatform{"linux": {Output: body.Output}}); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	rows, err := sensoroutput.Parse(body.Raw, body.Output, body.Fields)
	if err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	writeJSONResponse(w, parseCustomOutputResponse{Rows: rows})
}
