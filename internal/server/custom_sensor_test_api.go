package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

var wqlSelect = regexp.MustCompile(`(?is)^\s*select\s+.+?\s+from\s+([a-z_][a-z0-9_]*)\b`)
var wqlNamespace = regexp.MustCompile(`(?i)^root(?:\\[a-z_][a-z0-9_]*)+$`)

func validateWQL(query, namespace string) error {
	m := wqlSelect.FindStringSubmatch(query)
	if m == nil || (strings.HasPrefix(m[1], "__") && strings.HasSuffix(strings.ToLower(m[1]), "event")) || !wqlNamespace.MatchString(namespace) {
		return fmt.Errorf("WQL requires a local SELECT inventory query and a namespace such as root\\cimv2")
	}
	return nil
}

// testCustomSensorRequest is the body of POST /api/sensors/custom/test.
type testCustomSensorRequest struct {
	AgentID string             `json:"agent_id" api:"required"`
	Sensor  store.CustomSensor `json:"sensor" api:"required"`
}

// testCustomSensorResponse is what POST /api/sensors/custom/test answers.
type testCustomSensorResponse struct {
	Result          proto.CustomSensorResult `json:"result"`
	SuggestedFields []proto.SensorField      `json:"suggested_fields"`
}

func (s *Server) handleTestCustomSensor(w http.ResponseWriter, r *http.Request) {
	var body testCustomSensorRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var target *store.AgentRecord
	for i := range agents {
		if agents[i].AgentID == body.AgentID {
			target = &agents[i]
			break
		}
	}
	if target == nil || !target.Online {
		http.Error(w, "select an online endpoint", 400)
		return
	}
	caps, err := s.store.CustomCapabilities(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if caps[body.AgentID] < 1 {
		http.Error(w, "endpoint needs an agent upgrade and capability refresh", 409)
		return
	}
	c := body.Sensor
	if _, err = normalizeSensorScripts(c.Commands); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	p := c.Platform(target.OS)
	script := c.Commands[target.OS]
	if strings.TrimSpace(script) == "" {
		http.Error(w, "no script for the selected endpoint's platform", 400)
		return
	}
	if p.Language == "wql" {
		if err = validateWQL(script, p.Namespace); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	testPlatform := proto.SensorPlatform{Language: p.Language, Output: proto.SensorOutput{Format: "text"}}
	if p.Language == "wql" {
		testPlatform.Output.Format = "json"
	}
	if err = sensoroutput.Validate(nil, map[string]proto.SensorPlatform{target.OS: testPlatform}); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	timeout := c.TimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}
	if timeout > 60 {
		timeout = 60
	}
	def := proto.CustomSensorDef{Command: script, Platform: p, TimeoutSeconds: timeout}
	if p.Language == "go" {
		if caps[body.AgentID] < 2 {
			http.Error(w, "endpoint needs Go sensor capability version 2", 409)
			return
		}
		if err = s.buildGoSensors(r.Context(), c); err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		def.Artifact, err = s.goSensorArtifact(r.Context(), c, target.OS, target.Arch)
		if err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		def.Command = ""
	}
	payload, _ := json.Marshal(proto.AgentCommand{Cmd: "test_custom_sensor", CustomSensor: &def})
	// Preview executes operator code, so attribute it before dispatch just like other direct actions.
	detail, _ := json.Marshal(map[string]any{"name": c.Name, "language": p.Language, "revision": c.Revision(target.OS), "namespace": p.Namespace})
	if err := s.store.RecordAuditEvent(r.Context(), store.AuditEvent{Action: "sensors.custom.test", Actor: auth.CurrentUser(r.Context()).Username, Target: body.AgentID, AgentID: body.AgentID, Severity: "notice", Outcome: "started", Detail: string(detail)}); err != nil {
		http.Error(w, "cannot record endpoint test audit", 500)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout+5)*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(ctx, bnats.Cmd(body.AgentID), payload)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	var reply proto.AgentCommandResult
	if json.Unmarshal(msg.Data, &reply) != nil || reply.CustomSensor == nil {
		http.Error(w, "endpoint did not return a sensor result", 502)
		return
	}
	result := *reply.CustomSensor
	raw := ""
	if result.Raw != nil {
		raw = *result.Raw
	}
	suggested := []proto.SensorField{}
	if p.Language == "wql" && result.Error == "" {
		suggested = inferSensorFields(raw)
	}
	if result.Error == "" {
		rows, e := sensoroutput.Parse(raw, p.Output, c.Fields)
		if e != nil {
			result.Error = e.Error()
		} else {
			result.Rows = rows
		}
	}
	writeJSONResponse(w, testCustomSensorResponse{Result: result, SuggestedFields: suggested})
}
func inferSensorFields(raw string) []proto.SensorField {
	var rows []map[string]any
	if json.Unmarshal([]byte(raw), &rows) != nil {
		return nil
	}
	types := map[string]string{}
	for _, row := range rows {
		for k, v := range row {
			if v == nil {
				if types[k] == "" {
					types[k] = "string"
				}
				continue
			}
			t := ""
			switch v.(type) {
			case string:
				t = "string"
			case bool:
				t = "bool"
			case float64:
				t = "number"
			}
			if t != "" {
				types[k] = t
			}
		}
	}
	out := []proto.SensorField{}
	for name, t := range types {
		out = append(out, proto.SensorField{Name: name, Type: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
