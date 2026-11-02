package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"net/http"
	"strings"
	"time"

	gonats "github.com/nats-io/nats.go"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Custom sensors: operator-authored collection.
//
// The agent asks which ones apply to it rather than the server pushing them,
// matching the patch-list query — collection is driven by the agent's own
// timer, so the agent is the natural requester. The server resolves the
// per-OS command down to the single command that endpoint should run, so an
// agent never learns about commands meant for other platforms.
//
// On trust: this is operator-written code running on every endpoint with the
// agent's rights. That is the same boundary a software package's command
// already crosses deliberately, so it is gated on the same permission —
// authoring a custom sensor and authoring a package command are the same act
// with the same blast radius, and inventing a separate permission would
// imply a distinction that does not exist.

const (
	minCustomSensorInterval = 60
	maxCustomSensorTimeout  = 600
)

func (s *Server) subscribeCustomSensorQueries(ctx context.Context) (*gonats.Subscription, error) {
	return s.nc.Subscribe(bnats.CustomSensorsWildcard(), func(msg *gonats.Msg) {
		agentID := strings.TrimPrefix(msg.Subject, "beacon.customsensors.")
		if agentID == "" || agentID == msg.Subject {
			return
		}
		if !s.agentReplyAllowed(ctx, msg, replyAgent, agentID) {
			return
		}
		var request proto.CustomSensorRequest
		if json.Unmarshal(msg.Data, &request) != nil {
			return
		}
		reply := s.customSensorsFor(ctx, agentID, request.Version)
		payload, err := json.Marshal(reply)
		if err != nil {
			return
		}
		s.respondToAgent(ctx, msg, replyAgent, agentID, payload)
	})
}

// customSensorsFor resolves the definitions this agent should run. An
// unresolvable agent gets an empty list rather than an error: the agent's
// only sane response to a failure here is to run nothing, and saying so
// plainly beats leaving it to time out.
func (s *Server) customSensorsFor(ctx context.Context, agentID string, versions ...int) proto.CustomSensorReply {
	// One row, not the fleet: every agent asks every five minutes, and a
	// whole-table read per ask was a quarter of the server's CPU while 500
	// agents started together.
	agentOS, agentArch, err := s.store.GetAgentOSArch(ctx, agentID)
	if err != nil {
		s.logger.Warn("custom sensor query: agent lookup failed", "agent_id", agentID, "error", err)
		return proto.CustomSensorReply{}
	}
	if agentOS == "" {
		return proto.CustomSensorReply{}
	}

	defs, err := s.store.ListCustomSensors(ctx)
	if err != nil {
		s.logger.Warn("custom sensor query: list failed", "agent_id", agentID, "error", err)
		return proto.CustomSensorReply{}
	}

	version := 0
	if len(versions) > 0 {
		version = versions[0]
	}
	if err := s.store.RecordCustomCapability(ctx, agentID, version); err != nil {
		return proto.CustomSensorReply{}
	}
	out := proto.CustomSensorReply{}
	for _, c := range defs {
		if !c.Enabled || version < 3 && len(c.Parameters) > 0 {
			continue
		}
		cmd := strings.TrimSpace(c.Commands[agentOS])
		if cmd == "" {
			continue // not applicable to this platform
		}
		p := c.Platform(agentOS)
		if version < 1 && !c.LegacyCompatible(agentOS) {
			continue
		}
		var artifact *proto.SensorArtifact
		if p.Language == "go" {
			if version < 2 {
				continue
			}
			artifact, err = s.goSensorArtifact(ctx, c, agentOS, agentArch)
			if err != nil {
				s.logger.Warn("Go sensor artifact unavailable", "sensor", c.ID, "error", err)
				continue
			}
			cmd = ""
		}
		inputs, err := deploy.Parameters(c.Parameters, nil)
		if err != nil {
			continue
		}
		out.Sensors = append(out.Sensors, proto.CustomSensorDef{Inputs: inputs, Artifact: artifact,
			ID: c.ID, Name: c.Name, Sensor: c.SensorKind(), Command: cmd, Platform: p, Revision: c.Revision(agentOS),
			IntervalSeconds: c.IntervalSeconds, TimeoutSeconds: c.TimeoutSeconds,
		})
	}
	return out
}

// ---- CRUD ----

// listCustomSensorsResponse is what GET /api/sensors/custom answers.
type listCustomSensorsResponse struct {
	Sensors []store.CustomSensor `json:"sensors"`
}

func (s *Server) handleListCustomSensors(w http.ResponseWriter, r *http.Request) {
	defs, err := s.store.ListCustomSensors(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if defs == nil {
		defs = []store.CustomSensor{}
	}
	writeJSONResponse(w, listCustomSensorsResponse{Sensors: defs})
}

func (s *Server) handleUpsertCustomSensor(w http.ResponseWriter, r *http.Request) {
	var body store.CustomSensor
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	cleaned := map[string]string{}
	for os, cmd := range body.Commands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		cleaned[strings.ToLower(strings.TrimSpace(os))] = cmd
	}
	if len(cleaned) == 0 {
		http.Error(w, "give a command for at least one operating system", http.StatusBadRequest)
		return
	}
	commands, err := normalizeSensorScripts(body.Commands)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateSensorDefinition(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	validation, err := s.validateSensorLanguages(r.Context(), commands, body.Platforms)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if len(validation.Errors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeJSONResponse(w, validation)
		return
	}
	body.Commands = commands
	s.cleanupGoArtifacts(r.Context())
	if err := s.buildGoSensors(r.Context(), body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		diagnostics := map[string][]scriptDiagnostic{}
		for platform := range body.Commands {
			if body.Platform(platform).Language == "go" {
				diagnostics[platform] = []scriptDiagnostic{{Severity: "error", Message: err.Error()}}
			}
		}
		writeJSONResponse(w, scriptValidation{Errors: diagnostics})
		return
	}

	// Floors, not preferences. A custom sensor running every five seconds
	// across a fleet is a self-inflicted denial of service, and one with no
	// timeout is a hung process on every endpoint that never gets cleaned up.
	if body.IntervalSeconds < minCustomSensorInterval {
		body.IntervalSeconds = minCustomSensorInterval
	}
	if body.TimeoutSeconds <= 0 {
		body.TimeoutSeconds = 30
	}
	if body.TimeoutSeconds > maxCustomSensorTimeout {
		body.TimeoutSeconds = maxCustomSensorTimeout
	}
	if body.TimeoutSeconds > body.IntervalSeconds {
		// Otherwise a collection can still be running when the next is due.
		body.TimeoutSeconds = body.IntervalSeconds
	}

	if id := r.PathValue("id"); id != "" {
		body.ID = id
	}
	if body.ID == "" {
		body.ID = idgen.New("csn-")
		body.CreatedBy = auth.CurrentUser(r.Context()).Username
	}

	if old, e := s.store.GetCustomSensor(r.Context(), body.ID); e != nil {
		http.Error(w, e.Error(), 500)
		return
	} else if old != nil {
		retainGoRevision(*old)
	}
	out, err := s.store.UpsertCustomSensor(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "sensors.custom.save", Actor: auth.CurrentUser(r.Context()).Username,
		Target: out.Name, Severity: "notice",
		Detail: map[string]any{"id": out.ID, "platforms": len(out.Commands)},
	})
	s.cleanupGoArtifacts(r.Context())
	s.logger.Info("custom sensor saved", "id", out.ID, "name", out.Name,
		"platforms", len(out.Commands), "by", auth.CurrentUser(r.Context()).Username)
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteCustomSensor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteCustomSensor(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "sensors.custom.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: id, Severity: "notice",
	})
	w.WriteHeader(http.StatusNoContent)
}

// customSensorResultsResponse is what GET /api/sensors/custom/{id}/results
// answers.
type customSensorResultsResponse struct {
	Results []map[string]any    `json:"results"`
	Sensor  *store.CustomSensor `json:"sensor"`
}

// handleCustomSensorResults returns what each endpoint last reported for one
// custom sensor, which is the only way to find out whether the command an
// operator wrote actually does what they think on every platform.
func (s *Server) handleCustomSensorResults(w http.ResponseWriter, r *http.Request) {
	def, err := s.store.GetCustomSensor(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if def == nil {
		http.Error(w, "no such custom sensor", http.StatusNotFound)
		return
	}
	if !s.requireSensor(w, r, def.SensorKind()) {
		return
	}
	rows, err := s.store.ListSensorDataForSensor(r.Context(), def.SensorKind())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	caps, err := s.store.CustomCapabilities(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	byID := map[string]*store.AgentSensorRow{}
	for i := range rows {
		byID[rows[i].AgentID] = &rows[i]
	}
	out := []map[string]any{}
	for _, a := range agents {
		if strings.TrimSpace(def.Commands[a.OS]) == "" {
			continue
		}
		row := byID[a.AgentID]
		res, status := customStatus(*def, a.OS, row, caps[a.AgentID], time.Now())
		item := map[string]any{"agent_id": a.AgentID, "hostname": a.Hostname, "os": a.OS, "data": res, "status": status}
		if row != nil {
			item["collected_at"] = row.CollectedAt
		}
		success, err := s.store.LastCustomSuccess(r.Context(), a.AgentID, def.SensorKind())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if success != nil {
			var historical proto.CustomSensorResult
			if json.Unmarshal(success.Data, &historical) == nil {
				item["last_success"] = map[string]any{"rows": historical.Rows, "collected_at": success.CollectedAt}
			}
		}
		out = append(out, item)
	}
	writeJSONResponse(w, customSensorResultsResponse{Sensor: def, Results: out})
}

func validateSensorDefinition(c *store.CustomSensor) error {
	if c.Platforms == nil {
		c.Platforms = map[string]proto.SensorPlatform{}
	}
	for os, cmd := range c.Commands {
		p := c.Platform(os)
		c.Platforms[os] = p
		if p.Language == "wql" {
			if err := validateWQL(cmd, p.Namespace); err != nil {
				return err
			}
		}
	}
	if c.MaxAgeSeconds < 0 || c.MaxAgeSeconds > 31536000 {
		return fmt.Errorf("maximum age must be 0 (automatic) or at most one year")
	}
	if err := deploy.ValidateParameters(c.Parameters); err != nil {
		return err
	}
	return sensoroutput.Validate(c.Fields, c.Platforms)
}
