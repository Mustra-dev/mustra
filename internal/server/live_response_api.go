package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Live response: acting on one endpoint during an incident.
//
// Recorded as a deployment like everything else that touches an endpoint.
// Killing a process mid-incident is exactly the kind of action somebody
// asks about afterwards — "who stopped that, and when" — and answering it
// from a different place with a different shape is how an audit trail
// becomes several partial ones.

type killProcessRequest struct {
	PID int32 `json:"pid" api:"required"`
	// Name is what the console believed the process was called. Sent so the
	// agent can refuse if the PID has been recycled since it was observed.
	Name string `json:"name"`
}

// killProcessResponse is what POST /api/agents/{id}/kill-process answers.
type killProcessResponse struct {
	Message string `json:"message"`
	OK      bool   `json:"ok"`
	RunID   string `json:"run_id"`
}

func (s *Server) handleKillProcess(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	var req killProcessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PID <= 0 {
		http.Error(w, "a pid is required", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)

	who := auth.CurrentUser(r.Context()).Username
	// Resolved before anything is recorded. An unknown agent used to reach
	// the action insert, fail its foreign key, log a database error, and
	// then answer "the endpoint did not respond" — which is not what
	// happened: there is no such endpoint to respond.
	hostname := ""
	if agents, err := s.store.ListAgents(r.Context(), s.staleAfter()); err == nil {
		for _, a := range agents {
			if a.AgentID == agentID {
				hostname = a.Hostname
				break
			}
		}
	}
	if hostname == "" {
		http.Error(w, "no endpoint with that id is in inventory", http.StatusNotFound)
		return
	}
	// The expected name is what stops a recycled PID from being killed, so
	// it is always sent. A caller that did not supply one gets the name the
	// endpoint last reported for that PID; with neither, nothing is sent.
	if req.Name == "" {
		req.Name = s.cachedProcessName(r.Context(), agentID, req.PID)
	}
	if req.Name == "" {
		http.Error(w, "the process name is required, so the endpoint can refuse if the pid has been reused", http.StatusBadRequest)
		return
	}

	label := "Kill " + req.Name
	runID := idgen.New("run-")
	if err := s.store.RecordPatchJobRun(r.Context(), store.PatchJobRun{
		ID: runID, TargetDesc: "device: " + hostname, AgentCount: 1,
		ScheduleName: label, TriggeredBy: who,
	}); err != nil {
		s.logger.Warn("record kill run failed", "error", err)
	}
	actionID := idgen.New("act-")
	if err := s.store.StartAgentAction(r.Context(), store.AgentAction{
		ID: actionID, RunID: runID, AgentID: agentID, Kind: "live_response",
		Summary: label, RequestedBy: who,
	}); err != nil {
		s.logger.Warn("record kill action failed", "error", err)
	}

	// Logged before it is sent, matching Direct Connect: what was asked for
	// is worth recording even if the endpoint never answers.
	s.audit(r.Context(), auditEvent{
		Action: "live_response.kill", Actor: who, Target: hostname, Severity: "warning",
		Detail: map[string]any{"pid": req.PID, "process": req.Name, "run_id": runID},
	})

	payload, err := json.Marshal(proto.AgentCommand{
		Cmd: "kill_process", PID: req.PID, ProcessName: req.Name,
		RunID: runID, ActionID: actionID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(agentID), payload)
	if err != nil {
		_ = s.store.FinishAgentAction(r.Context(), agentID, actionID, "failed", "agent did not respond: "+err.Error())
		http.Error(w, "the endpoint did not respond: "+err.Error(), http.StatusGatewayTimeout)
		return
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &res); err != nil {
		_ = s.store.FinishAgentAction(r.Context(), agentID, actionID, "failed", "malformed response")
		http.Error(w, "malformed response from the endpoint", http.StatusBadGateway)
		return
	}
	if !res.OK {
		_ = s.store.FinishAgentAction(r.Context(), agentID, actionID, "failed", res.Error)
		http.Error(w, res.Error, http.StatusBadRequest)
		return
	}
	// Unlike a patch, this one really is finished when the agent says so:
	// a kill either happened or it did not.
	_ = s.store.FinishAgentAction(r.Context(), agentID, actionID, "succeeded", res.Output)
	s.logger.Warn("process killed", "host", hostname, "pid", req.PID, "by", who)
	writeJSONResponse(w, killProcessResponse{OK: true, RunID: runID, Message: res.Output})
}

// cachedProcessName looks a PID up in the endpoint's last processes
// snapshot, or returns "" when it is not there.
func (s *Server) cachedProcessName(ctx context.Context, agentID string, pid int32) string {
	rec, err := s.store.GetSensorData(ctx, agentID, string(proto.SensorProcesses))
	if err != nil || rec == nil {
		return ""
	}
	var procs []proto.ProcessInfo
	if json.Unmarshal(rec.Data, &procs) != nil {
		return ""
	}
	for _, p := range procs {
		if p.PID == pid {
			return strings.TrimSpace(p.Name)
		}
	}
	return ""
}
