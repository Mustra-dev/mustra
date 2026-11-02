package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/mustra-dev/mustra/internal/deploylog"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

func (s *Server) handleActionLogSensor(w http.ResponseWriter, r *http.Request) {
	record, e := s.store.GetDeployJob(r.Context(), r.PathValue("job"))
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if record == nil {
		http.NotFound(w, r)
		return
	}
	if s.nc == nil {
		http.Error(w, "endpoint connection unavailable", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
	defer cancel()
	raw, _ := json.Marshal(proto.AgentCommand{Cmd: "action_logs", ActionID: record.Job.ID})
	msg, e := s.nc.RequestWithContext(ctx, bnats.Cmd(record.Job.AgentID), raw)
	if e != nil {
		http.Error(w, "Endpoint did not respond; use retained server logs or retry when it is online", 504)
		return
	}
	var result proto.AgentCommandResult
	if json.Unmarshal(msg.Data, &result) != nil || !result.OK {
		http.Error(w, "Endpoint log sensor unavailable: "+result.Error, 502)
		return
	}
	for _, event := range result.ActionLogs {
		if event.JobID != record.Job.ID || event.AgentID != record.Job.AgentID || event.RunID != record.Job.RunID {
			http.Error(w, "endpoint returned mismatched log evidence", 502)
			return
		}
	}
	writeJSONResponse(w, deploylog.Result{Events: result.ActionLogs, Truncated: result.LogsTruncated})
}
