package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
)

// "Rescan now" for the Patches page.
//
// The cached patch list is only as fresh as the patches sensor's interval
// (15 minutes by default), so an update published a minute ago did not
// appear until the next tick or an agent restart, and a collection that
// failed on the endpoint (a broken repository, `dnf check-update` exiting
// 1) was only in the endpoint's log: the host just dropped off the page.
//
// This uses the existing live "patches" query rather than new agent
// protocol: each targeted agent collects now and answers on its own result
// subject, the fresh lists are written to the same cache the sensor feeds,
// and the endpoints whose collection failed or that did not answer are
// returned with the reason.

const (
	// The agent gives a live patches query 30 seconds; a little over that
	// covers the round trip.
	patchRescanWait = 40 * time.Second
	patchRescanMax  = 500
)

type patchRescanRequest struct {
	AgentIDs []string `json:"agent_ids"`
}

type patchRescanProblem struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Error    string `json:"error"`
}

type patchRescanResponse struct {
	Asked      int                  `json:"asked"`
	Refreshed  int                  `json:"refreshed"`
	Failed     []patchRescanProblem `json:"failed"`
	NoResponse []patchRescanProblem `json:"no_response"`
	// Searching: endpoints still collecting; their list arrives later.
	Searching []patchRescanProblem `json:"searching"`
}

func (s *Server) handleRescanPatches(w http.ResponseWriter, r *http.Request) {
	var req patchRescanRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scope, err := s.endpointScope(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	wanted := map[string]bool{}
	for _, id := range req.AgentIDs {
		wanted[id] = true
	}
	hostnames := map[string]string{}
	var targets []string
	for _, a := range agents {
		hostnames[a.AgentID] = a.Hostname
		if !a.Online || (len(wanted) > 0 && !wanted[a.AgentID]) || (scope != nil && !scope[a.AgentID]) {
			continue
		}
		// Home Assistant OS has no package manager to scan; asking it can
		// only come back as a failure on every rescan.
		if patchUnsupportedReason(a) != "" && !(a.Platform == "haos" && !versionIsNewer(haosPatchesAgentVersion, a.AgentVersion)) {
			continue
		}
		targets = append(targets, a.AgentID)
	}
	if len(targets) == 0 {
		http.Error(w, "no online endpoint you manage to rescan (Home Assistant OS updates through Home Assistant, not patch scans)", http.StatusBadRequest)
		return
	}
	if len(targets) > patchRescanMax {
		http.Error(w, "too many endpoints for one rescan; select fewer", http.StatusBadRequest)
		return
	}

	// One query per endpoint, on the subject only that agent reads, so a
	// scoped operator's rescan never asks endpoints outside their scope.
	queries := make(map[string]*activeQuery, len(targets))
	resp := patchRescanResponse{Asked: len(targets), Failed: []patchRescanProblem{}, NoResponse: []patchRescanProblem{}, Searching: []patchRescanProblem{}}
	for _, id := range targets {
		aq, err := s.queryMgr.Start(proto.QueryKindPatches, nil, bnats.QAgent(id), 1)
		if err != nil {
			resp.Failed = append(resp.Failed, patchRescanProblem{AgentID: id, Hostname: hostnames[id], Error: "could not send the query"})
			continue
		}
		queries[id] = aq
	}
	deadline := time.Now().Add(patchRescanWait)
	for time.Now().Before(deadline) && !allAnswered(queries) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}

	ctx := context.WithoutCancel(r.Context())
	for _, id := range targets {
		aq, ok := queries[id]
		if !ok {
			continue
		}
		var result *proto.QueryResult
		snap := aq.snapshot()
		for i := range snap.Results {
			if snap.Results[i].AgentID == id {
				result = &snap.Results[i]
			}
		}
		switch {
		case result == nil:
			resp.NoResponse = append(resp.NoResponse, patchRescanProblem{AgentID: id, Hostname: hostnames[id],
				Error: "no answer within " + patchRescanWait.String()})
		case result.Pending:
			resp.Searching = append(resp.Searching, patchRescanProblem{AgentID: id, Hostname: hostnames[id],
				Error: safeTruncate(result.Error, 500)})
		case result.Error != "":
			resp.Failed = append(resp.Failed, patchRescanProblem{AgentID: id, Hostname: hostnames[id],
				Error: safeTruncate(result.Error, 500)})
			s.recordPatchStatus(ctx, id, proto.PatchStatus{Error: safeTruncate(result.Error, 2000), CheckedAt: time.Now().UTC()})
		default:
			if err := s.storeRescannedPatches(ctx, id, result.Patches); err != nil {
				s.logger.Warn("storing rescanned patches failed", "agent_id", id, "error", err)
				resp.Failed = append(resp.Failed, patchRescanProblem{AgentID: id, Hostname: hostnames[id],
					Error: "the result could not be stored"})
				continue
			}
			s.recordPatchStatus(ctx, id, proto.PatchStatus{OK: true, CheckedAt: time.Now().UTC()})
			resp.Refreshed++
		}
	}
	for _, list := range [][]patchRescanProblem{resp.Failed, resp.NoResponse, resp.Searching} {
		sort.Slice(list, func(i, j int) bool { return list[i].Hostname < list[j].Hostname })
	}
	s.audit(r.Context(), auditEvent{Action: "patches.rescan", Actor: auth.CurrentUser(r.Context()).Username,
		Target: "patch lists", Severity: "info",
		Detail: map[string]any{"asked": resp.Asked, "refreshed": resp.Refreshed, "failed": len(resp.Failed), "no_response": len(resp.NoResponse)}})
	writeJSONResponse(w, resp)
}

func allAnswered(queries map[string]*activeQuery) bool {
	for _, aq := range queries {
		aq.mu.Lock()
		n := len(aq.results)
		aq.mu.Unlock()
		if n == 0 {
			return false
		}
	}
	return true
}

// storeRescannedPatches writes a live result into the patches sensor
// cache through the same normalization and bookkeeping a periodic snapshot
// goes through.
func (s *Server) storeRescannedPatches(ctx context.Context, agentID string, patches []proto.PatchInfo) error {
	if patches == nil {
		patches = []proto.PatchInfo{}
	}
	raw, err := json.Marshal(patches)
	if err != nil {
		return err
	}
	data, err := normalizeSnapshotData(proto.SensorPatches, raw)
	if err != nil {
		return err
	}
	snap := proto.SensorSnapshot{AgentID: agentID, Sensor: proto.SensorPatches, Timestamp: time.Now().UTC(), Data: data}
	if err := s.store.UpsertSensorData(ctx, agentID, string(proto.SensorPatches), snap.Timestamp, snap.Data); err != nil {
		return err
	}
	s.recordPatchObservations(ctx, snap)
	return nil
}
