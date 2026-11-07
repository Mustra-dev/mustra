package server

import (
	"cmp"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Containers: the containers sensor across the fleet, what needs attention
// first. It only reports. mustra does not pull images or recreate containers:
// an unattended image update is how a working service breaks overnight, so
// the decision stays with whoever reads this.

// containerRow is a container and the endpoint it runs on.
type containerRow struct {
	proto.ContainerInfo
	AgentID     string `json:"agent_id"`
	Hostname    string `json:"hostname"`
	Online      bool   `json:"online"`
	CollectedAt string `json:"collected_at"`
}

// containersResponse is what GET /api/containers answers. Counts and Hosts
// cover the rows answered, so a filtered request counts only its filter.
type containersResponse struct {
	Containers []containerRow `json:"containers"`
	Counts     map[string]int `json:"counts"`
	Hosts      int            `json:"hosts"`
}

var containerUpdateRank = map[string]int{
	proto.ContainerUpdateAvailable: 0,
	proto.ContainerCheckFailed:     1,
	proto.ContainerNotChecked:      2,
	proto.ContainerUpToDate:        3,
}

func (s *Server) handleContainers(w http.ResponseWriter, r *http.Request) {
	update := r.URL.Query().Get("update")
	if _, known := containerUpdateRank[update]; update != "" && !known {
		http.Error(w, "unknown update status", http.StatusBadRequest)
		return
	}
	rows, err := s.store.ListSensorDataForSensor(r.Context(), string(proto.SensorContainers))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hostnames, online := map[string]string{}, map[string]bool{}
	for _, a := range agents {
		hostnames[a.AgentID], online[a.AgentID] = a.Hostname, a.Online
	}
	only := r.URL.Query().Get("agent_id")
	resp := containersResponse{Containers: []containerRow{}, Counts: map[string]int{}}
	hosts := map[string]bool{}
	for _, row := range rows {
		hostname, enrolled := hostnames[row.AgentID]
		if !enrolled || (only != "" && row.AgentID != only) {
			continue
		}
		var list []proto.ContainerInfo
		if err := json.Unmarshal(row.Data, &list); err != nil {
			s.logger.Warn("container snapshot not usable", "agent_id", row.AgentID, "error", err)
			continue
		}
		for _, c := range list {
			// Nothing but a verified answer may read as a conclusion.
			if _, known := containerUpdateRank[c.Update]; !known {
				c.Update = proto.ContainerNotChecked
			}
			if update != "" && c.Update != update {
				continue
			}
			resp.Counts[c.Update]++
			hosts[row.AgentID] = true
			resp.Containers = append(resp.Containers, containerRow{
				ContainerInfo: c, AgentID: row.AgentID, Hostname: hostname, Online: online[row.AgentID],
				CollectedAt: row.CollectedAt.UTC().Format(time.RFC3339),
			})
		}
	}
	resp.Hosts = len(hosts)
	slices.SortStableFunc(resp.Containers, func(a, b containerRow) int {
		return cmp.Or(
			cmp.Compare(containerUpdateRank[a.Update], containerUpdateRank[b.Update]),
			cmp.Compare(a.Hostname, b.Hostname),
			cmp.Compare(a.Name, b.Name),
		)
	})
	writeJSONResponse(w, resp)
}
