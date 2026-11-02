package server

import (
	"net/http"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Removing an endpoint from inventory.
//
// This is bookkeeping, not an action on the machine: it deletes the row and
// its sensor history, and does nothing to the endpoint itself. An agent that
// is still installed and running will register again on its next heartbeat,
// which is the correct outcome — the console should not be able to make a
// managed machine invisible by forgetting about it.
//
// It exists because uninstalling the agent leaves the row behind. The
// endpoint stops reporting and sits in the list until offline expiry, and a
// machine that gets the agent reinstalled comes back with a new identity, so
// the same hostname appears twice — once dead, once alive. Decommissioned
// hardware and rebuilt VMs have the same shape.
func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "agent id is required", http.StatusBadRequest)
		return
	}

	// Read it first, so the audit entry can name the machine rather than
	// only its id -- an id means nothing to whoever reads the log later.
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hostname, found := "", false
	for i := range agents {
		if agents[i].AgentID == id {
			hostname, found = agents[i].Hostname, true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	if err := s.store.DeleteAgent(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.audit(r.Context(), auditEvent{
		Action: "agent.remove", Actor: auth.CurrentUser(r.Context()).Username,
		Target: hostname, Severity: "warning",
		Detail: map[string]any{"agent_id": id, "note": "removed from inventory; the endpoint itself was not changed"},
	})
	s.logger.Info("endpoint removed from inventory", "hostname", hostname, "agent_id", id,
		"actor", auth.CurrentUser(r.Context()).Username)
	w.WriteHeader(http.StatusNoContent)
}
