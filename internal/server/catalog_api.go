package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The requests half of Self Service. What the window on someone's machine
// offers is the software packages published to it (self_service on the
// package, edited in the Deploy package editor); a package scoped to
// computer groups can still let a machine outside them ask, and these
// routes are where an operator answers.

func (s *Server) handleListCatalogRequests(w http.ResponseWriter, r *http.Request) {
	reqs, err := s.store.ListCatalogRequests(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if reqs == nil {
		reqs = []store.CatalogRequest{}
	}
	writeJSONResponse(w, reqs)
}

// decideCatalogRequestRequest is the body of POST /api/catalog/requests/{id}/decide.
type decideCatalogRequestRequest struct {
	Status string `json:"status" api:"required"`
}

// decideCatalogRequestResponse is what POST
// /api/catalog/requests/{id}/decide answers.
type decideCatalogRequestResponse struct {
	Status string `json:"status"`
}

// handleDecideCatalogRequest approves or denies one pending request: 404
// for an unknown one, 409 for one already decided. Approval grants that one
// device that one item — it does not move the machine into a group, so the
// grant stays visible as a request rather than quietly widening a group's
// membership.
func (s *Server) handleDecideCatalogRequest(w http.ResponseWriter, r *http.Request) {
	var body decideCatalogRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.Status != "approved" && body.Status != "denied" {
		http.Error(w, `status must be "approved" or "denied"`, http.StatusBadRequest)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	req, err := s.store.DecideCatalogRequest(r.Context(), r.PathValue("id"), body.Status, who)
	switch {
	case errors.Is(err, store.ErrNoSuchCatalogRequest):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case errors.Is(err, store.ErrCatalogRequestDecided):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// An approval entitles the endpoint to install the package.
	s.audit(r.Context(), auditEvent{
		Action: "catalog_request." + body.Status, Actor: who, Target: req.ItemName, AgentID: req.AgentID, Severity: "notice",
		Detail: map[string]any{"request_id": req.ID, "item_id": req.ItemID, "hostname": req.Hostname, "requested_by": req.RequestedBy},
	})
	writeJSONResponse(w, decideCatalogRequestResponse{Status: body.Status})
}
