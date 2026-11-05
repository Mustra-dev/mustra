package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

var iocKinds = map[string]bool{
	store.IOCFileHash:    true,
	store.IOCFilePath:    true,
	store.IOCProcessName: true,
	store.IOCIPAddress:   true,
	store.IOCAppName:     true,
}

// listIOCsResponse is what GET /api/hunt/iocs answers.
type listIOCsResponse struct {
	IOCs []store.IOC `json:"iocs"`
}

func (s *Server) handleListIOCs(w http.ResponseWriter, r *http.Request) {
	iocs, err := s.store.ListIOCs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if iocs == nil {
		iocs = []store.IOC{}
	}
	writeJSONResponse(w, listIOCsResponse{IOCs: iocs})
}

// upsertIOCRequest is the body of POST /api/hunt/iocs and PUT
// /api/hunt/iocs/{id}. A PUT replaces the whole indicator: a field it
// leaves out takes its empty value, and enabled left out switches the
// indicator off. Send every field, as read from GET /api/hunt/iocs.
type upsertIOCRequest struct {
	store.IOC
	// Enabled is true when a create leaves it out: an indicator is added
	// to be hunted for. On a PUT, left out is false.
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleUpsertIOC(w http.ResponseWriter, r *http.Request) {
	var req upsertIOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body := req.IOC
	body.Enabled = req.Enabled != nil && *req.Enabled
	body.Name = strings.TrimSpace(body.Name)
	body.Value = strings.TrimSpace(body.Value)
	if body.Name == "" || body.Value == "" {
		http.Error(w, "a name and a value are required", http.StatusBadRequest)
		return
	}
	if !iocKinds[body.Kind] {
		http.Error(w, "kind must be one of: file_hash, file_path, process_name, ip, app_name",
			http.StatusBadRequest)
		return
	}
	switch body.Severity {
	case "info", "warning", "critical":
	default:
		body.Severity = "warning"
	}
	// A SHA-256 is 64 hex characters. Catching a truncated paste here beats
	// a hunt that quietly matches nothing forever and reads as "all clear".
	if body.Kind == store.IOCFileHash {
		body.Value = strings.ToLower(body.Value)
		if len(body.Value) != 64 || strings.TrimLeft(body.Value, "0123456789abcdef") != "" {
			http.Error(w, "a file hash must be a 64-character SHA-256 — mustra's integrity sensor hashes with SHA-256, so nothing else can ever match",
				http.StatusBadRequest)
			return
		}
	}

	if id := r.PathValue("id"); id != "" {
		body.ID = id
	}
	if body.ID == "" {
		body.ID = idgen.New("ioc-")
		body.CreatedBy = auth.CurrentUser(r.Context()).Username
		if req.Enabled == nil {
			body.Enabled = true
		}
	}

	out, err := s.store.UpsertIOC(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "hunt.ioc.save", Actor: auth.CurrentUser(r.Context()).Username,
		Target: out.Name, Severity: "notice",
		Detail: map[string]any{"kind": out.Kind, "severity": out.Severity},
	})
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteIOC(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteIOC(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listIOCFindingsResponse is what GET /api/hunt/findings answers.
type listIOCFindingsResponse struct {
	Findings    []store.IOCFinding `json:"findings"`
	Outstanding int                `json:"outstanding"`
}

func (s *Server) handleListIOCFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.store.ListIOCFindings(r.Context(), 500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if findings == nil {
		findings = []store.IOCFinding{}
	}
	outstanding := 0
	for _, f := range findings {
		if !f.Acknowledged {
			outstanding++
		}
	}
	writeJSONResponse(w, listIOCFindingsResponse{Findings: findings, Outstanding: outstanding})
}

// ackIOCFindingRequest is the body of POST /api/hunt/findings/{id}/ack.
type ackIOCFindingRequest struct {
	// Acknowledged is true when left out, or with no body at all: the
	// route acknowledges. False re-opens the finding. A body that is not
	// valid JSON is refused. The same as a signal finding's ack.
	Acknowledged *bool `json:"acknowledged"`
}

func (s *Server) handleAckIOCFinding(w http.ResponseWriter, r *http.Request) {
	var body ackIOCFindingRequest
	// No body at all acknowledges; one that cannot be read is refused
	// rather than taken as the same.
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ack := true
	if body.Acknowledged != nil {
		ack = *body.Acknowledged
	}
	if err := s.store.AcknowledgeIOCFinding(r.Context(), r.PathValue("id"), ack); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// runHuntResponse is what POST /api/hunt/run answers.
type runHuntResponse struct {
	NewFindings int `json:"new_findings"`
}

// handleRunHunt evaluates every indicator now rather than waiting for the
// timer — what you press after adding an indicator, when the question is
// "is it here already".
func (s *Server) handleRunHunt(w http.ResponseWriter, r *http.Request) {
	found := s.runHunt(context.WithoutCancel(r.Context()))
	s.announceHunt(found)
	s.audit(r.Context(), auditEvent{
		Action: "hunt.run", Actor: auth.CurrentUser(r.Context()).Username,
		Target: "fleet", Severity: "notice", Detail: map[string]any{"new_findings": found},
	})
	writeJSONResponse(w, runHuntResponse{NewFindings: found})
}
