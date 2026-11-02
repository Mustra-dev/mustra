package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// --- watchlists ------------------------------------------------------------

// listWatchlistsResponse is what GET /api/watchlists answers.
type listWatchlistsResponse struct {
	Templates  []watchTemplate   `json:"templates"`
	Watchlists []store.Watchlist `json:"watchlists"`
}

func (s *Server) handleListWatchlists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.store.ListWatchlists(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listWatchlistsResponse{Watchlists: lists, Templates: watchTemplates})
}

func cleanPaths(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func (s *Server) handleSaveWatchlist(w http.ResponseWriter, r *http.Request) {
	var in store.Watchlist
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	in.Paths = cleanPaths(in.Paths)
	in.RegistryKeys = cleanPaths(in.RegistryKeys)
	for _, p := range in.Paths {
		if !strings.HasPrefix(p, "/") && !(len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) {
			http.Error(w, "path must be absolute: "+p, http.StatusBadRequest)
			return
		}
	}
	for _, k := range in.RegistryKeys {
		u := strings.ToUpper(k)
		if !strings.HasPrefix(u, "HKLM\\") && !strings.HasPrefix(u, "HKEY_LOCAL_MACHINE\\") && !strings.HasPrefix(u, "HKCU\\") && !strings.HasPrefix(u, "HKU\\") && !strings.HasPrefix(u, "HKCR\\") {
			http.Error(w, "registry key must start with HKLM\\, HKCU\\, HKU\\ or HKCR\\: "+k, http.StatusBadRequest)
			return
		}
	}
	if len(in.Paths)+len(in.RegistryKeys) == 0 {
		http.Error(w, "a watchlist needs at least one path or registry key", http.StatusBadRequest)
		return
	}
	if len(in.Paths) > 500 || len(in.RegistryKeys) > 200 {
		http.Error(w, "a watchlist holds at most 500 paths and 200 registry keys", http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetWatchlist(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such watchlist", http.StatusNotFound)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		in.ID, in.CreatedBy = idgen.New("wl-"), u.Username
	}
	if err := s.store.UpsertWatchlist(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "watchlist.save", Actor: u.Username, Target: in.Name, Severity: "notice", Detail: map[string]any{"id": in.ID, "paths": len(in.Paths), "registry_keys": len(in.RegistryKeys), "template": in.Template}})
	s.invalidateWatchRoots()
	go s.applyWatchSets(context.WithoutCancel(r.Context()))
	// The save has happened: say so if the answer cannot show it, rather
	// than answer 200 with null.
	out, err := s.store.GetWatchlist(r.Context(), in.ID)
	if err == nil && out == nil {
		err = fmt.Errorf("it was deleted meanwhile")
	}
	if err != nil {
		http.Error(w, "saved, but could not read it back: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteWatchlist(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetWatchlist(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such watchlist", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteWatchlist(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "watchlist.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	s.invalidateWatchRoots()
	go s.applyWatchSets(context.WithoutCancel(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}

// --- monitors --------------------------------------------------------------

// listIntegrityMonitorsResponse is what GET /api/integrity/monitors
// answers.
type listIntegrityMonitorsResponse struct {
	Monitors []store.IntegrityMonitor `json:"monitors"`
}

func (s *Server) handleListIntegrityMonitors(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListIntegrityMonitors(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listIntegrityMonitorsResponse{Monitors: list})
}

func (s *Server) handleSaveIntegrityMonitor(w http.ResponseWriter, r *http.Request) {
	var in store.IntegrityMonitor
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	wl, err := s.store.GetWatchlist(r.Context(), in.WatchlistID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if wl == nil {
		http.Error(w, "pick a watchlist", http.StatusBadRequest)
		return
	}
	in.GroupIDs = cleanPaths(in.GroupIDs)
	if len(in.GroupIDs) == 0 {
		http.Error(w, "a monitor applies to at least one computer group", http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetIntegrityMonitor(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such monitor", http.StatusNotFound)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		in.ID, in.CreatedBy, in.Enabled = idgen.New("mon-"), u.Username, true
	}
	if err := s.store.UpsertIntegrityMonitor(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "integrity_monitor.save", Actor: u.Username, Target: in.Name, Severity: "notice", Detail: map[string]any{"id": in.ID, "watchlist": wl.Name, "groups": len(in.GroupIDs), "enabled": in.Enabled}})
	s.invalidateWatchRoots()
	go s.applyWatchSets(context.WithoutCancel(r.Context()))
	out, _ := s.store.GetIntegrityMonitor(r.Context(), in.ID)
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteIntegrityMonitor(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetIntegrityMonitor(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such monitor", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteIntegrityMonitor(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "integrity_monitor.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	s.invalidateWatchRoots()
	go s.applyWatchSets(context.WithoutCancel(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}

// watchStatusResponse is what GET /api/integrity/watch-status answers.
type watchStatusResponse struct {
	Applied      int              `json:"applied"`
	Endpoints    []watchStatusRow `json:"endpoints"`
	Monitored    int              `json:"monitored"`
	NeedsUpgrade int              `json:"needs_upgrade"`
	Total        int              `json:"total"`
}

// GET /api/integrity/watch-status; POST /api/integrity/watch-status/apply
func (s *Server) handleWatchStatus(w http.ResponseWriter, r *http.Request) {
	rows, err := s.watchStatus(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	monitored, applied, upgrade := 0, 0, 0
	for _, row := range rows {
		if row.WantRevision != "" {
			monitored++
			if row.Applied {
				applied++
			}
			if row.NeedsUpgrade {
				upgrade++
			}
		}
	}
	writeJSONResponse(w, watchStatusResponse{Endpoints: rows, Total: len(rows), Monitored: monitored, Applied: applied, NeedsUpgrade: upgrade})
}

// watchApplyResponse is what POST /api/integrity/watch-status/apply
// answers.
type watchApplyResponse struct {
	Failed map[string]string `json:"failed"`
	Pushed int               `json:"pushed"`
}

func (s *Server) handleWatchApply(w http.ResponseWriter, r *http.Request) {
	pushed, failed := s.applyWatchSets(r.Context())
	writeJSONResponse(w, watchApplyResponse{Pushed: pushed, Failed: failed})
}

// --- labels ----------------------------------------------------------------

// listIntegrityLabelsResponse is what GET /api/integrity/labels answers.
type listIntegrityLabelsResponse struct {
	Labels []store.IntegrityLabel `json:"labels"`
}

func (s *Server) handleListIntegrityLabels(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListIntegrityLabels(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listIntegrityLabelsResponse{Labels: list})
}

func (s *Server) handleSaveIntegrityLabel(w http.ResponseWriter, r *http.Request) {
	var in store.IntegrityLabel
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	var crit labelCriteria
	if err := json.Unmarshal(in.Criteria, &crit); err != nil {
		http.Error(w, "criteria is not valid JSON", http.StatusBadRequest)
		return
	}
	if crit.PathPrefix == "" && crit.PathSuffix == "" && crit.PathContains == "" && len(crit.Kinds) == 0 && len(crit.GroupIDs) == 0 &&
		len(crit.Weekdays) == 0 && crit.Start == "" && !crit.DuringMaintenance && crit.Process == "" && crit.User == "" {
		http.Error(w, "a label needs at least one criterion, or it would match every change", http.StatusBadRequest)
		return
	}
	if (crit.Start == "") != (crit.End == "") || (crit.Start != "" && (hhmm(crit.Start) < 0 || hhmm(crit.End) < 0)) {
		http.Error(w, "a time window needs both start and end as HH:MM", http.StatusBadRequest)
		return
	}
	if crit.Timezone != "" {
		if _, err := time.LoadLocation(crit.Timezone); err != nil {
			http.Error(w, "unknown timezone: "+crit.Timezone, http.StatusBadRequest)
			return
		}
	}
	u := auth.CurrentUser(r.Context())
	if id := r.PathValue("id"); id != "" {
		existing, err := s.store.GetIntegrityLabel(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such label", http.StatusNotFound)
			return
		}
		in.ID, in.CreatedBy = existing.ID, existing.CreatedBy
	} else {
		in.ID, in.CreatedBy, in.Enabled = idgen.New("lbl-"), u.Username, true
	}
	if err := s.store.UpsertIntegrityLabel(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateLabels()
	s.audit(r.Context(), auditEvent{Action: "integrity_label.save", Actor: u.Username, Target: in.Name, Severity: "notice", Detail: map[string]any{"id": in.ID, "expected": in.Expected}})
	out, _ := s.store.GetIntegrityLabel(r.Context(), in.ID)
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteIntegrityLabel(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetIntegrityLabel(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such label", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteIntegrityLabel(r.Context(), existing.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateLabels()
	s.audit(r.Context(), auditEvent{Action: "integrity_label.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: existing.Name, Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

// testIntegrityLabelResponse is what POST /api/integrity/labels/test
// answers.
type testIntegrityLabelResponse struct {
	Matched int                     `json:"matched"`
	Of      int                     `json:"of"`
	Sample  []store.IntegrityChange `json:"sample"`
}

// POST /api/integrity/labels/test — which recent changes a label would
// match, before it is saved.
func (s *Server) handleTestIntegrityLabel(w http.ResponseWriter, r *http.Request) {
	var in store.IntegrityLabel
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	var crit labelCriteria
	if err := json.Unmarshal(in.Criteria, &crit); err != nil {
		http.Error(w, "criteria is not valid JSON", http.StatusBadRequest)
		return
	}
	cl := compiledLabel{IntegrityLabel: in, crit: crit}
	if len(crit.GroupIDs) > 0 {
		m, err := s.agentsInGroups(r.Context(), crit.GroupIDs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if m == nil {
			m = map[string]bool{}
		}
		cl.members = m
	}
	changes, err := s.store.ListIntegrityChanges(r.Context(), 500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	matched := 0
	var sample []store.IntegrityChange
	for _, c := range changes {
		if s.labelMatches(r.Context(), cl, c.AgentID, c.Path, c.Kind, c.DetectedAt) {
			matched++
			if len(sample) < 10 {
				sample = append(sample, c)
			}
		}
	}
	if sample == nil {
		sample = []store.IntegrityChange{}
	}
	writeJSONResponse(w, testIntegrityLabelResponse{Matched: matched, Of: len(changes), Sample: sample})
}

// ackIntegrityChangeResponse is what POST /api/integrity/changes/{id}/ack
// answers.
type ackIntegrityChangeResponse struct {
	Acknowledged bool `json:"acknowledged"`
}

// POST /api/integrity/changes/{id}/ack
func (s *Server) handleAckIntegrityChange(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	ok, err := s.store.AcknowledgeIntegrityChange(r.Context(), id, auth.CurrentUser(r.Context()).Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, ackIntegrityChangeResponse{Acknowledged: ok})
}
