package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// This file backs Scan Management: CRUD for named patch lists (repo
// definitions) and the rules assigning them to a slice of the fleet. Same
// patches.manage permission as the rest of the Patches tab — no new
// permission key, since scoping which repos a scan/apply uses is just
// another facet of managing patches.

// listPatchListsResponse is what GET /api/patches/lists answers.
type listPatchListsResponse struct {
	PatchLists []store.PatchList `json:"patch_lists"`
}

func (s *Server) handleListPatchLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.store.ListPatchLists(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listPatchListsResponse{PatchLists: lists})
}

type createPatchListRequest struct {
	Name        string `json:"name" api:"required"`
	OSFamily    string `json:"os_family" api:"required"`
	Repos       string `json:"repos"`
	Description string `json:"description,omitempty"`
}

// dnfRepoID is what a dnf/yum repository ID may hold: the agent passes
// each as --enablerepo=<id>.
var dnfRepoID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// validateRepoLines checks a list's repositories before any endpoint is
// pointed at them: apt lines are one-line sources.list entries, dnf
// entries are repo IDs already configured on the host. A list with none
// would change nothing, so it is refused rather than saved.
func validateRepoLines(family, raw string) error {
	lines := splitRepoLines(raw)
	if len(lines) == 0 {
		return fmt.Errorf("add at least one repository")
	}
	for _, l := range lines {
		switch family {
		case "apt":
			if !strings.HasPrefix(l, "deb ") && !strings.HasPrefix(l, "deb-src ") {
				return fmt.Errorf("%q is not a sources.list line: each starts with \"deb \" or \"deb-src \"", l)
			}
		case "dnf":
			if !dnfRepoID.MatchString(l) {
				return fmt.Errorf("%q is not a repository ID: one ID per line, as dnf repolist shows it", l)
			}
		}
	}
	return nil
}

func (s *Server) handleCreatePatchList(w http.ResponseWriter, r *http.Request) {
	var req createPatchListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.OSFamily != "apt" && req.OSFamily != "dnf" {
		http.Error(w, `os_family must be "apt" or "dnf"`, http.StatusBadRequest)
		return
	}
	if err := validateRepoLines(req.OSFamily, req.Repos); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	u := auth.CurrentUser(r.Context())
	pl, err := s.store.CreatePatchList(r.Context(), store.PatchList{
		ID: idgen.New("plist-"), Name: req.Name, OSFamily: req.OSFamily, Repos: strings.Join(splitRepoLines(req.Repos), "\n"),
		Description: strings.TrimSpace(req.Description), CreatedBy: u.Username,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "patches.repo_list.create", Actor: u.Username, Target: pl.Name, Severity: "notice",
		Detail: map[string]any{"id": pl.ID, "os_family": pl.OSFamily, "repos": splitRepoLines(pl.Repos)}})
	writeJSONResponse(w, pl)
}

func (s *Server) handleDeletePatchList(w http.ResponseWriter, r *http.Request) {
	pl, err := s.store.GetPatchList(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pl == nil {
		http.Error(w, "no such repository list", http.StatusNotFound)
		return
	}
	if err := s.store.DeletePatchList(r.Context(), pl.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Its assignments cascade: their endpoints go back to their own repos.
	s.audit(r.Context(), auditEvent{Action: "patches.repo_list.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: pl.Name, Severity: "notice",
		Detail: map[string]any{"id": pl.ID}})
	w.WriteHeader(http.StatusNoContent)
}

// listPatchListAssignmentsResponse is what GET
// /api/patches/list-assignments answers.
type listPatchListAssignmentsResponse struct {
	Assignments []store.PatchListAssignment `json:"assignments"`
}

func (s *Server) handleListPatchListAssignments(w http.ResponseWriter, r *http.Request) {
	assignments, err := s.store.ListPatchListAssignments(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listPatchListAssignmentsResponse{Assignments: assignments})
}

// createPatchListAssignmentRequest is the body of POST
// /api/patches/list-assignments. At least one target is required. An
// assignment naming an endpoint applies to that endpoint whatever else it
// names. A site and a platform combine: together they mean that
// platform's hosts at that site. When several assignments match a host,
// the most specific wins: one naming the endpoint, then site and platform,
// then site, then platform; within a rank, the most recent.
type createPatchListAssignmentRequest struct {
	PatchListID string `json:"patch_list_id" api:"required"`
	// TargetPlatform is the host's distro, such as "debian" or "rhel",
	// not its OS.
	TargetPlatform string `json:"target_platform,omitempty"`
	TargetSite     string `json:"target_site,omitempty"`
	// TargetAgent is an agent ID.
	TargetAgent string `json:"target_agent,omitempty"`
}

// patchListAssignmentMatches says whether an assignment's site and
// platform rule covers an endpoint, as ResolvePatchListForAgent reads it.
func patchListAssignmentMatches(b createPatchListAssignmentRequest, a store.AgentRecord) bool {
	if b.TargetAgent != "" {
		return a.AgentID == b.TargetAgent
	}
	if b.TargetSite == "" && b.TargetPlatform == "" {
		return false
	}
	return (b.TargetSite == "" || a.Site == b.TargetSite) && (b.TargetPlatform == "" || a.Platform == b.TargetPlatform)
}

func (s *Server) handleCreatePatchListAssignment(w http.ResponseWriter, r *http.Request) {
	var req createPatchListAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PatchListID == "" {
		http.Error(w, "patch_list_id is required", http.StatusBadRequest)
		return
	}
	if req.TargetPlatform == "" && req.TargetSite == "" && req.TargetAgent == "" {
		http.Error(w, "at least one of target_platform, target_site, or target_agent is required", http.StatusBadRequest)
		return
	}
	pl, err := s.store.GetPatchList(r.Context(), req.PatchListID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pl == nil {
		http.Error(w, "no such repository list", http.StatusBadRequest)
		return
	}
	if req.TargetAgent != "" {
		a := s.agentByID(r.Context(), req.TargetAgent)
		if a == nil {
			http.Error(w, "no such endpoint", http.StatusBadRequest)
			return
		}
		if a.OS != "" && a.OS != "linux" {
			http.Error(w, a.Hostname+" is not a Linux endpoint; a repository list applies only to apt and dnf hosts", http.StatusBadRequest)
			return
		}
	}

	u := auth.CurrentUser(r.Context())
	a, err := s.store.CreatePatchListAssignment(r.Context(), store.PatchListAssignment{
		ID: idgen.New("plassign-"), PatchListID: req.PatchListID, TargetPlatform: req.TargetPlatform,
		TargetSite: req.TargetSite, TargetAgent: req.TargetAgent, CreatedBy: u.Username,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "patches.repo_list.assign", Actor: u.Username, Target: pl.Name, AgentID: req.TargetAgent, Severity: "notice",
		Detail: map[string]any{"assignment_id": a.ID, "patch_list_id": pl.ID, "site": req.TargetSite, "platform": req.TargetPlatform}})
	writeJSONResponse(w, a)
}

func (s *Server) handleDeletePatchListAssignment(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetPatchListAssignment(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if a == nil {
		http.Error(w, "no such assignment", http.StatusNotFound)
		return
	}
	if err := s.store.DeletePatchListAssignment(r.Context(), a.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "patches.repo_list.unassign", Actor: auth.CurrentUser(r.Context()).Username, Target: a.PatchListName, AgentID: a.TargetAgent, Severity: "notice",
		Detail: map[string]any{"assignment_id": a.ID, "patch_list_id": a.PatchListID, "site": a.TargetSite, "platform": a.TargetPlatform}})
	w.WriteHeader(http.StatusNoContent)
}
