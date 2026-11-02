package scim

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	attr, value, hasFilter := parseEqFilter(r.URL.Query().Get("filter"))
	nameFilter := ""
	if hasFilter && attr == "displayName" {
		nameFilter = value
	}
	startIndex, count := paginationParams(r)

	groups, total, err := s.store.ListGroups(r.Context(), nameFilter, startIndex-1, count)
	if err != nil {
		s.logger.Error("scim list groups failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resources := make([]any, 0, len(groups))
	for _, g := range groups {
		if g.SCIMManaged {
			resources = append(resources, groupToResource(g))
		}
	}
	writeJSON(w, http.StatusOK, listResponse{
		Schemas: []string{schemaListResponse}, TotalResults: total, StartIndex: startIndex, ItemsPerPage: len(resources), Resources: resources,
	})
}

func groupToResource(g store.Group) groupResource {
	r := groupResource{
		Schemas:     []string{schemaGroup},
		ID:          g.ID,
		ExternalID:  g.ExternalID,
		DisplayName: g.DisplayName,
		Meta:        meta{ResourceType: "Group", Created: g.CreatedAt, LastModified: g.UpdatedAt},
	}
	for _, uid := range g.MemberIDs {
		r.Members = append(r.Members, groupMember{Value: uid})
	}
	return r
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req groupResource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "displayName is required")
		return
	}

	existing, _, _ := s.store.ListGroups(r.Context(), req.DisplayName, 0, 1)
	if len(existing) == 1 {
		g := existing[0]
		if !g.SCIMManaged {
			writeError(w, http.StatusConflict, "displayName is already taken by a group SCIM does not manage")
			return
		}
		writeJSON(w, http.StatusOK, groupToResource(g))
		return
	}

	g, err := s.store.CreateGroup(r.Context(), idgen.New("grp-"), req.ExternalID, req.DisplayName)
	if err == nil {
		err = s.store.MarkGroupSCIMManaged(r.Context(), g.ID)
	}
	if err != nil {
		s.logger.Error("scim create group failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var initial []string
	for _, m := range req.Members {
		initial = append(initial, m.Value)
	}
	for _, uid := range s.scimMembers(r.Context(), initial) {
		if err := s.store.AddGroupMember(r.Context(), g.ID, uid); err != nil {
			s.logger.Warn("scim add initial group member failed", "error", err, "group_id", g.ID, "user_id", uid)
		}
	}
	g.MemberIDs, _ = s.store.ListGroupMemberIDs(r.Context(), g.ID)
	s.logger.Info("scim group created", "display_name", g.DisplayName, "external_id", g.ExternalID)
	writeJSON(w, http.StatusCreated, groupToResource(*g))
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.scimGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		s.logger.Error("scim get group failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if g == nil {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	writeJSON(w, http.StatusOK, groupToResource(*g))
}

func (s *Server) handleReplaceGroup(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMGroup(w, r) {
		return
	}
	var req groupResource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")
	g, err := s.store.RenameGroup(r.Context(), id, req.DisplayName)
	if err != nil {
		s.logger.Error("scim replace group failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if g == nil {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	var memberIDs []string
	for _, m := range req.Members {
		memberIDs = append(memberIDs, m.Value)
	}
	memberIDs = s.scimMembers(r.Context(), memberIDs)
	if err := s.store.ReplaceGroupMembers(r.Context(), id, memberIDs); err != nil {
		s.logger.Error("scim replace group members failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	g.MemberIDs = memberIDs
	writeJSON(w, http.StatusOK, groupToResource(*g))
}

var memberRemoveFilterRE = regexp.MustCompile(`(?i)^members\[value eq "([^"]+)"\]$`)

// handlePatchGroup handles what real IdP group-sync clients send:
// {"op":"add","path":"members","value":[{"value":"<user-id>"}, ...]} and
// {"op":"remove","path":"members[value eq \"<user-id>\"]"} (a single
// member's removal, addressed via a filter expression in the path itself —
// the one SCIM PATCH path-filter shape implemented here).
func (s *Server) handlePatchGroup(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMGroup(w, r) {
		return
	}
	var req patchOp
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")

	for _, op := range req.Operations {
		switch {
		case op.Path == "members" && op.Op == "add":
			for _, uid := range s.scimMembers(r.Context(), extractMemberValues(op.Value)) {
				if err := s.store.AddGroupMember(r.Context(), id, uid); err != nil {
					s.logger.Error("scim add group member failed", "error", err)
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
			}
		case op.Path == "members" && op.Op == "remove":
			for _, uid := range extractMemberValues(op.Value) {
				if err := s.store.RemoveGroupMember(r.Context(), id, uid); err != nil {
					s.logger.Error("scim remove group member failed", "error", err)
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
			}
		case op.Op == "remove":
			if m := memberRemoveFilterRE.FindStringSubmatch(op.Path); m != nil {
				if err := s.store.RemoveGroupMember(r.Context(), id, m[1]); err != nil {
					s.logger.Error("scim remove group member (filter path) failed", "error", err)
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
			} else {
				s.logger.Debug("scim patch group: unsupported path ignored", "path", op.Path)
			}
		case op.Path == "displayName":
			if name, ok := op.Value.(string); ok {
				if _, err := s.store.RenameGroup(r.Context(), id, name); err != nil {
					s.logger.Error("scim rename group failed", "error", err)
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
			}
		default:
			s.logger.Debug("scim patch group: unsupported op ignored", "op", op.Op, "path", op.Path)
		}
	}

	g, err := s.store.GetGroup(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if g == nil {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	writeJSON(w, http.StatusOK, groupToResource(*g))
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMGroup(w, r) {
		return
	}
	if err := s.store.DeleteGroup(r.Context(), r.PathValue("id")); err != nil {
		s.logger.Error("scim delete group failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// extractMemberValues pulls user IDs out of a PATCH op's value, which per
// spec is an array of {"value": "<id>"} objects but arrives here as
// unmarshaled JSON (any), so it needs a type-switch rather than a struct.
func extractMemberValues(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := obj["value"].(string); ok && id != "" {
			out = append(out, id)
		}
	}
	return out
}
