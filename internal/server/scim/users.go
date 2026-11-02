package scim

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

func toUserResource(u store.User) userResource {
	r := userResource{
		Schemas:     []string{schemaUser},
		ID:          u.ID,
		ExternalID:  u.ExternalID,
		UserName:    u.Username,
		DisplayName: u.DisplayName,
		Active:      u.Active,
		Meta:        meta{ResourceType: "User", Created: u.CreatedAt, LastModified: u.UpdatedAt},
	}
	if u.DisplayName != "" {
		r.Name = &name{Formatted: u.DisplayName}
	}
	if u.Email != "" {
		r.Emails = []email{{Value: u.Email, Primary: true}}
	}
	return r
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	attr, value, hasFilter := parseEqFilter(r.URL.Query().Get("filter"))
	usernameFilter := ""
	if hasFilter && attr == "userName" {
		usernameFilter = value
	}
	startIndex, count := paginationParams(r)

	users, total, err := s.store.ListUsers(r.Context(), usernameFilter, startIndex-1, count)
	if err != nil {
		s.logger.Error("scim list users failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resources := make([]any, len(users))
	for i, u := range users {
		resources[i] = toUserResource(u)
	}
	writeJSON(w, http.StatusOK, listResponse{
		Schemas: []string{schemaListResponse}, TotalResults: total, StartIndex: startIndex, ItemsPerPage: len(resources), Resources: resources,
	})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req userResource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.UserName == "" {
		writeError(w, http.StatusBadRequest, "userName is required")
		return
	}

	// Authentik's SCIM provider checks existence with a filter GET before
	// creating; honor that here too so a create retried after a prior
	// partial failure doesn't error out on a duplicate username.
	if existing, _ := s.store.GetUserByUsername(r.Context(), req.UserName); existing != nil {
		// Only a SCIM account is handed back. A local account with the same
		// name stays invisible: returning it gave the IdP its id, and with
		// it the ability to PATCH or DELETE it.
		if existing.Source == "scim" && !existing.IsAdmin {
			writeJSON(w, http.StatusOK, toUserResource(*existing))
			return
		}
		writeError(w, http.StatusConflict, "userName is already taken by an account SCIM does not manage")
		return
	}

	email := ""
	if len(req.Emails) > 0 {
		email = req.Emails[0].Value
	}
	displayName := req.DisplayName
	if displayName == "" && req.Name != nil {
		displayName = req.Name.Formatted
	}
	// Real IdP provisioning clients (Authentik included) always send
	// "active" explicitly on create, so trusting Go's JSON zero-value here
	// (false if omitted) rather than defaulting to true is the safer
	// reading: an omitted-and-defaulted-true user would be created active
	// when the IdP may have meant the opposite.
	u, err := s.store.CreateSCIMUser(r.Context(), userID(), req.ExternalID, req.UserName, email, displayName, req.Active)
	if err != nil {
		s.logger.Error("scim create user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.logger.Info("scim user created", "username", u.Username, "external_id", u.ExternalID)
	writeJSON(w, http.StatusCreated, toUserResource(*u))
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.scimUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.logger.Error("scim get user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if u == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserResource(*u))
}

func (s *Server) handleReplaceUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMUser(w, r) {
		return
	}
	var req userResource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	email := ""
	if len(req.Emails) > 0 {
		email = req.Emails[0].Value
	}
	displayName := req.DisplayName
	if displayName == "" && req.Name != nil {
		displayName = req.Name.Formatted
	}
	u, err := s.store.ReplaceSCIMUser(r.Context(), r.PathValue("id"), req.UserName, email, displayName, req.Active)
	if err != nil {
		s.logger.Error("scim replace user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if u == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserResource(*u))
}

// handlePatchUser handles the SCIM PATCH shapes real IdP provisioning
// clients actually send for users: toggling "active" (deprovisioning) and
// replacing simple top-level attributes. See package doc for scope.
func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMUser(w, r) {
		return
	}
	var req patchOp
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")

	var lastUser *store.User
	for _, op := range req.Operations {
		switch op.Path {
		case "active":
			active, _ := op.Value.(bool)
			u, err := s.store.SetUserActive(r.Context(), id, active)
			if err != nil {
				s.logger.Error("scim patch user active failed", "error", err)
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if !active {
				// Deprovisioned at the IdP: signed out here too.
				_ = s.store.DeleteSessionsForUser(r.Context(), id)
			}
			lastUser = u
		default:
			// Unrecognized path (e.g. a nested emails[...] filter path) —
			// ignored rather than rejected, since IdPs commonly send a mix
			// of ops per sync and we don't want one unsupported op to fail
			// the whole provisioning run. See docs/ROADMAP.md.
			s.logger.Debug("scim patch user: unsupported path ignored", "path", op.Path)
		}
	}
	if lastUser == nil {
		u, err := s.store.GetUserByID(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		lastUser = u
	}
	if lastUser == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserResource(*lastUser))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMUser(w, r) {
		return
	}
	if err := s.store.DeleteUser(r.Context(), r.PathValue("id")); err != nil {
		s.logger.Error("scim delete user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func paginationParams(r *http.Request) (startIndex, count int) {
	startIndex = 1
	count = 100
	if v := r.URL.Query().Get("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			startIndex = n
		}
	}
	if v := r.URL.Query().Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			count = n
		}
	}
	if count > maxSCIMPage {
		count = maxSCIMPage
	}
	return startIndex, count
}

func userID() string { return idgen.New("usr-scim-") }
