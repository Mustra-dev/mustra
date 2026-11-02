package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// This file backs the admin Users/Groups/Roles tab: viewing and managing
// accounts, local security groups, and the roles tying permissions to
// either a group or a user directly. Every route here is gated behind
// PermUsersManage (see httpapi.go's route registration) — see
// docs/ARCHITECTURE.md for why permissions themselves stay a fixed,
// code-defined set rather than admin-creatable resources: it's roles that
// are open-ended and admin-manageable, not the underlying permission keys
// they're built from.

// --- Users ---

// minLocalPasswordLen is the shortest password a local account may have.
const minLocalPasswordLen = 12

type adminUserView struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Source      string    `json:"source"`
	IsAdmin     bool      `json:"is_admin"`
	Active      bool      `json:"active"`
	RoleIDs     []string  `json:"role_ids"`
	GroupIDs    []string  `json:"group_ids"`
	CreatedAt   time.Time `json:"created_at"`
	// MFAEnabled: a local account that signs in with an authenticator
	// code as well as its password.
	MFAEnabled bool `json:"mfa_enabled"`
}

func (s *Server) buildAdminUserView(r *http.Request, u store.User) (adminUserView, error) {
	roleIDs, err := s.store.ListUserRoleIDs(r.Context(), u.ID)
	if err != nil {
		return adminUserView{}, err
	}
	groupIDs, err := s.store.ListUserGroupIDs(r.Context(), u.ID)
	if err != nil {
		return adminUserView{}, err
	}
	totp, err := s.store.GetUserTOTP(r.Context(), u.ID)
	if err != nil {
		return adminUserView{}, err
	}
	return adminUserView{
		ID: u.ID, Username: u.Username, Email: u.Email, DisplayName: u.DisplayName,
		Source: u.Source, IsAdmin: u.IsAdmin, Active: u.Active,
		RoleIDs: nonNil(roleIDs), GroupIDs: nonNil(groupIDs), CreatedAt: u.CreatedAt,
		MFAEnabled: totp != nil && totp.Enabled(),
	}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// listUsersResponse is what GET /api/admin/users answers.
type listUsersResponse struct {
	Users []adminUserView `json:"users"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListAllUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]adminUserView, 0, len(users))
	for _, u := range users {
		v, err := s.buildAdminUserView(r, u)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		views = append(views, v)
	}
	writeJSONResponse(w, listUsersResponse{Users: views})
}

type createLocalUserRequest struct {
	Username    string `json:"username" api:"required"`
	Password    string `json:"password" api:"required,writeonly"`
	DisplayName string `json:"display_name"`
}

func (s *Server) handleCreateLocalUser(w http.ResponseWriter, r *http.Request) {
	var req createLocalUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}
	if len(req.Password) < minLocalPasswordLen {
		http.Error(w, fmt.Sprintf("a local password must be at least %d characters", minLocalPasswordLen), http.StatusBadRequest)
		return
	}
	if !s.auditIdentity(w, r, "users.create", req.Username, map[string]any{"source": "local"}) {
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}
	user, err := s.store.CreateLocalUser(r.Context(), idgen.New("usr-"), req.Username, hash, displayName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v, err := s.buildAdminUserView(r, *user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, v)
}

// setActiveRequest is the body of POST /api/admin/users/{id}/active.
type setActiveRequest struct {
	// Active is required. A body without it is refused rather than read
	// as false, which would deactivate the user and sign them out.
	Active *bool `json:"active" api:"required"`
}

func (s *Server) handleSetUserActive(w http.ResponseWriter, r *http.Request) {
	var req setActiveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Active == nil {
		http.Error(w, "active is required: true or false", http.StatusBadRequest)
		return
	}
	active := *req.Active
	id := r.PathValue("id")
	if !active {
		if cur := auth.CurrentUser(r.Context()); cur != nil && cur.ID == id {
			http.Error(w, "you can't deactivate your own account", http.StatusBadRequest)
			return
		}
	}
	target, perr := s.protectedAccount(r.Context(), id)
	if target == nil && perr == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "users.set_active", target.Username, map[string]any{"user_id": id, "active": active}) {
		return
	}
	user, err := s.store.SetUserActive(r.Context(), id, active)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if !active {
		if err := s.store.DeleteSessionsForUser(r.Context(), id); err != nil {
			s.logger.Warn("signing a deactivated user out failed", "user_id", id, "error", err)
		}
	}
	v, err := s.buildAdminUserView(r, *user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, v)
}

// setAdminRequest is the body of POST /api/admin/users/{id}/admin.
type setAdminRequest struct {
	// IsAdmin is required. A body without it is refused rather than read
	// as false, which would remove the user's administrator rights and
	// sign them out.
	IsAdmin *bool `json:"is_admin" api:"required"`
}

func (s *Server) handleSetUserAdmin(w http.ResponseWriter, r *http.Request) {
	var req setAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.IsAdmin == nil {
		http.Error(w, "is_admin is required: true or false", http.StatusBadRequest)
		return
	}
	isAdmin := *req.IsAdmin
	id := r.PathValue("id")
	// Making or unmaking an administrator is an administrator's decision.
	// users.manage alone used to be enough, including on the caller's own
	// account, which made the permission a synonym for admin.
	if !requireAdmin(w, r, "grant or remove administrator rights") {
		return
	}
	if !isAdmin {
		if cur := auth.CurrentUser(r.Context()); cur != nil && cur.ID == id {
			http.Error(w, "you can't remove your own super-admin flag", http.StatusBadRequest)
			return
		}
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if target == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if !s.auditIdentity(w, r, "users.set_admin", target.Username, map[string]any{"user_id": id, "is_admin": isAdmin}) {
		return
	}
	user, err := s.store.SetUserAdmin(r.Context(), id, isAdmin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	// A session minted under the old rights does not outlive them.
	if err := s.store.DeleteSessionsForUser(r.Context(), id); err != nil {
		s.logger.Warn("signing a user out after an admin change failed", "user_id", id, "error", err)
	}
	v, err := s.buildAdminUserView(r, *user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, v)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if cur := auth.CurrentUser(r.Context()); cur != nil && cur.ID == id {
		http.Error(w, "you can't delete your own account", http.StatusBadRequest)
		return
	}
	target, perr := s.protectedAccount(r.Context(), id)
	if target == nil && perr == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "users.delete", target.Username, map[string]any{"user_id": id}) {
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type roleIDRequest struct {
	RoleID string `json:"role_id" api:"required"`
}

func (s *Server) handleAssignUserRole(w http.ResponseWriter, r *http.Request) {
	var req roleIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RoleID == "" {
		http.Error(w, "role_id is required", http.StatusBadRequest)
		return
	}
	target, perr := s.protectedAccount(r.Context(), r.PathValue("id"))
	if target == nil && perr == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if perr == nil {
		perr = s.checkRoleGrantable(r.Context(), req.RoleID)
	}
	if perr != nil {
		s.audit(r.Context(), auditEvent{Action: "users.assign_role", Actor: auth.CurrentUser(r.Context()).Username,
			Target: target.Username, Outcome: "denied", Severity: "warning", Detail: map[string]any{"role_id": req.RoleID, "reason": perr.Error()}})
		http.Error(w, perr.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "users.assign_role", target.Username, map[string]any{"user_id": target.ID, "role_id": req.RoleID}) {
		return
	}
	if err := s.store.AssignUserRole(r.Context(), r.PathValue("id"), req.RoleID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveUserRole(w http.ResponseWriter, r *http.Request) {
	target, perr := s.protectedAccount(r.Context(), r.PathValue("id"))
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusForbidden)
		return
	}
	name := r.PathValue("id")
	if target != nil {
		name = target.Username
	}
	if !s.auditIdentity(w, r, "users.remove_role", name, map[string]any{"user_id": r.PathValue("id"), "role_id": r.PathValue("role_id")}) {
		return
	}
	if err := s.store.RemoveUserRole(r.Context(), r.PathValue("id"), r.PathValue("role_id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Groups ---

type adminGroupView struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	ExternalID  string    `json:"external_id,omitempty"` // set if SCIM-provisioned; empty means created locally in the console
	MemberIDs   []string  `json:"member_ids"`
	RoleIDs     []string  `json:"role_ids"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Server) buildAdminGroupView(r *http.Request, g store.Group) (adminGroupView, error) {
	roleIDs, err := s.store.ListGroupRoleIDs(r.Context(), g.ID)
	if err != nil {
		return adminGroupView{}, err
	}
	return adminGroupView{
		ID: g.ID, DisplayName: g.DisplayName, ExternalID: g.ExternalID,
		MemberIDs: nonNil(g.MemberIDs), RoleIDs: nonNil(roleIDs), CreatedAt: g.CreatedAt,
	}, nil
}

// listGroupsResponse is what GET /api/admin/groups answers.
type listGroupsResponse struct {
	Groups []adminGroupView `json:"groups"`
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, _, err := s.store.ListGroups(r.Context(), "", 0, 10000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]adminGroupView, 0, len(groups))
	for _, g := range groups {
		v, err := s.buildAdminGroupView(r, g)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		views = append(views, v)
	}
	writeJSONResponse(w, listGroupsResponse{Groups: views})
}

type createGroupRequest struct {
	DisplayName string `json:"display_name" api:"required"`
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DisplayName == "" {
		http.Error(w, "display_name is required", http.StatusBadRequest)
		return
	}
	if !s.auditIdentity(w, r, "groups.create", req.DisplayName, nil) {
		return
	}
	group, err := s.store.CreateGroup(r.Context(), idgen.New("grp-"), "", req.DisplayName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v, err := s.buildAdminGroupView(r, *group)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, v)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.auditIdentity(w, r, "groups.delete", r.PathValue("id"), nil) {
		return
	}
	if err := s.store.DeleteGroup(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type userIDRequest struct {
	UserID string `json:"user_id" api:"required"`
}

func (s *Server) handleAddGroupMember(w http.ResponseWriter, r *http.Request) {
	var req userIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}
	// Membership grants every role the group carries.
	target, perr := s.protectedAccount(r.Context(), req.UserID)
	if target == nil && perr == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if perr == nil {
		perr = s.checkGroupGrantable(r.Context(), r.PathValue("id"))
	}
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "groups.add_member", r.PathValue("id"), map[string]any{"user_id": req.UserID, "username": target.Username}) {
		return
	}
	if err := s.store.AddGroupMember(r.Context(), r.PathValue("id"), req.UserID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	if _, perr := s.protectedAccount(r.Context(), r.PathValue("user_id")); perr != nil {
		http.Error(w, perr.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "groups.remove_member", r.PathValue("id"), map[string]any{"user_id": r.PathValue("user_id")}) {
		return
	}
	if err := s.store.RemoveGroupMember(r.Context(), r.PathValue("id"), r.PathValue("user_id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAssignGroupRole(w http.ResponseWriter, r *http.Request) {
	var req roleIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RoleID == "" {
		http.Error(w, "role_id is required", http.StatusBadRequest)
		return
	}
	if err := s.checkRoleGrantable(r.Context(), req.RoleID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "groups.assign_role", r.PathValue("id"), map[string]any{"role_id": req.RoleID}) {
		return
	}
	if err := s.store.AssignGroupRole(r.Context(), r.PathValue("id"), req.RoleID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveGroupRole(w http.ResponseWriter, r *http.Request) {
	if !s.auditIdentity(w, r, "groups.remove_role", r.PathValue("id"), map[string]any{"role_id": r.PathValue("role_id")}) {
		return
	}
	if err := s.store.RemoveGroupRole(r.Context(), r.PathValue("id"), r.PathValue("role_id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Roles ---

// listRolesResponse is what GET /api/admin/roles answers.
type listRolesResponse struct {
	AvailablePermissions []string            `json:"available_permissions"`
	ContentSets          []store.ContentSet  `json:"content_sets"`
	RoleContentSets      map[string][]string `json:"role_content_sets"`
	Roles                []store.Role        `json:"roles"`
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for i := range roles {
		roles[i].Permissions = nonNil(roles[i].Permissions)
	}
	// Content sets ride along so the roles editor can offer them without a
	// second round trip, and so a role's current sets are visible where
	// they are edited rather than somewhere else.
	sets, _ := s.store.ListContentSets(r.Context())
	byRole := map[string][]string{}
	for i := range roles {
		ids, _ := s.store.RoleContentSetIDs(r.Context(), roles[i].ID)
		byRole[roles[i].ID] = ids
	}
	writeJSONResponse(w, listRolesResponse{Roles: roles, AvailablePermissions: auth.AllPermissions,
		ContentSets: sets, RoleContentSets: byRole})
}

type roleRequest struct {
	Name        string   `json:"name" api:"required"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	// ComputerGroupIDs are the role's management rights; empty is the
	// whole fleet. ContentSetIDs are the content it may use; empty is all.
	ComputerGroupIDs []string `json:"computer_group_ids"`
	ContentSetIDs    []string `json:"content_set_ids"`
}

func validPermissions(perms []string) bool {
	allowed := map[string]bool{}
	for _, p := range auth.AllPermissions {
		allowed[p] = true
	}
	for _, p := range perms {
		if !allowed[p] {
			return false
		}
	}
	return true
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req roleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if !validPermissions(req.Permissions) {
		http.Error(w, "unknown permission key — see available_permissions on GET /api/admin/roles", http.StatusBadRequest)
		return
	}
	if err := s.checkGrantable(r.Context(), req.Permissions, req.ComputerGroupIDs, req.ContentSetIDs); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "roles.create", req.Name, map[string]any{"permissions": req.Permissions,
		"computer_group_ids": req.ComputerGroupIDs, "content_set_ids": req.ContentSetIDs}) {
		return
	}
	role, err := s.store.CreateRole(r.Context(), idgen.New("role-"), req.Name, req.Description, req.Permissions, req.ComputerGroupIDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.SetRoleContentSets(r.Context(), role.ID, req.ContentSetIDs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateAccess()
	role.Permissions = nonNil(role.Permissions)
	writeJSONResponse(w, role)
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.store.GetRole(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "no such role", http.StatusNotFound)
		return
	}
	if existing.IsBuiltin {
		http.Error(w, "builtin roles (admin, user) can't be edited — create a custom role instead", http.StatusForbidden)
		return
	}
	var req roleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if !validPermissions(req.Permissions) {
		http.Error(w, "unknown permission key — see available_permissions on GET /api/admin/roles", http.StatusBadRequest)
		return
	}
	// Both what the role is now (editing a role widens or narrows everyone
	// who holds it) and what it becomes must be within the caller's reach.
	if err := s.checkRoleGrantable(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.checkGrantable(r.Context(), req.Permissions, req.ComputerGroupIDs, req.ContentSetIDs); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "roles.update", req.Name, map[string]any{"role_id": id, "permissions": req.Permissions,
		"computer_group_ids": req.ComputerGroupIDs, "content_set_ids": req.ContentSetIDs}) {
		return
	}
	role, err := s.store.UpdateRole(r.Context(), id, req.Name, req.Description, req.Permissions, req.ComputerGroupIDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if role == nil {
		http.Error(w, "no such role", http.StatusNotFound)
		return
	}
	if err := s.store.SetRoleContentSets(r.Context(), role.ID, req.ContentSetIDs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateAccess()
	role.Permissions = nonNil(role.Permissions)
	writeJSONResponse(w, role)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.store.GetRole(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing != nil && existing.IsBuiltin {
		http.Error(w, "builtin roles (admin, user) can't be deleted", http.StatusForbidden)
		return
	}
	if existing != nil {
		if err := s.checkRoleGrantable(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	if !s.auditIdentity(w, r, "roles.delete", id, nil) {
		return
	}
	if err := s.store.DeleteRole(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
