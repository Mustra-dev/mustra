package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Nobody grants what they do not hold.
//
// users.manage and settings.manage are delegable permissions, and each
// used to be a short step to full administrator: users.manage could set
// is_admin (on anyone, including the caller) or hand out the builtin
// admin role, and settings.manage could reset the break-glass password or
// mint an API token with every permission. The rules here close that:
//
//   - only an administrator makes or unmakes an administrator, edits an
//     administrator's account, or touches the break-glass account;
//   - a role may only be created, edited or assigned (directly or through
//     a group) by someone who holds every permission in it and whose own
//     management rights and content sets are at least as wide;
//   - an API token's permissions are a subset of its creator's.
//
// API tokens never count as administrators here, whatever their creator is.

// callerIsAdmin reports whether the request comes from an administrator's
// own session — not from a token, however privileged its creator.
func callerIsAdmin(ctx context.Context) bool {
	if _, isToken := auth.TokenPermissions(ctx); isToken {
		return false
	}
	u := auth.CurrentUser(ctx)
	return u != nil && u.IsAdmin
}

// requireAdmin writes a 403 unless the caller is an administrator.
func requireAdmin(w http.ResponseWriter, r *http.Request, what string) bool {
	if callerIsAdmin(r.Context()) {
		return true
	}
	http.Error(w, "only an administrator can "+what, http.StatusForbidden)
	return false
}

// requireAdminOr writes a 403 unless the caller is an administrator or
// holds perm: one of the permissions for settings that once needed an
// administrator (auth.PermAllowlistsManage and the rest). Unlike
// requireAdmin, an API token may pass, with that permission granted.
func (s *Server) requireAdminOr(w http.ResponseWriter, r *http.Request, perm, what string) bool {
	ctx := r.Context()
	if callerIsAdmin(ctx) {
		return true
	}
	if ok, err := s.auth.HasPermission(ctx, auth.CurrentUser(ctx), perm); err == nil && ok {
		return true
	}
	http.Error(w, "you need the "+perm+" permission to "+what, http.StatusForbidden)
	return false
}

// callerMayChange reports what requireAdminOr would allow, for pages that
// show a setting read-only to those who cannot change it.
func (s *Server) callerMayChange(ctx context.Context, perm string) bool {
	if callerIsAdmin(ctx) {
		return true
	}
	ok, err := s.auth.HasPermission(ctx, auth.CurrentUser(ctx), perm)
	return err == nil && ok
}

// callerPermissions is what the caller may grant.
func (s *Server) callerPermissions(ctx context.Context) (map[string]bool, error) {
	perms, err := s.auth.GrantedPermissions(ctx, auth.CurrentUser(ctx))
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, p := range perms {
		out[p] = true
	}
	return out, nil
}

// checkGrantable returns an error naming what the caller would be handing
// out beyond their own reach, or nil.
func (s *Server) checkGrantable(ctx context.Context, perms, computerGroupIDs, contentSetIDs []string) error {
	if callerIsAdmin(ctx) {
		return nil
	}
	held, err := s.callerPermissions(ctx)
	if err != nil {
		return err
	}
	for _, p := range perms {
		if !held[p] {
			return fmt.Errorf("you cannot grant %q, which you do not hold yourself", p)
		}
	}
	principal, _, ok := accessPrincipal(ctx)
	if !ok {
		return fmt.Errorf("no identity to grant from")
	}
	// Management rights: empty on a role means the whole fleet.
	myGroups, unrestricted, err := s.store.ManagementGroupsForUser(ctx, principal)
	if err != nil {
		return err
	}
	if !unrestricted {
		if len(computerGroupIDs) == 0 {
			return fmt.Errorf("your management rights are limited, so a role you grant must name computer groups (empty means the whole fleet)")
		}
		mine := map[string]bool{}
		for _, g := range myGroups {
			mine[g] = true
		}
		for _, g := range computerGroupIDs {
			if !mine[g] {
				return fmt.Errorf("computer group %s is outside your own management rights", g)
			}
		}
	}
	mySets, unrestrictedContent, err := s.store.ContentSetIDsForUser(ctx, principal)
	if err != nil {
		return err
	}
	if !unrestrictedContent {
		if len(contentSetIDs) == 0 {
			return fmt.Errorf("your content is limited to content sets, so a role you grant must name content sets (empty means all content)")
		}
		mine := map[string]bool{}
		for _, c := range mySets {
			mine[c] = true
		}
		for _, c := range contentSetIDs {
			if !mine[c] {
				return fmt.Errorf("content set %s is not one you hold", c)
			}
		}
	}
	return nil
}

// checkRoleGrantable applies checkGrantable to a stored role.
func (s *Server) checkRoleGrantable(ctx context.Context, roleID string) error {
	role, err := s.store.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return fmt.Errorf("no such role")
	}
	if role.IsBuiltin && role.Name == "admin" && !callerIsAdmin(ctx) {
		return fmt.Errorf("only an administrator can grant the admin role")
	}
	sets, err := s.store.RoleContentSetIDs(ctx, role.ID)
	if err != nil {
		return err
	}
	return s.checkGrantable(ctx, role.Permissions, role.ComputerGroupIDs, sets)
}

// checkGroupGrantable is checkRoleGrantable for every role a security
// group carries: adding someone to the group grants them all of it.
func (s *Server) checkGroupGrantable(ctx context.Context, groupID string) error {
	if callerIsAdmin(ctx) {
		return nil
	}
	roleIDs, err := s.store.ListGroupRoleIDs(ctx, groupID)
	if err != nil {
		return err
	}
	for _, id := range roleIDs {
		if err := s.checkRoleGrantable(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// protectedAccount refuses a non-administrator acting on an
// administrator's account or on the break-glass account.
func (s *Server) protectedAccount(ctx context.Context, userID string) (*store.User, error) {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, nil
	}
	if callerIsAdmin(ctx) {
		return u, nil
	}
	if u.IsAdmin {
		return u, fmt.Errorf("only an administrator can change an administrator's account")
	}
	if bg := s.backdoorUsername(); bg != "" && u.Username == bg {
		return u, fmt.Errorf("only an administrator can change the break-glass account")
	}
	return u, nil
}

// auditIdentity records an identity or permission change at critical
// severity and reports whether it was written. Callers refuse the change
// when it was not: these are exactly the edits an audit log exists for.
func (s *Server) auditIdentity(w http.ResponseWriter, r *http.Request, action, target string, detail map[string]any) bool {
	if err := s.auditStrict(r.Context(), auditEvent{
		Action: action, Actor: auth.CurrentUser(r.Context()).Username, Target: target,
		Severity: "critical", Detail: detail,
	}); err != nil {
		http.Error(w, "the change could not be recorded in the audit log, so it was not made", http.StatusServiceUnavailable)
		return false
	}
	return true
}
