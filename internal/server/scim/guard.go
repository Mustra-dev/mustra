package scim

import (
	"context"
	"net/http"

	"github.com/mustra-dev/mustra/internal/store"
)

// What SCIM may touch.
//
// The SCIM token is a credential an IdP holds, and it used to reach every
// account and group in the console: rename, deactivate or delete the
// break-glass administrator, or add any account to a group carrying an
// admin role. SCIM now manages only what SCIM created — users whose source
// is "scim" and who are not administrators, and groups it provisioned —
// and only SCIM users can be members it adds. Everything else answers 404,
// exactly as if it did not exist, so the IdP learns nothing about local
// accounts either.

// scimUser returns the user when SCIM may manage it.
func (s *Server) scimUser(ctx context.Context, id string) (*store.User, error) {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil || u == nil {
		return nil, err
	}
	if u.Source != "scim" || u.IsAdmin {
		return nil, nil
	}
	return u, nil
}

// scimGroup returns the group when SCIM provisioned it.
func (s *Server) scimGroup(ctx context.Context, id string) (*store.Group, error) {
	g, err := s.store.GetGroup(ctx, id)
	if err != nil || g == nil {
		return nil, err
	}
	if !g.SCIMManaged {
		return nil, nil
	}
	return g, nil
}

// requireSCIMUser writes the 404 and returns false when SCIM may not
// manage the path's user.
func (s *Server) requireSCIMUser(w http.ResponseWriter, r *http.Request) bool {
	u, err := s.scimUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return false
	}
	if u == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return false
	}
	return true
}

func (s *Server) requireSCIMGroup(w http.ResponseWriter, r *http.Request) bool {
	g, err := s.scimGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return false
	}
	if g == nil {
		writeError(w, http.StatusNotFound, "group not found")
		return false
	}
	return true
}

// scimMembers keeps only the ids SCIM may place in a group.
func (s *Server) scimMembers(ctx context.Context, ids []string) []string {
	var out []string
	for _, id := range ids {
		if u, err := s.scimUser(ctx, id); err == nil && u != nil {
			out = append(out, id)
		} else {
			s.logger.Warn("scim tried to add a non-SCIM account to a group; ignored", "user_id", id)
		}
	}
	return out
}

// maxSCIMPage bounds count, which was unbounded.
const maxSCIMPage = 200

// MinTokenLen is the shortest SCIM bearer token honoured.
const MinTokenLen = 32
