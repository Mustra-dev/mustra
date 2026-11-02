package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// API tokens are managed under Administration. Creating one is the only
// time its secret exists in plaintext — the response carries it once and
// nothing stores it, so a lost token is replaced rather than recovered.

// listAPITokensResponse is what GET /api/admin/tokens answers.
type listAPITokensResponse struct {
	Permissions []string         `json:"permissions"`
	Tokens      []store.APIToken `json:"tokens"`
}

func (s *Server) handleListAPITokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.store.ListAPITokens(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listAPITokensResponse{Tokens: tokens, Permissions: auth.AllPermissions})
}

type createAPITokenRequest struct {
	Name        string   `json:"name" api:"required"`
	Permissions []string `json:"permissions" api:"required"`
	ExpiresDays int      `json:"expires_days"` // 0 = never expires
	// ApprovalExempt lets the token run operations an approval policy
	// covers. Administrators only.
	ApprovalExempt bool `json:"approval_exempt"`
}

// createAPITokenResponse is what POST /api/admin/tokens answers.
type createAPITokenResponse struct {
	ID    string `json:"id"`
	Note  string `json:"note"`
	Token string `json:"token"`
}

func (s *Server) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	var req createAPITokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	// A token makes tokens only with tokens.manage, and what it makes is
	// bound to it (parent_token_id): never wider, and dead once it is
	// revoked, deleted or expired, so a leaked token leaves no foothold
	// that outlives it.
	parent, ok := s.tokenMayManageTokens(w, r)
	if !ok {
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required — it's how you'll recognize this token later", http.StatusBadRequest)
		return
	}

	if len(req.Permissions) == 0 {
		http.Error(w, "grant the token at least one permission, or it can't do anything", http.StatusBadRequest)
		return
	}
	perms, ok := s.checkTokenGrant(w, r, req.Permissions, req.ApprovalExempt)
	if !ok {
		return
	}
	if req.ExpiresDays < 0 || req.ExpiresDays > 3650 {
		http.Error(w, "expires_days must be between 0 and 3650", http.StatusBadRequest)
		return
	}

	token, prefix, err := auth.GenerateToken()
	if err != nil {
		http.Error(w, "generate token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := auth.HashToken(token)
	if err != nil {
		http.Error(w, "hash token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var expiresAt *time.Time
	if req.ExpiresDays > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour).UTC()
		expiresAt = &t
	}

	u := auth.CurrentUser(r.Context())
	record := store.APIToken{
		ID: idgen.New("tok-"), Name: req.Name, Prefix: prefix,
		Permissions: perms, CreatedBy: u.Username, ExpiresAt: expiresAt,
		CreatedByID: u.ID, ApprovalExempt: req.ApprovalExempt,
	}
	if parent != nil {
		// The person behind the parent is the creator: the new token is
		// also bounded by their reach on every use.
		record.CreatedByID, record.ParentTokenID = parent.CreatorID, parent.ID
	}
	if !s.auditIdentity(w, r, "tokens.create", req.Name, map[string]any{"token_id": record.ID,
		"permissions": perms, "expires_days": req.ExpiresDays, "approval_exempt": req.ApprovalExempt}) {
		return
	}
	if err := s.store.CreateAPIToken(r.Context(), record, hash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("api token created", "name", record.Name, "permissions", perms, "created_by", u.Username)

	// The only response that ever carries the secret.
	writeJSONResponse(w, createAPITokenResponse{
		Token: token,
		ID:    record.ID,
		Note:  "Copy this now — it isn't stored and can't be shown again.",
	})
}

// checkTokenGrant validates what a token is to be allowed to do, writing
// the refusal itself when it is not allowed: only the fixed permission
// keys, at least one, never more than the caller holds, and approval
// exemption from an administrator only. Shared by create and update, so
// editing a token cannot grant what creating it could not.
func (s *Server) checkTokenGrant(w http.ResponseWriter, r *http.Request, requested []string, approvalExempt bool) ([]string, bool) {
	// Only the fixed permission keys are accepted: a typo'd permission that
	// silently grants nothing is worse than a rejected request.
	allowed := map[string]bool{}
	for _, p := range auth.AllPermissions {
		allowed[p] = true
	}
	perms := make([]string, 0, len(requested))
	seen := map[string]bool{}
	for _, p := range requested {
		if !allowed[p] {
			http.Error(w, "unknown permission: "+p, http.StatusBadRequest)
			return nil, false
		}
		if !seen[p] {
			seen[p] = true
			perms = append(perms, p)
		}
	}
	if len(perms) == 0 {
		http.Error(w, "grant the token at least one permission, or it can't do anything", http.StatusBadRequest)
		return nil, false
	}
	// A token is never wider than the person granting it. (It is also
	// re-intersected with its creator's permissions on every use.)
	if !callerIsAdmin(r.Context()) {
		held, herr := s.callerPermissions(r.Context())
		if herr != nil {
			http.Error(w, herr.Error(), http.StatusInternalServerError)
			return nil, false
		}
		for _, p := range perms {
			if !held[p] {
				http.Error(w, "you cannot give a token "+p+", which you do not hold yourself", http.StatusForbidden)
				return nil, false
			}
		}
	}
	if approvalExempt && !callerIsAdmin(r.Context()) {
		http.Error(w, "only an administrator can make a token approval-exempt", http.StatusForbidden)
		return nil, false
	}
	return perms, true
}

// updateAPITokenRequest is the body of PUT /api/admin/tokens/{id}.
type updateAPITokenRequest struct {
	Name        string   `json:"name" api:"required"`
	Permissions []string `json:"permissions" api:"required"`
	// ApprovalExempt lets the token run operations an approval policy
	// covers. Administrators only.
	ApprovalExempt bool `json:"approval_exempt"`
}

// handleUpdateAPIToken changes a token's name, permissions and approval
// exemption in place. Replacing a token to change what it may do meant
// handing every script that uses it a new secret; the secret stays.
func (s *Server) handleUpdateAPIToken(w http.ResponseWriter, r *http.Request) {
	var req updateAPITokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// The same rule as creating one, and a token changes only the tokens
	// it made (directly or through them), never its own or a person's.
	parent, ok := s.tokenMayManageTokens(w, r)
	if !ok {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	cur, err := s.store.GetAPIToken(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cur == nil {
		http.Error(w, "no such token", http.StatusNotFound)
		return
	}
	if cur.Revoked {
		http.Error(w, "this token is revoked; create a new one", http.StatusConflict)
		return
	}
	if parent != nil && !s.tokenDescendsFrom(r.Context(), cur, parent.ID) {
		http.Error(w, "an API token may change only the tokens it created", http.StatusForbidden)
		return
	}
	if len(req.Permissions) == 0 {
		http.Error(w, "grant the token at least one permission, or it can't do anything", http.StatusBadRequest)
		return
	}
	perms, ok := s.checkTokenGrant(w, r, req.Permissions, req.ApprovalExempt)
	if !ok {
		return
	}
	if !s.auditIdentity(w, r, "tokens.update", req.Name, map[string]any{"token_id": id,
		"permissions": perms, "permissions_before": cur.Permissions, "name_before": cur.Name,
		"approval_exempt": req.ApprovalExempt, "approval_exempt_before": cur.ApprovalExempt}) {
		return
	}
	updated, err := s.store.UpdateAPIToken(r.Context(), id, req.Name, perms, req.ApprovalExempt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !updated {
		http.Error(w, "this token was revoked or deleted meanwhile", http.StatusConflict)
		return
	}
	s.logger.Info("api token updated", "id", id, "name", req.Name, "permissions", perms,
		"updated_by", auth.CurrentUser(r.Context()).Username)
	cur.Name, cur.Permissions, cur.ApprovalExempt = req.Name, perms, req.ApprovalExempt
	writeJSONResponse(w, cur)
}

func (s *Server) handleRevokeAPIToken(w http.ResponseWriter, r *http.Request) {
	if !s.auditIdentity(w, r, "tokens.revoke", r.PathValue("id"), nil) {
		return
	}
	if err := s.store.RevokeAPIToken(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := auth.CurrentUser(r.Context())
	s.logger.Info("api token revoked", "id", r.PathValue("id"), "revoked_by", u.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteAPIToken(w http.ResponseWriter, r *http.Request) {
	if !s.auditIdentity(w, r, "tokens.delete", r.PathValue("id"), nil) {
		return
	}
	if err := s.store.DeleteAPIToken(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tokenMayManageTokens answers for create and update: a person passes
// (with nil), a token passes only with tokens.manage and while a token it
// makes could still be used, and gets its TokenInfo back.
func (s *Server) tokenMayManageTokens(w http.ResponseWriter, r *http.Request) (*auth.TokenInfo, bool) {
	ctx := r.Context()
	if _, isToken := auth.TokenPermissions(ctx); !isToken {
		return nil, true
	}
	info, ok := auth.Token(ctx)
	if !ok {
		http.Error(w, "this API token cannot be identified, so it cannot manage tokens", http.StatusForbidden)
		return nil, false
	}
	if ok, err := s.auth.HasPermission(ctx, auth.CurrentUser(ctx), auth.PermTokensManage); err != nil || !ok {
		http.Error(w, "an API token needs the tokens.manage permission to create or change API tokens", http.StatusForbidden)
		return nil, false
	}
	depth, err := s.auth.TokenChainDepth(ctx, info.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	if depth+1 > auth.MaxTokenChain {
		http.Error(w, "this token was itself made by a chain of tokens too long to extend; create the token from the console", http.StatusForbidden)
		return nil, false
	}
	return info, true
}

// tokenDescendsFrom reports whether t was made by the token ancestorID,
// directly or through tokens it made.
func (s *Server) tokenDescendsFrom(ctx context.Context, t *store.APIToken, ancestorID string) bool {
	for depth := 0; t != nil && t.ParentTokenID != "" && depth < auth.MaxTokenChain; depth++ {
		if t.ParentTokenID == ancestorID {
			return true
		}
		next, err := s.store.GetAPIToken(ctx, t.ParentTokenID)
		if err != nil {
			return false
		}
		t = next
	}
	return false
}
