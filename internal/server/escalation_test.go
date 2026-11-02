package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

func asUser(r *http.Request, u *store.User) *http.Request {
	return r.WithContext(auth.WithUser(r.Context(), u))
}

// users.manage is not admin: setting is_admin, on anyone including
// yourself, is refused before anything is read or written.
func TestOnlyAdminsGrantAdmin(t *testing.T) {
	s := &Server{logger: slog.Default()}
	mgr := &store.User{ID: "usr-mgr", Username: "mgr", Active: true}
	for _, target := range []string{"usr-mgr", "usr-other"} {
		req := httptest.NewRequest("POST", "/api/admin/users/"+target+"/admin", strings.NewReader(`{"is_admin":true}`))
		req.SetPathValue("id", target)
		rec := httptest.NewRecorder()
		s.handleSetUserAdmin(rec, asUser(req, mgr))
		if rec.Code != http.StatusForbidden {
			t.Errorf("non-admin set is_admin on %s: %d, want 403", target, rec.Code)
		}
	}
}

// A token whose creator is an administrator is still not an administrator.
func TestTokenIsNeverAdmin(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	ctx := auth.WithUser(r.Context(), &store.User{ID: "usr-root", Username: "root", IsAdmin: true})
	if !callerIsAdmin(ctx) {
		t.Fatal("an admin session was not recognised")
	}
	ctx = auth.WithToken(ctx, auth.AllPermissions, &auth.TokenInfo{ID: "tok", CreatorID: "usr-root", CreatorAdmin: true})
	if callerIsAdmin(ctx) {
		t.Fatal("a token counted as an administrator")
	}
}

func TestTokensCannotMintTokens(t *testing.T) {
	s := &Server{logger: slog.Default()}
	req := httptest.NewRequest("POST", "/api/admin/tokens", strings.NewReader(`{"name":"x","permissions":["settings.manage"]}`))
	ctx := auth.WithUser(req.Context(), &store.User{ID: auth.APITokenUserID, Username: "token:t"})
	ctx = auth.WithToken(ctx, []string{auth.PermSettingsManage}, &auth.TokenInfo{ID: "tok", CreatorID: "usr-root", CreatorAdmin: true})
	rec := httptest.NewRecorder()
	s.handleCreateAPIToken(rec, req.WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token minting a token: %d, want 403", rec.Code)
	}
}

// settings.manage alone cannot touch the break-glass account, the SCIM
// token, the agents' bus address, the allowlists or who may sign in: each
// takes its own permission (or, for the break-glass account, an
// administrator). A token stands in for any non-administrator here.
func TestSettingsManageCannotReachAdmin(t *testing.T) {
	s := &Server{logger: slog.Default(), live: &liveConfig{}}
	mgr := &store.User{ID: auth.APITokenUserID, Username: "token:mgr", Active: true}
	for _, body := range []string{
		`{"backdoor_password":"a-new-long-password"}`,
		`{"backdoor_username":"me"}`,
		`{"scim_token":"0123456789abcdef0123456789abcdef"}`,
		`{"agent_nats_url":"nats://evil.example:4222"}`,
		`{"import_allowed_hosts":"169.254.169.254"}`,
		`{"sso_allowed_domains":"gmail.com"}`,
		`{"webhook_allowed_hosts":"10.0.0.1"}`,
		`{"fleet_url":"https://fleet.example.com"}`,
	} {
		req := httptest.NewRequest("POST", "/api/admin/settings", strings.NewReader(body))
		req = asUser(req, mgr)
		// Every new permission but the one each field needs would still
		// leave settings.manage plus unrelated grants: hold just these.
		req = req.WithContext(auth.WithToken(req.Context(), []string{auth.PermSettingsManage, auth.PermTokensManage, auth.PermBackupsRestore}, &auth.TokenInfo{ID: "tok-mgr"}))
		rec := httptest.NewRecorder()
		s.handleUpdateSettings(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s by settings.manage: %d, want 403", body, rec.Code)
		}
	}
}

func TestValidateAgentNATSURL(t *testing.T) {
	for _, bad := range []string{"http://x", "nats://", "nats://h:4222/$(id)", "nats://h;id", "nats://u:p@h:4222", "nats://h:4222?x=1"} {
		if validateAgentNATSURL(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"", "nats://10.0.0.5:4222", "tls://nats.example.com:4222"} {
		if err := validateAgentNATSURL(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
}
