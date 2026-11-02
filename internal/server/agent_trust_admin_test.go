package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The public URL is the download root for every install and update, and the
// legacy toggle re-opens the shared password: settings.manage alone may read
// them but not change them (review F5); that takes agents.trust.
func TestAgentTrustPutNeedsAgentTrust(t *testing.T) {
	s := &Server{logger: slog.Default()}
	tokenUser := &store.User{ID: auth.APITokenUserID, Username: "token:t", Active: true}
	for _, body := range []string{`{"legacy_allowed":true}`, `{"public_url":"https://evil.example.com"}`} {
		req := httptest.NewRequest("PUT", "/api/agent-trust", strings.NewReader(body))
		ctx := auth.WithToken(auth.WithUser(req.Context(), tokenUser), []string{auth.PermSettingsManage}, &auth.TokenInfo{ID: "tok-1"})
		rec := httptest.NewRecorder()
		s.handlePutAgentTrust(rec, req.WithContext(ctx))
		if rec.Code != http.StatusForbidden {
			t.Errorf("PUT %s with settings.manage only: got %d, want 403", body, rec.Code)
		}
	}
}

// requireAdminOr lets through an administrator's session or the named
// permission (including on an API token), and nothing else.
func TestRequireAdminOr(t *testing.T) {
	s := &Server{logger: slog.Default()}
	tokenUser := &store.User{ID: auth.APITokenUserID, Username: "token:t", Active: true}
	cases := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"admin session", auth.WithUser(context.Background(), &store.User{ID: "u", IsAdmin: true}), true},
		{"token with the permission", auth.WithToken(auth.WithUser(context.Background(), tokenUser), []string{auth.PermSettingsManage, auth.PermAllowlistsManage}, &auth.TokenInfo{ID: "tok-1"}), true},
		{"token without it", auth.WithToken(auth.WithUser(context.Background(), tokenUser), []string{auth.PermSettingsManage, auth.PermIdentityManage}, &auth.TokenInfo{ID: "tok-1"}), false},
		// A token never counts as an administrator, whoever made it.
		{"token marked admin", auth.WithToken(auth.WithUser(context.Background(), &store.User{ID: auth.APITokenUserID, IsAdmin: true}), []string{auth.PermSettingsManage}, &auth.TokenInfo{ID: "tok-1", CreatorAdmin: true}), false},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/x", nil).WithContext(c.ctx)
		if got := s.requireAdminOr(rec, req, auth.PermAllowlistsManage, "test"); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
		if !c.want && rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", c.name, rec.Code)
		}
	}
}

// The GET side tells the console whether the caller may change the fields,
// so it can render them read-only; it stays settings.manage-readable, and
// the flag reflects the caller's admin status.
func TestAgentTrustGetReportsAdmin(t *testing.T) {
	for _, admin := range []bool{false, true} {
		ctx := auth.WithUser(context.Background(), &store.User{ID: "u", Username: "u", IsAdmin: admin})
		if got := callerIsAdmin(ctx); got != admin {
			t.Fatalf("callerIsAdmin = %v, want %v", got, admin)
		}
		out := agentTrustSettings{CallerIsAdmin: callerIsAdmin(ctx)}
		blob, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		want := `"caller_is_admin":` + map[bool]string{true: "true", false: "false"}[admin]
		if !strings.Contains(string(blob), want) {
			t.Errorf("admin=%v: response missing %s: %s", admin, want, blob)
		}
	}
}
