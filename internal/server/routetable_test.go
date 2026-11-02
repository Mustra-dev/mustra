package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// openMutatingRoutes are the state-changing routes deliberately open to any
// signed-in user. Each needs a reason; adding to this list is a security
// decision, and the test below exists so it is made on purpose.
var openMutatingRoutes = map[string]string{
	// Per-viewer state: these change only the caller's own data.
	"PUT /api/preferences":              "the caller's own preferences",
	"POST /api/me/mfa/setup":            "the caller's own authenticator; refuses tokens and SSO accounts",
	"POST /api/me/mfa/enable":           "the caller's own authenticator, confirmed by a current code",
	"POST /api/me/mfa/recovery-codes":   "the caller's own recovery codes, gated on a current code",
	"POST /api/me/mfa/disable":          "the caller's own authenticator, gated on a current code",
	"POST /api/notifications/{id}/read": "the caller's own read marker",
	"POST /api/interact/saved":          "saved questions are read-only queries",
	"DELETE /api/interact/saved/{id}":   "author or settings.manage, enforced in the handler",
	"POST /api/dashboards":              "ownership is enforced in the handler (canEditDashboard)",
	"PUT /api/dashboards/{id}":          "ownership is enforced in the handler (canEditDashboard)",
	"DELETE /api/dashboards/{id}":       "ownership is enforced in the handler (canEditDashboard)",
	"POST /api/dashboards/{id}/clone":   "the copy belongs to the caller; the source must be visible to them",
	"POST /api/dashboards/preview":      "renders a panel from data the caller can already read",
	// Read-only questions to the fleet. The kinds are a fixed, read-only
	// vocabulary; nothing runs on an endpoint that it was not already
	// collecting.
	"POST /api/query":         "fixed read-only query kinds",
	"POST /api/interact/ask":  "read-only question; answered from inventory or the fixed query kinds",
	"POST /api/guide/refresh": "recomputes the tray; hides nothing",
}

// TestMutatingRoutesRequirePermission fails when a state-changing route is
// registered behind the session check alone. Sidebar visibility is not
// authorization: every POST/PUT/DELETE either names its permission at
// registration or is listed above with the reason it does not need one.
func TestMutatingRoutesRequirePermission(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	if s.routeLog == nil || len(s.routeLog.entries) == 0 {
		t.Fatal("route table was not recorded")
	}
	seen := map[string]bool{}
	var missing []string
	for _, e := range s.routeLog.entries {
		seen[e.Pattern] = true
		if !mutatingMethod(routeMethod(e.Pattern)) {
			continue
		}
		// fleet.read alone is what every route gets by default; a route
		// that changes something with nothing more than that is open to
		// every reader, and has to be listed with its reason.
		if g, ok := e.Handler.(*permGuard); ok && !(len(g.perms) == 1 && g.perms[0] == auth.PermFleetRead) {
			continue
		}
		if _, ok := openMutatingRoutes[e.Pattern]; ok {
			continue
		}
		missing = append(missing, e.Pattern)
	}
	sort.Strings(missing)
	for _, p := range missing {
		t.Errorf("mutating route %q has no permission wrapper; wrap it in perm()/permAny() or add it to openMutatingRoutes with a reason", p)
	}
	for p := range openMutatingRoutes {
		if !seen[p] {
			t.Errorf("openMutatingRoutes lists %q, which is not registered; remove it", p)
		}
	}
}

func TestSensorIntervalBounds(t *testing.T) {
	s := &Server{logger: slog.Default()}
	for _, body := range []string{
		`{"sensor":"processes","interval_seconds":2147483647}`,
		`{"sensor":"processes","interval_seconds":1}`,
		`{"sensor":"processes","interval_seconds":0}`,
		`{"sensor":"../x","interval_seconds":60}`,
		`{"sensor":"","interval_seconds":60}`,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/agents/agt-1/sensor-interval", strings.NewReader(body))
		req.SetPathValue("id", "agt-1")
		s.handleSetSensorInterval(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, rec.Code)
		}
	}
}

// Every route either names the permission it needs or reads the fleet
// (fleet.read); only the caller's own account is open to an account with
// no role. A selfRoutes entry that is not registered is a typo that would
// leave the real route behind fleet.read.
func TestEveryRouteNeedsAPermissionOrIsSelf(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	seen := map[string]bool{}
	for _, e := range s.routeLog.entries {
		seen[e.Pattern] = true
		if _, ok := e.Handler.(*permGuard); ok {
			if selfRoutes[e.Pattern] {
				t.Errorf("%q is a self route but is behind a permission", e.Pattern)
			}
			continue
		}
		if !selfRoutes[e.Pattern] {
			t.Errorf("%q has no permission guard and is not a self route", e.Pattern)
		}
	}
	for p := range selfRoutes {
		if !seen[p] {
			t.Errorf("selfRoutes lists %q, which is not registered", p)
		}
	}
}
