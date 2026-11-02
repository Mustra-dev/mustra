package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// dispatchingRoutes are routes known to send work to endpoints (or save a
// definition the server later sends unattended). Each must be registered
// through the shared gate. When a new route reaches the bus, add it here and
// to endpointActionRoutes.
var dispatchingRoutes = []string{
	"POST /api/deploy/run", "POST /api/deploy/preview", "POST /api/deploy/test",
	"POST /api/software/deploy", "POST /api/software-inventory/product/{key}/remove-unused",
	"POST /api/patches/deploy", "POST /api/agents/{id}/apply-patches",
	"POST /api/agents/{id}/kill-process", "POST /api/agents/{id}/update", "POST /api/agents/update-outdated",
	"POST /api/clients/upgrade", "POST /api/clients/profiles/apply",
	"POST /api/enforce/policies/{id}/run", "POST /api/reveal/rules/{id}/run", "POST /api/reveal/search",
	"POST /api/schedules", "PUT /api/schedules/{id}", "POST /api/schedules/{id}/run",
	"POST /api/sensors/custom/test", "POST /api/eun/{id}/send", "POST /api/surveys/{id}/send",
	"DELETE /api/agents/{id}", "POST /api/agents/{id}/sensor-interval", "POST /api/playbooks/{id}/run",
	"POST /api/shell/sessions", "POST /api/remote/sessions", "POST /api/certificates/managed", "PUT /api/certificates/managed/{id}", "POST /api/certificates/managed/{id}/renew", "POST /api/certificates/managed/{id}/upload", "POST /api/patches/list-assignments", "POST /api/certificates/apps/credentials", "PUT /api/certificates/apps/credentials/{id}", "POST /api/certificates/apps/credentials/{id}/renew", "POST /api/jump/requests", "POST /api/shell/sessions/{id}/exec", "POST /api/compliance/policies/{id}/run",
	"POST /api/catalog/requests/{id}/decide", "POST /api/integrity/watch-status/apply", "PUT /api/deploy/settings",
	"POST /api/patches/schedules", "POST /api/enforce/policies", "PUT /api/enforce/policies/{id}",
	"POST /api/sensors/custom", "PUT /api/sensors/custom/{id}",
	"POST /api/certificates/trust/{id}", "POST /api/agents/{id}/intune/{action}",
	"POST /api/compliance/scan",
	"POST /api/patches/schedules/{id}/enabled", "DELETE /api/patches/schedules/{id}",
	"POST /api/reveal/rule-sets", "PUT /api/reveal/rule-sets/{id}",
	"POST /api/patch-policies", "PUT /api/patch-policies/{id}", "DELETE /api/patch-policies/{id}", "POST /api/patch-policies/import",
}

func TestEndpointActionRoutesAreGated(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	byPattern := map[string]http.Handler{}
	for _, e := range s.routeLog.entries {
		byPattern[e.Pattern] = e.Handler
	}
	specs := s.endpointActionRoutes()
	for _, p := range dispatchingRoutes {
		if _, ok := specs[p]; !ok {
			t.Errorf("%s dispatches to endpoints but is not in endpointActionRoutes", p)
		}
	}
	for p := range specs {
		h, ok := byPattern[p]
		if !ok {
			t.Errorf("endpointActionRoutes names %q, which is not registered (typo or removed route)", p)
			continue
		}
		pg, ok := h.(*permGuard)
		if !ok {
			t.Errorf("%s: not behind a permission wrapper", p)
			continue
		}
		if _, ok := pg.next.(*actionGate); !ok {
			t.Errorf("%s: permission wrapper does not lead to the action gate", p)
		}
	}
}

// gatedServer is a bare server whose access cache says: group "workstations"
// is agt-ws1 and agt-ws2; the deploy action group is workstations only.
func gatedServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{logger: slog.Default(), syslog: &syslogSink{}}
	s.access.members = map[string]map[string]bool{"grp-ws": {"agt-ws1": true, "agt-ws2": true}}
	s.access.actionGs = []store.ActionGroup{{Module: "deploy", GroupIDs: []string{"grp-ws"}, Enabled: true}}
	s.access.at = time.Now().Add(time.Hour)
	s.routes()
	return s
}

func serveGated(s *Server, pattern, method, path, body string, user *store.User, pv map[string]string) *httptest.ResponseRecorder {
	var h http.Handler
	for _, e := range s.routeLog.entries {
		if e.Pattern == pattern {
			h = e.Handler
		}
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range pv {
		req.SetPathValue(k, v)
	}
	req = req.WithContext(auth.WithUser(req.Context(), user))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The action-group ceiling binds even an administrator: an agent update to
// a domain controller outside the deploy action group is refused before
// the handler runs (which, on this bare server, would otherwise panic on
// the missing store).
func TestGateRefusesTargetsOutsideActionGroup(t *testing.T) {
	s := gatedServer(t)
	admin := &store.User{ID: "usr-1", Username: "root", IsAdmin: true, Active: true}
	for _, c := range []struct{ pattern, path, body string }{
		{"POST /api/agents/{id}/update", "/api/agents/agt-dc/update", ""},
		{"POST /api/deploy/run", "/api/deploy/run", `{"agent_ids":["agt-ws1","agt-dc"],"package_id":"p"}`},
		{"POST /api/software/deploy", "/api/software/deploy", `{"agent_ids":["agt-dc"]}`},
		// A push credential's renewal writes a file and runs its reload
		// command on the endpoint it names.
		{"POST /api/certificates/apps/credentials", "/api/certificates/apps/credentials",
			`{"app_name":"web","mode":"push","push_agent_id":"agt-dc","push_path":"/etc/app/secret","push_reload":"systemctl reload app"}`},
		{"PUT /api/certificates/apps/credentials/{id}", "/api/certificates/apps/credentials/acr-1",
			`{"mode":"push","push_agent_id":"agt-dc","push_path":"/etc/app/secret"}`},
	} {
		rec := serveGated(s, c.pattern, "POST", c.path, c.body, admin, map[string]string{"id": "agt-dc"})
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "action group") {
			t.Errorf("%s: %d %q, want 403 naming the action group", c.pattern, rec.Code, rec.Body.String())
		}
	}
}

// A fleet-wide operation the caller cannot fully reach is refused (not
// silently partial) where the handler cannot narrow it.
func TestGateRefusesFleetWideBeyondReach(t *testing.T) {
	s := gatedServer(t)
	admin := &store.User{ID: "usr-1", Username: "root", IsAdmin: true, Active: true}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/x", nil)
	req = req.WithContext(auth.WithUser(req.Context(), admin))
	_, ok := s.authorizeEndpointAction(rec, req, endpointAction{Module: "deploy",
		Fleet: func(context.Context) ([]string, error) { return []string{"agt-ws1", "agt-dc"}, nil }})
	if ok || rec.Code != http.StatusForbidden {
		t.Fatalf("fleet-wide beyond the action group: ok=%v code=%d, want refused", ok, rec.Code)
	}
	rec = httptest.NewRecorder()
	got, ok := s.authorizeEndpointAction(rec, req, endpointAction{Module: "deploy", NarrowFleet: true,
		Fleet: func(context.Context) ([]string, error) { return []string{"agt-ws1", "agt-dc"}, nil }})
	if !ok || len(got) != 1 || got[0] != "agt-ws1" {
		t.Fatalf("narrowable fleet: ok=%v got=%v, want [agt-ws1]", ok, got)
	}
}

// A token with no resolvable creator gets no endpoints at all.
func TestTokenWithoutCreatorHasNoScope(t *testing.T) {
	s := gatedServer(t)
	req := httptest.NewRequest("POST", "/x", nil)
	ctx := auth.WithUser(req.Context(), &store.User{ID: auth.APITokenUserID, Username: "token:x", Active: true})
	ctx = auth.WithToken(ctx, []string{auth.PermDeployManage}, &auth.TokenInfo{ID: "tok-1", Name: "x"})
	scope, err := s.endpointScope(ctx)
	if err != nil || scope == nil || len(scope) != 0 {
		t.Fatalf("scope = %v, %v; want empty, non-nil", scope, err)
	}
	ok, _ := s.contentAllowed(ctx, "packages", "p")
	if ok {
		t.Fatal("content allowed for a token with no creator")
	}
}

// An empty explicit list means "every eligible endpoint", like an omitted
// one. Returned as an empty allowed set it made the software deploy
// handler narrow an administrator's fleet-wide deployment to nothing
// (found upgrading a live fleet: the console's "every eligible endpoint"
// sends agent_ids: [] and reported targets=0, skipped=4).
func TestEmptyExplicitListIsNotAnEmptyAllowedSet(t *testing.T) {
	s := gatedServer(t)
	admin := &store.User{ID: "usr-1", Username: "root", IsAdmin: true, Active: true}
	req := httptest.NewRequest("POST", "/x", nil)
	req = req.WithContext(auth.WithUser(req.Context(), admin))
	for _, explicit := range [][]string{nil, {}} {
		rec := httptest.NewRecorder()
		got, ok := s.authorizeEndpointAction(rec, req, endpointAction{Explicit: explicit, NarrowFleet: true,
			Fleet: func(context.Context) ([]string, error) { return []string{"agt-ws1", "agt-dc"}, nil }})
		if !ok || got != nil {
			t.Errorf("Explicit=%#v: ok=%v allowed=%#v, want ok and nil (no narrowing)", explicit, ok, got)
		}
	}
}

// Revoking an endpoint's credential and setting its criticality act on
// that endpoint, so an operator whose management rights do not reach it is
// refused before the handler runs. Both used to skip the gate: a scan
// found an operator scoped to one group revoking credentials of endpoints
// in another.
func TestEndpointRecordRoutesRespectManagementRights(t *testing.T) {
	s := gatedServer(t)
	for _, c := range []struct{ pattern, path, body string }{
		{"POST /api/agents/{id}/revoke-credential", "/api/agents/agt-ws1/revoke-credential", ""},
		{"POST /api/risk/criticality", "/api/risk/criticality", `{"agent_id":"agt-ws1","level":"critical"}`},
	} {
		var gate http.Handler
		for _, e := range s.routeLog.entries {
			if e.Pattern == c.pattern {
				if pg, ok := e.Handler.(*permGuard); ok {
					gate = pg.next
				}
			}
		}
		if _, ok := gate.(*actionGate); !ok {
			t.Fatalf("%s is not behind the action gate", c.pattern)
		}
		req := httptest.NewRequest("POST", c.path, strings.NewReader(c.body))
		req.SetPathValue("id", "agt-ws1")
		// A token whose creator cannot be resolved manages nothing: the
		// narrowest scope there is, reachable without a store.
		ctx := auth.WithUser(req.Context(), &store.User{ID: auth.APITokenUserID, Username: "token:x", Active: true})
		ctx = auth.WithToken(ctx, []string{auth.PermDeployManage, auth.PermPatchesManage}, &auth.TokenInfo{ID: "tok-1", Name: "x"})
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "management rights") {
			t.Errorf("%s: %d %q, want 403 naming management rights", c.pattern, rec.Code, rec.Body.String())
		}
	}
}

// A repository list assignment decides where an endpoint installs patches
// from, so it is refused for an endpoint outside the patches action group,
// named or matched by site.
func TestGateRefusesRepositoryListBeyondReach(t *testing.T) {
	s := gatedServer(t)
	s.access.actionGs = append(s.access.actionGs, store.ActionGroup{Module: "patches", GroupIDs: []string{"grp-ws"}, Enabled: true})
	admin := &store.User{ID: "usr-1", Username: "root", IsAdmin: true, Active: true}
	rec := serveGated(s, "POST /api/patches/list-assignments", "POST", "/api/patches/list-assignments",
		`{"patch_list_id":"plist-1","target_agent":"agt-dc"}`, admin, nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "action group") {
		t.Errorf("named endpoint: %d %q, want 403 naming the action group", rec.Code, rec.Body.String())
	}
}
