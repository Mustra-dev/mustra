package server

import (
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// routeTable is the protected mux plus a record of what guards each route,
// so a test can read the whole table and fail when a route that changes
// something is registered without a permission check. The record is
// presentation-free: it holds the handler as registered, and the guard
// types below identify themselves.
type routeTable struct {
	*http.ServeMux
	entries []routeEntry
	s       *Server
	actions map[string]actionSpec
}

type routeEntry struct {
	Pattern string
	Handler http.Handler
}

func (s *Server) newRouteTable() *routeTable {
	t := &routeTable{ServeMux: http.NewServeMux(), s: s, actions: s.endpointActionRoutes()}
	s.routeLog = t
	return t
}

// Handle registers a route. An endpoint-action route (endpointActionRoutes)
// is wrapped in the shared authorization gate, inside its permission
// check so an unpermitted caller learns nothing about targets. One
// registered without a permission wrapper stops the server from starting:
// the gate is not a substitute for the permission.
func (t *routeTable) Handle(pattern string, h http.Handler) {
	// A route registered without a permission wrapper reads the fleet, so
	// it needs fleet.read; only the caller's own account (selfRoutes) is
	// open to every signed-in account. Pages answer a caller without it
	// with a page saying so rather than a bare 403.
	if _, guarded := h.(*permGuard); !guarded && !selfRoutes[pattern] {
		next := h
		wrap := func(h http.Handler) http.Handler { return t.s.auth.RequirePermission(auth.PermFleetRead)(h) }
		h = &permGuard{perms: []string{auth.PermFleetRead}, check: wrap(next), next: next, wrap: wrap}
	}
	// A page the caller may not open says so, and which permission it
	// needs, in the console's own frame rather than as a line of text.
	if pg, guarded := h.(*permGuard); guarded && isPageRoute(pattern) {
		perms := pg.perms
		wrap := func(h http.Handler) http.Handler { return t.s.requirePermsPage(perms, h) }
		h = &permGuard{perms: perms, check: wrap(pg.next), next: pg.next, wrap: wrap}
	}
	if spec, ok := t.actions[pattern]; ok {
		pg, guarded := h.(*permGuard)
		if !guarded {
			panic("endpoint-action route " + pattern + " registered without a permission wrapper")
		}
		inner := t.s.gate(pattern, spec, pg.next)
		h = &permGuard{perms: pg.perms, check: pg.wrap(inner), next: inner, wrap: pg.wrap}
	}
	t.entries = append(t.entries, routeEntry{Pattern: pattern, Handler: h})
	t.ServeMux.Handle(pattern, h)
}

func (t *routeTable) HandleFunc(pattern string, f func(http.ResponseWriter, *http.Request)) {
	t.Handle(pattern, http.HandlerFunc(f))
}

// permGuard is what perm/permAny return: the permission check, labelled
// with the keys it demands so the route table can be audited.
type permGuard struct {
	perms []string
	check http.Handler // the wrapped auth middleware around next
	next  http.Handler
	wrap  func(http.Handler) http.Handler // builds check from a handler
}

func (g *permGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.check.ServeHTTP(w, r) }

// routeMethod is the method half of a "METHOD /path" pattern, or "" for a
// pattern that matches every method.
func routeMethod(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i > 0 {
		return pattern[:i]
	}
	return ""
}

// mutatingMethod reports whether a request with this method changes state.
// A pattern with no method matches POST too, so it counts.
func mutatingMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// selfRoutes are about the signed-in account itself, not the fleet: every
// account may use them, with or without a role, so someone just given an
// account can still set up two-step sign-in, read Help and see that they
// have no access yet.
var selfRoutes = map[string]bool{
	"GET /api/me":                       true,
	"GET /api/preferences":              true,
	"PUT /api/preferences":              true,
	"GET /api/me/mfa":                   true,
	"POST /api/me/mfa/setup":            true,
	"POST /api/me/mfa/enable":           true,
	"POST /api/me/mfa/recovery-codes":   true,
	"POST /api/me/mfa/disable":          true,
	"GET /api/notifications":            true,
	"GET /api/notifications/count":      true,
	"POST /api/notifications/{id}/read": true,
	"GET /api/help":                     true,
	"GET /api/help/{slug}":              true,
	"GET /help":                         true,
}

// isPageRoute reports whether a pattern serves a console page rather than
// the API.
func isPageRoute(pattern string) bool {
	path := pattern
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		path = pattern[i+1:]
	}
	return routeMethod(pattern) == http.MethodGet && !strings.HasPrefix(path, "/api/")
}
