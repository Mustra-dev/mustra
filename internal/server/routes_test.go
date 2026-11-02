package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRoutesRegisterWithoutConflict builds the real mux. Go's ServeMux
// panics at registration when two patterns are ambiguous, which is a
// process crash at startup rather than a compile error — 0.57.0's first
// build died on /api/software/inventory/{key} against
// /api/software/{id}/applicability. Method values are read lazily by the
// handlers, so a bare Server with a logger is enough to register.
func TestRoutesRegisterWithoutConflict(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("routes() panicked: %v", r)
		}
	}()
	s := &Server{logger: slog.Default()}
	if s.routes() == nil {
		t.Fatal("no handler")
	}
}

// TestHealthzIsUnauthenticated drives the real router. Compose's healthcheck
// and any reverse proxy probe /healthz without a session, so if it ever moved
// behind `protected` the stack would report itself unhealthy forever and
// `docker compose up --wait` would never return. A bare Server has no store,
// so the handler's own "not ready" is the proof it was reached: a redirect to
// /login would mean the route had been wrapped.
func TestHealthzIsUnauthenticated(t *testing.T) {
	s := &Server{logger: slog.Default()}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /healthz = %d, want %d (a redirect means it is behind auth)",
			rec.Code, http.StatusServiceUnavailable)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Fatalf("GET /healthz redirected to %q; it must not require a session", got)
	}
}
