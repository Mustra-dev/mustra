package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func csrfProbe(t *testing.T, method, path string, headers map[string]string) int {
	t.Helper()
	s := &Server{logger: slog.Default()}
	reached := false
	h := s.secureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(method, "http://console.example:8080"+path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusTeapot != reached {
		t.Fatalf("inconsistent: code %d reached %v", rec.Code, reached)
	}
	return rec.Code
}

func TestCSRFRefusesCrossOriginStateChanges(t *testing.T) {
	refused := []map[string]string{
		{"Origin": "https://evil.example"},
		{"Origin": "http://console.example:8081"},
		{"Origin": "null"},
		{"Origin": "http://console.example.evil.example:8080"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Referer": "https://evil.example/x"},
		// A cookie is not a bearer token; only the header counts.
		{"Origin": "https://evil.example", "Cookie": "mustra_session=x"},
	}
	for _, h := range refused {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if code := csrfProbe(t, m, "/api/deploy/run", h); code != http.StatusForbidden {
				t.Errorf("%s with %v = %d, want 403", m, h, code)
			}
		}
	}
	// Login and setup are forms a login-CSRF would target.
	for _, p := range []string{"/login/local", "/setup", "/logout"} {
		if code := csrfProbe(t, http.MethodPost, p, map[string]string{"Origin": "https://evil.example"}); code != http.StatusForbidden {
			t.Errorf("POST %s cross-origin = %d, want 403", p, code)
		}
	}
}

func TestCSRFAllowsSameOriginAndNonBrowserCallers(t *testing.T) {
	allowed := []struct {
		method, path string
		h            map[string]string
	}{
		{"POST", "/api/deploy/run", map[string]string{"Origin": "http://console.example:8080"}},
		{"POST", "/api/deploy/run", map[string]string{"Origin": "HTTP://CONSOLE.EXAMPLE:8080"}},
		{"POST", "/api/deploy/run", map[string]string{"Sec-Fetch-Site": "same-origin"}},
		{"POST", "/api/deploy/run", map[string]string{"Referer": "http://console.example:8080/software"}},
		{"POST", "/api/deploy/run", nil}, // curl, scripts
		// Bearer-authenticated: API tokens and SCIM.
		{"POST", "/api/deploy/run", map[string]string{"Authorization": "Bearer mstr_x", "Origin": "https://ci.example"}},
		{"PATCH", "/scim/v2/Users/u", map[string]string{"Authorization": "Bearer scim", "Sec-Fetch-Site": "cross-site"}},
		// Outside systems posting to a playbook webhook.
		{"POST", "/hooks/playbook/tok", map[string]string{"Origin": "https://alerts.example"}},
		// Reads are never refused.
		{"GET", "/api/agents", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}},
	}
	for _, c := range allowed {
		if code := csrfProbe(t, c.method, c.path, c.h); code != http.StatusTeapot {
			t.Errorf("%s %s with %v = %d, want it allowed", c.method, c.path, c.h, code)
		}
	}
}

func TestCSRFTrustedOrigins(t *testing.T) {
	tr := trustedOrigins("https://mustra.example.com, bogus, ftp://x")
	r := httptest.NewRequest("POST", "http://server:8080/api/x", nil)
	r.Header.Set("Origin", "https://mustra.example.com")
	if reason := crossOriginReason(r, tr); reason != "" {
		t.Fatalf("trusted origin refused: %s", reason)
	}
	r.Header.Set("Origin", "http://mustra.example.com")
	if crossOriginReason(r, tr) == "" {
		t.Fatal("scheme must be part of a trusted origin")
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s := &Server{logger: slog.Default()}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	for k, want := range map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Referrer-Policy":            "same-origin",
		"Cross-Origin-Opener-Policy": "same-origin",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if rec.Header().Get("Permissions-Policy") == "" {
		t.Error("missing Permissions-Policy")
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent in plain-HTTP mode")
	}
	s.cfg.CookieSecure = true
	rec = httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS in secure-cookie mode")
	}
}

func TestBodyLimits(t *testing.T) {
	s := &Server{logger: slog.Default()}
	var readErr error
	h := s.secureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.Copy(io.Discard, r.Body)
	}))
	big := strings.Repeat("x", defaultBodyLimit+1)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/dashboards", strings.NewReader(big)))
	if readErr == nil {
		t.Fatal("a body past the default limit was read in full")
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/login/local", strings.NewReader(strings.Repeat("x", unauthBodyLimit+1))))
	if readErr == nil {
		t.Fatal("an unauthenticated form past its limit was read in full")
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/software/sw-1/files", strings.NewReader(big)))
	if readErr != nil {
		t.Fatalf("an upload route was held to the JSON limit: %v", readErr)
	}
}
