package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func guardedEcho() (*selfServiceGuard, *bool) {
	hit := new(bool)
	g := newSelfServiceGuard("127.0.0.1:8137", "tok123", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hit = true
	}))
	return g, hit
}

func TestSelfServiceGuard(t *testing.T) {
	cases := []struct {
		name   string
		method string
		host   string
		hdr    map[string]string
		ok     bool
	}{
		{"window GET", "GET", "127.0.0.1:8137", nil, true},
		{"localhost GET", "GET", "localhost:8137", nil, true},
		{"rebinding GET", "GET", "evil.example:8137", nil, false},
		{"rebinding POST", "POST", "attacker.example", map[string]string{"X-Mustra-Token": "tok123", "Content-Type": "application/json"}, false},
		{"good POST", "POST", "127.0.0.1:8137", map[string]string{"X-Mustra-Token": "tok123", "Content-Type": "application/json; charset=utf-8", "Origin": "http://127.0.0.1:8137"}, true},
		{"tray POST without Origin", "POST", "127.0.0.1:8137", map[string]string{"X-Mustra-Token": "tok123", "Content-Type": "application/json"}, true},
		{"CSRF form POST", "POST", "127.0.0.1:8137", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil.example"}, false},
		{"CSRF text/plain with stolen-less token", "POST", "127.0.0.1:8137", map[string]string{"Content-Type": "text/plain", "Origin": "null"}, false},
		{"wrong token", "POST", "127.0.0.1:8137", map[string]string{"X-Mustra-Token": "nope", "Content-Type": "application/json"}, false},
		{"token but foreign Origin", "POST", "127.0.0.1:8137", map[string]string{"X-Mustra-Token": "tok123", "Content-Type": "application/json", "Origin": "https://evil.example"}, false},
		{"token but text/plain", "POST", "127.0.0.1:8137", map[string]string{"X-Mustra-Token": "tok123", "Content-Type": "text/plain"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, hit := guardedEcho()
			req := httptest.NewRequest(c.method, "/api/install", strings.NewReader("{}"))
			req.Host = c.host
			for k, v := range c.hdr {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			g.ServeHTTP(rec, req)
			if *hit != c.ok {
				t.Fatalf("reached handler = %v, want %v (status %d)", *hit, c.ok, rec.Code)
			}
		})
	}
}

func TestWindowCSPNonce(t *testing.T) {
	page := string(withScriptNonce(withSelfServiceToken([]byte("<html><head></head><body><script>x()</script></body></html>"), "t"), "n0nce"))
	if strings.Count(page, `<script nonce="n0nce">`) != 2 || strings.Contains(page, "<script>") {
		t.Fatalf("not every script carries the nonce: %s", page)
	}
	csp := selfServiceCSP("n0nce")
	if !strings.Contains(csp, "script-src 'nonce-n0nce'") || strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "unsafe-inline") ||
		!strings.Contains(csp, "style-src-attr 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP: %s", csp)
	}
}

func TestWindowCarriesTheToken(t *testing.T) {
	page := string(withSelfServiceToken([]byte("<!doctype html><html><head><title>x</title></head></html>"), "abc\"<"))
	if !strings.Contains(page, `<head><meta name="mustra-session" content="abc&#34;&lt;">`) {
		t.Fatalf("token not embedded (escaped) at the top of <head>: %s", page)
	}
	if !strings.Contains(page, "X-Mustra-Token") || !strings.Contains(page, "application/json") {
		t.Fatal("the window's POSTs would not carry the token and a JSON content type")
	}
}
