package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestCheckWebhookURL(t *testing.T) {
	allowed := map[string]bool{"siem.internal.example": true}
	for _, c := range []struct {
		url string
		ok  bool
	}{
		{"https://discord.com/api/webhooks/1/x", true},
		{"https://siem.internal.example/ingest", true},
		{"http://siem.internal.example:3100/loki/api/v1/push", true},
		{"http://hooks.example.com/x", false},
		{"ftp://hooks.example.com/x", false},
		{"file:///etc/passwd", false},
		{"/relative", false},
		{"", false},
	} {
		if err := checkWebhookURL(c.url, allowed); (err == nil) != c.ok {
			t.Errorf("checkWebhookURL(%q) = %v, want ok=%v", c.url, err, c.ok)
		}
	}
}

// A Connect or report webhook used to be posted with a plain http.Client,
// so settings.manage could aim it at loopback, the metadata service or any
// internal host. Now an internal target needs an administrator's allowlist.
func TestWebhookDeliveryRefusesInternalAddressesUnlessAllowlisted(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	cfg := store.ExportConfig{Destination: "webhook", Target: srv.URL + "/hook"}

	t.Setenv("MUSTRA_WEBHOOK_ALLOWED_HOSTS", "")
	if err := s.deliverWebhook(ctx, cfg, []byte("x"), "text/plain"); err == nil {
		t.Fatal("plain http to an un-allowlisted loopback host was delivered")
	}
	https := cfg
	https.Target = strings.Replace(srv.URL, "http://", "https://", 1) + "/hook"
	if err := s.deliverWebhook(ctx, https, []byte("x"), "text/plain"); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("https to loopback should be refused at dial time, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the refused webhooks reached the server")
	}

	t.Setenv("MUSTRA_WEBHOOK_ALLOWED_HOSTS", "127.0.0.1")
	if err := s.deliverWebhook(ctx, cfg, []byte("x"), "text/plain"); err != nil {
		t.Fatalf("allowlisted internal host refused: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	var landed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { landed.Add(1) }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	t.Setenv("MUSTRA_WEBHOOK_ALLOWED_HOSTS", "127.0.0.1")
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := s.deliverWebhook(context.Background(), store.ExportConfig{Destination: "webhook", Target: redirector.URL}, []byte("x"), "text/plain")
	if err == nil {
		t.Error("a redirect answer should be reported, not treated as delivered")
	}
	if landed.Load() != 0 {
		t.Error("the webhook followed a redirect to a host nobody configured")
	}
}
