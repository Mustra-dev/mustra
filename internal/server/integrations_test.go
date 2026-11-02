package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestIntegrationDeliveryFormats(t *testing.T) {
	type got struct {
		path, auth, sig string
		body            map[string]any
	}
	var last got
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		last = got{path: r.URL.Path, auth: r.Header.Get("Authorization"), sig: r.Header.Get("X-Mustra-Signature")}
		_ = json.Unmarshal(raw, &last.body)
		if last.sig != "" {
			mac := hmac.New(sha256.New, []byte("s3cret"))
			mac.Write(raw)
			if last.sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
				t.Error("webhook signature does not match the body")
			}
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	s := &Server{logger: slog.Default()}
	ev := integrationEvent{Type: "alert", Time: time.Unix(1760000000, 0).UTC(), Severity: "warning", Title: "Certificate renewal failed: pi.hole", Body: "reload failed"}
	send := func(kind, secret string, cfg map[string]string) {
		t.Helper()
		if cfg == nil {
			cfg = map[string]string{}
		}
		cfg["url"] = srv.URL
		in := store.Integration{ID: "int-1", Kind: kind, Config: cfg}
		if secret != "" {
			in.Secret = "plain:" + secret
		}
		if err := s.deliverEvent(context.Background(), in, ev); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}

	send("webhook", "s3cret", nil)
	if last.sig == "" || last.body["title"] != ev.Title || last.body["type"] != "alert" {
		t.Errorf("webhook: %+v", last)
	}
	send("splunk_hec", "hec-token", map[string]string{"index": "mustra"})
	if last.path != "/services/collector/event" || last.auth != "Splunk hec-token" || last.body["sourcetype"] != "mustra:alert" || last.body["index"] != "mustra" {
		t.Errorf("splunk: %+v", last)
	}
	send("loki", "user:pass", nil)
	if last.path != "/loki/api/v1/push" || last.auth != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")) {
		t.Errorf("loki: %+v", last)
	}
	streams, _ := last.body["streams"].([]any)
	if len(streams) != 1 || !strings.Contains(asJSON(streams[0]), `"severity":"warning"`) {
		t.Errorf("loki stream: %v", last.body)
	}
	send("servicenow", "svc:pw", map[string]string{"assignment_group": "IT"})
	if last.path != "/api/now/table/incident" || !strings.HasPrefix(last.auth, "Basic ") || last.body["urgency"] != "2" ||
		!strings.Contains(last.body["short_description"].(string), "pi.hole") || last.body["assignment_group"] != "IT" {
		t.Errorf("servicenow: %+v", last)
	}
	send("teams", "", nil)
	if !strings.Contains(asJSON(last.body), "AdaptiveCard") {
		t.Errorf("teams: %v", last.body)
	}
	send("discord", "", nil)
	if !strings.Contains(last.body["content"].(string), "[WARNING]") {
		t.Errorf("discord: %v", last.body)
	}
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
