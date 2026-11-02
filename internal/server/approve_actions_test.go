package server

import (
	"context"
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

// A request waiting on a decision reaches chat with buttons that open
// /approve on the public URL: Slack Block Kit link buttons, Teams
// Adaptive Card OpenUrl actions, Discord markdown links, and the actions
// array in a plain webhook.
func TestApprovalActionsInChat(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = nil
		_ = json.Unmarshal(raw, &body)
	}))
	defer srv.Close()
	s := &Server{logger: slog.Default(), trust: &agentTrust{publicURLEnv: "https://m.example"}}
	ev := integrationEvent{Type: "alert", Time: time.Now(), Severity: "notice", Title: "alice is asking for access to web01", Body: "deploy fix",
		Link: "/access#jump", Actions: []eventAction{
			{Label: "Approve", Link: "/approve?kind=jump&id=jg-1&decision=approve", Style: "primary"},
			{Label: "Deny", Link: "/approve?kind=jump&id=jg-1&decision=deny", Style: "danger"}}}
	send := func(kind string) string {
		t.Helper()
		if err := s.deliverEvent(context.Background(), store.Integration{Kind: kind, Config: map[string]string{"url": srv.URL}}, ev); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(body)
		return string(raw)
	}
	want := "https://m.example/approve?kind=jump\\u0026id=jg-1\\u0026decision=approve"
	if out := send("slack"); !strings.Contains(out, `"type":"actions"`) || !strings.Contains(out, want) || !strings.Contains(out, `"style":"danger"`) {
		t.Errorf("slack: %s", out)
	}
	if out := send("teams"); !strings.Contains(out, "Action.OpenUrl") || !strings.Contains(out, want) || !strings.Contains(out, `"style":"destructive"`) {
		t.Errorf("teams: %s", out)
	}
	if out := send("discord"); !strings.Contains(out, "[Approve](https://m.example/approve?kind=jump") {
		t.Errorf("discord: %s", out)
	}
	if out := send("webhook"); !strings.Contains(out, `"actions":[`) || !strings.Contains(out, want) || !strings.Contains(out, `"link":"https://m.example/access#jump"`) {
		t.Errorf("webhook: %s", out)
	}
}
