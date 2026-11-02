package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// The overview's counts mean what the tiles say. The database is shared,
// so each case reads the overview before and after adding its own rows
// and checks the difference.
func TestRevealOverviewCounts(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}}
	s.live.setAgent(time.Hour, 0, "")

	overview := func(t *testing.T) revealOverviewResponse {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleRevealOverview(w, httptest.NewRequest(http.MethodGet, "/api/reveal/overview", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		var out revealOverviewResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	rule := func(t *testing.T, kind string) string {
		t.Helper()
		id := idgen.New("rvl-test-")
		if err := st.UpsertRevealRule(ctx, store.RevealRule{ID: id, Name: "overview " + kind, Kind: kind, Enabled: true,
			Roots: map[string][]string{"linux": {"/home"}}, PatternIDs: []string{"aws_access_key"}, IntervalHours: 24, CreatedBy: "test"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteRevealRule(context.Background(), id) })
		return id
	}

	t.Run("rules counts rules, not quick searches", func(t *testing.T) {
		before := overview(t)
		rule(t, "rule")
		rule(t, "quick")
		after := overview(t)
		if d := after.Rules - before.Rules; d != 1 {
			t.Errorf("rules went up by %d for one rule and one quick search, want 1", d)
		}
		if d := after.RulesEnabled - before.RulesEnabled; d != 1 {
			t.Errorf("rules_enabled went up by %d, want 1", d)
		}
	})

	t.Run("an endpoint whose scan never started is not scanned", func(t *testing.T) {
		ruleID := rule(t, "rule")
		report := func(errText string) string {
			t.Helper()
			agent := idgen.New("agt-")
			if err := st.UpsertOnRegister(ctx, agent, proto.AgentInfo{Hostname: "reveal-" + agent, OS: "linux", Arch: "amd64"}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), agent) })
			now := time.Now().UTC().Format(time.RFC3339)
			if err := st.RecordRevealReport(ctx, proto.RevealReport{ScanID: idgen.New("scan-"), RuleID: ruleID, AgentID: agent,
				Started: now, Finished: now, Error: errText, Matches: []proto.RevealMatch{}}); err != nil {
				t.Fatal(err)
			}
			return agent
		}
		before := overview(t)
		report("not started: unknown command: reveal_scan")
		if d := overview(t).Summary.EndpointsScanned - before.Summary.EndpointsScanned; d != 0 {
			t.Errorf("a refused scan counted as %d endpoint(s) scanned, want 0", d)
		}
		scanned := report("")
		if d := overview(t).Summary.EndpointsScanned - before.Summary.EndpointsScanned; d != 1 {
			t.Errorf("a finished scan counted as %d endpoint(s) scanned, want 1", d)
		}
		// The tile divides by the endpoints enrolled now.
		if err := st.DeleteAgent(ctx, scanned); err != nil {
			t.Fatal(err)
		}
		if d := overview(t).Summary.EndpointsScanned - before.Summary.EndpointsScanned; d != 0 {
			t.Errorf("a deleted endpoint still counts: %d more scanned than before, want 0", d)
		}
	})
}
