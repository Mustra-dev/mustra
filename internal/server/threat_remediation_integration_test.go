package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// threatRemediationFixture is a real store, no broker, and one online
// endpoint with a pending update for libssl3t64. Its agent version is
// chosen per test: anything older than patchPolicyAgentVersion is refused
// before a command would be sent, which is what these tests can observe.
func threatRemediationFixture(t *testing.T, agentVersion string) (*Server, *store.Store, string) {
	t.Helper()
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
	agent := idgen.New("agt-")
	if err := st.UpsertOnRegister(ctx, agent, proto.AgentInfo{Hostname: "tr-" + agent, OS: "linux", Arch: "amd64", Version: agentVersion}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), agent) })
	if err := st.RecordHeartbeat(ctx, agent, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]proto.PatchInfo{{Name: "libssl3t64", NewVersion: "3.5.4-1"}, {Name: "curl", NewVersion: "8.18.0-2"}})
	if err := st.UpsertSensorData(ctx, agent, string(proto.SensorPatches), time.Now(), raw); err != nil {
		t.Fatal(err)
	}
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}}
	s.live.setAgent(time.Hour, 0, "")
	return s, st, agent
}

func actionFor(t *testing.T, st *store.Store, runID, agent string) store.AgentActionWithHost {
	t.Helper()
	acts, err := st.ActionsForRun(context.Background(), runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.AgentID == agent {
			return a
		}
	}
	t.Fatalf("no action for %s in run %s", agent, runID)
	return store.AgentActionWithHost{}
}

// A narrowed job never reaches an agent that would ignore the list and
// install everything; the action says why, and records what it was for.
func TestOnlyPackagesRefusesAgentsThatWouldPatchEverything(t *testing.T) {
	s, st, agent := threatRemediationFixture(t, "0.43.0")
	ctx := context.Background()
	agents, err := st.ListAgents(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var target []store.AgentRecord
	for _, a := range agents {
		if a.AgentID == agent {
			target = append(target, a)
		}
	}
	runID := idgen.New("run-")
	started, failed := s.deployPatchesToAgents(ctx, target, "tester", runID, true, patchRestart{}, map[string][]string{agent: {"libssl3t64"}})
	if len(started) != 0 || !strings.Contains(failed[agent], "cannot update only some packages") {
		t.Fatalf("started %v, failed %v", started, failed)
	}
	act := actionFor(t, st, runID, agent)
	if act.Status != "failed" || act.Summary != "Update libssl3t64" {
		t.Fatalf("action = %+v", act)
	}
	if only, err := st.ActionPatchOnly(ctx, act.ID); err != nil || len(only) != 1 || only[0] != "libssl3t64" {
		t.Fatalf("recorded list = %v, %v", only, err)
	}

	// An endpoint the request names no package for is not patched at all.
	runID = idgen.New("run-")
	started, failed = s.deployPatchesToAgents(ctx, target, "tester", runID, true, patchRestart{}, map[string][]string{"someone-else": {"curl"}})
	if len(started) != 0 || failed[agent] == "" {
		t.Fatalf("an endpoint with no packages named was dispatched: started %v failed %v", started, failed)
	}
}

// With nothing pending for the named package, the job is skipped with the
// reason instead of falling back to everything pending.
func TestOnlyPackagesWithNothingPendingIsSkipped(t *testing.T) {
	s, st, agent := threatRemediationFixture(t, "0.57.44")
	ctx := context.Background()
	agents, err := st.ListAgents(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var a *store.AgentRecord
	for i := range agents {
		if agents[i].AgentID == agent {
			a = &agents[i]
		}
	}
	if a == nil {
		t.Fatal("test agent not listed")
	}
	act := store.AgentAction{ID: idgen.New("act-"), RunID: idgen.New("run-"), AgentID: agent, Kind: "patch_apply", Summary: "t"}
	if err := st.StartAgentAction(ctx, act); err != nil {
		t.Fatal(err)
	}
	ok, why := s.dispatchPatchApply(ctx, *a, act.RunID, act.ID, patchRestart{}, []string{"zlib1g"})
	if ok || !strings.Contains(why, "No pending update for zlib1g") {
		t.Fatalf("ok=%v why=%q", ok, why)
	}
	if got := actionFor(t, st, act.RunID, agent); got.Status != "skipped" {
		t.Fatalf("action = %+v", got)
	}
}

// The hourly pass: off by default, so nothing is patched; turned on, one
// run for the vulnerable endpoint's vulnerable package, counted as an
// attempt and not repeated within the day. Past the due date, one alert.
func TestRemediateThreats(t *testing.T) {
	s, st, agent := threatRemediationFixture(t, "0.43.0")
	ctx := context.Background()
	brief := idgen.New("kev-test-")
	due := time.Now().AddDate(0, 0, -3)
	set := &threatSet{
		briefs: []threatBriefing{{ID: brief, Kind: "kev", Title: "Test OpenSSL flaw " + brief, DueDate: &due}},
		endpoints: map[string][]threatEndpoint{brief: {
			{AgentID: agent, Hostname: "tr-" + agent, OS: "linux", Online: true, Status: "vulnerable", Product: "libssl3t64", Packages: []string{"libssl3t64"}},
		}},
	}
	t.Cleanup(func() {
		_, _ = st.SyncThreatExposures(context.Background(), map[string][]string{})
		_ = st.SetSetting(context.Background(), settingThreatAutoRemediation, "", "test")
	})
	_ = st.SetSetting(ctx, settingThreatAutoRemediation, "", "test")

	countAlerts := func() int {
		ns, _, err := st.ListNotifications(ctx, "nobody", 200)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, x := range ns {
			if strings.Contains(x.Title, brief) {
				n++
			}
		}
		return n
	}
	runs := func() int {
		rs, err := st.ListPatchJobRuns(ctx, 200)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range rs {
			if r.TriggeredBy == "auto-remediation" && strings.Contains(r.TargetDesc, "1 endpoint") {
				if acts, _ := st.ActionsForRun(ctx, r.ID); len(acts) == 1 && acts[0].AgentID == agent {
					n++
				}
			}
		}
		return n
	}

	s.remediateThreats(ctx, set)
	if runs() != 0 {
		t.Fatal("patched with automatic remediation off")
	}
	if countAlerts() != 1 {
		t.Fatalf("past-due alerts = %d, want 1", countAlerts())
	}

	cfg, _ := json.Marshal(threatAutoRemediation{Enabled: true, OverdueAlerts: true})
	if err := st.SetSetting(ctx, settingThreatAutoRemediation, string(cfg), "test"); err != nil {
		t.Fatal(err)
	}
	s.remediateThreats(ctx, set)
	s.remediateThreats(ctx, set)
	if n := runs(); n != 1 {
		t.Fatalf("automatic runs = %d, want 1 (and none repeated within the day)", n)
	}
	if countAlerts() != 1 {
		t.Fatalf("the past-due alert repeated: %d", countAlerts())
	}
	ex, _ := st.SyncThreatExposures(ctx, map[string][]string{brief: {agent}})
	if e := ex[brief][agent]; e.Attempts != 1 {
		t.Fatalf("exposure = %+v", e)
	}
}

// The preview names exactly the updates a narrowed run installs: the
// vulnerable package's, not the other pending one.
func TestPatchPreviewWithOnlyPackages(t *testing.T) {
	s, _, agent := threatRemediationFixture(t, "0.57.44")
	body := `{"target_agents":["` + agent + `"],"only_packages":{"` + agent + `":["libssl3t64:amd64"]}}`
	r := httptest.NewRequest(http.MethodPost, "/api/patches/deploy/preview", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handlePatchDeployPreview(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp patchDeployPreviewResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Endpoints) != 1 || len(resp.Endpoints[0].Only) != 1 || resp.Endpoints[0].Only[0] != "libssl3t64" || resp.Endpoints[0].Pending != 2 {
		t.Fatalf("preview = %+v", resp.Endpoints)
	}
}
