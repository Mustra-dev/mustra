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
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// patchDeployAuditFixture is "Deploy now" against a real store: one online
// endpoint on a site of its own, and an administrator whose name is unique
// to the test, so the audit rows it reads are the ones this request wrote.
type patchDeployAuditFixture struct {
	s     *Server
	st    *store.Store
	agent string
	site  string
	user  *store.User
}

func newPatchDeployAuditFixture(t *testing.T) *patchDeployAuditFixture {
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

	f := &patchDeployAuditFixture{st: st, agent: idgen.New("agt-"), site: idgen.New("site-")}
	// Older than patchRestartAgentVersion, so a request asking for a
	// restart is refused per endpoint before anything is sent: these tests
	// have no broker, and the audit row is written before dispatch anyway.
	if err := st.UpsertOnRegister(ctx, f.agent, proto.AgentInfo{
		Hostname: "patch-audit-" + f.agent, OS: "linux", Arch: "amd64", Site: f.site, Version: "0.50.0",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordHeartbeat(ctx, f.agent, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.user = &store.User{ID: idgen.New("usr-"), Username: idgen.New("patch-auditor-"), IsAdmin: true, Active: true}
	f.s = &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}}
	f.s.live.setAgent(time.Hour, 0, "")
	return f
}

func (f *patchDeployAuditFixture) deploy(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/patches/deploy", strings.NewReader(body))
	r = r.WithContext(auth.WithUser(r.Context(), f.user))
	w := httptest.NewRecorder()
	f.s.handleDeployPatchesBulk(w, r)
	return w
}

// rows returns this test's patches.* audit rows, keyed by action.
func (f *patchDeployAuditFixture) rows(t *testing.T) map[string][]store.AuditEvent {
	t.Helper()
	evs, err := f.st.ListAuditEvents(context.Background(), "patches.", f.user.Username, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]store.AuditEvent{}
	for _, e := range evs {
		out[e.Action] = append(out[e.Action], e)
	}
	return out
}

// outsideActionGroup confines the patches action group to a group the
// fixture's endpoint is not in, through the access cache as gatedServer
// does, so no other test sees it. The action group binds administrators
// too, which puts the endpoint out of reach without a role setup.
func (f *patchDeployAuditFixture) outsideActionGroup() {
	f.s.access.members = map[string]map[string]bool{"grp-elsewhere": {"agt-elsewhere": true}}
	f.s.access.actionGs = []store.ActionGroup{{Module: "patches", GroupIDs: []string{"grp-elsewhere"}, Enabled: true}}
	f.s.access.at = time.Now().Add(time.Hour)
}

// A request refused as malformed never reached an endpoint and writes no
// row, as with every other endpoint action. It used to be recorded as a
// successful fleet-wide deployment.
func TestDeployPatchesAuditBadRequestWritesNoRow(t *testing.T) {
	f := newPatchDeployAuditFixture(t)
	for _, body := range []string{
		`{"target_agents":`,
		`{"target_agents":["` + idgen.New("agt-") + `"]}`,
		`{"target_agents":["` + f.agent + `"],"restart_mode":"sometimes"}`,
	} {
		if w := f.deploy(t, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400: %s", body, w.Code, w.Body)
		}
	}
	if rows := f.rows(t); len(rows) != 0 {
		t.Fatalf("a refused request left audit rows: %+v", rows)
	}
}

// A named endpoint out of reach is refused, and the refusal is the only
// row: patches.denied, not a deployment.
func TestDeployPatchesAuditOutOfReachTargetIsDenied(t *testing.T) {
	f := newPatchDeployAuditFixture(t)
	f.outsideActionGroup()
	if w := f.deploy(t, `{"target_agents":["`+f.agent+`"]}`); w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", w.Code, w.Body)
	}
	rows := f.rows(t)
	if len(rows["patches.deploy"]) != 0 {
		t.Fatalf("a refused deployment was recorded as one: %+v", rows["patches.deploy"])
	}
	if d := rows["patches.denied"]; len(d) != 1 || d[0].Outcome != "denied" {
		t.Fatalf("want one denied row, got %+v", rows)
	}
}

// A fleet-wide request whose every endpoint falls outside the action group
// is narrowed to nothing and refused; that refusal is recorded too.
func TestDeployPatchesAuditFleetNarrowedToNothingIsDenied(t *testing.T) {
	f := newPatchDeployAuditFixture(t)
	f.outsideActionGroup()
	if w := f.deploy(t, `{"target_site":"`+f.site+`"}`); w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", w.Code, w.Body)
	}
	rows := f.rows(t)
	if len(rows["patches.deploy"]) != 0 {
		t.Fatalf("a refused deployment was recorded as one: %+v", rows["patches.deploy"])
	}
	d := rows["patches.denied"]
	if len(d) != 1 || d[0].Outcome != "denied" || !strings.Contains(d[0].Target, "site="+f.site) {
		t.Fatalf("want one denied row naming the target, got %+v", rows)
	}
}

// A request an approval policy parks has not started anything. Its row is
// the approval request, not a deployment.
func TestDeployPatchesAuditParkedIsNotStarted(t *testing.T) {
	f := newPatchDeployAuditFixture(t)
	ctx := context.Background()
	policy := store.ApprovalPolicy{ID: idgen.New("apol-"), Name: idgen.New("patch-audit-policy-"), Module: "patches", Enabled: true}
	if err := f.st.UpsertApprovalPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.st.DeleteApprovalPolicy(context.Background(), policy.ID) })

	if w := f.deploy(t, `{"target_agents":["`+f.agent+`"]}`); w.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202: %s", w.Code, w.Body)
	}
	rows := f.rows(t)
	if len(rows["patches.deploy"]) != 0 {
		t.Fatalf("a parked deployment was recorded as started: %+v", rows["patches.deploy"])
	}
	if len(rows["patches.approval_requested"]) != 1 {
		t.Fatalf("want one approval_requested row, got %+v", rows)
	}
}

// A deployment that starts is recorded once, naming the endpoints it was
// aimed at rather than the fleet, against the run it started.
func TestDeployPatchesAuditStartedNamesTargets(t *testing.T) {
	f := newPatchDeployAuditFixture(t)
	w := f.deploy(t, `{"target_agents":["`+f.agent+`"],"restart_mode":"always"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	var resp deployPatchesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	rows := f.rows(t)
	if len(rows) != 1 || len(rows["patches.deploy"]) != 1 {
		t.Fatalf("want exactly one patches.deploy row, got %+v", rows)
	}
	ev := rows["patches.deploy"][0]
	if ev.Target != resp.TargetDesc || ev.Target == "fleet" || ev.Target == "all agents" {
		t.Errorf("target %q, want the request's own %q", ev.Target, resp.TargetDesc)
	}
	if ev.Outcome != "ok" || ev.AgentID != f.agent {
		t.Errorf("outcome %q agent %q, want ok on %s", ev.Outcome, ev.AgentID, f.agent)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(ev.Detail), &detail); err != nil {
		t.Fatalf("detail %q: %v", ev.Detail, err)
	}
	if detail["run_id"] != resp.RunID || detail["endpoints"] != float64(1) {
		t.Errorf("detail %v, want run %s on 1 endpoint", detail, resp.RunID)
	}
}
