package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// An approved request runs as its requester, and only with the authority
// the requester still has when it is approved: a request can wait hours,
// and the approver needs only approvals.decide. A disabled requester, or
// one who lost the route's permission meanwhile, gets nothing run.
func TestApprovalReplayRechecksTheRequester(t *testing.T) {
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
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}}
	s.auth = auth.New(ctx, st, nil, false, slog.Default())

	// A gated route registered the way httpapi.go registers it, so its
	// replay is the gate behind the route's permission check. The handler
	// only records that it ran.
	ran := 0
	tbl := s.newRouteTable()
	wrap := func(h http.Handler) http.Handler { return s.auth.RequirePermission(auth.PermDeployManage)(h) }
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ran++ })
	tbl.Handle("POST /api/agents/{id}/update", &permGuard{perms: []string{auth.PermDeployManage}, check: wrap(stub), next: stub, wrap: wrap})

	newUser := func(perms ...string) *store.User {
		u, err := st.CreateLocalUser(ctx, idgen.New("usr-"), idgen.New("replay-"), "", "replay test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteUser(context.Background(), u.ID) })
		role, err := st.CreateRole(ctx, idgen.New("role-"), idgen.New("replay-role-"), "", perms, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteRole(context.Background(), role.ID) })
		if err := st.AssignUserRole(ctx, u.ID, role.ID); err != nil {
			t.Fatal(err)
		}
		return u
	}
	replay := func(u *store.User, handler, method, path string, pathValues map[string]string) string {
		t.Helper()
		body, _ := json.Marshal(parkedRequest{Handler: handler, Body: json.RawMessage(`{}`), PathValues: pathValues})
		exp := time.Now().Add(time.Hour)
		req := store.ApprovalRequest{ID: idgen.New("apr-"), Module: "deploy", Summary: "replay test", Method: method,
			Path: path, Body: body, RequestedBy: u.Username, ExpiresAt: &exp}
		if err := st.CreateApprovalRequest(ctx, req); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetApprovalRequest(ctx, req.ID)
		if err != nil {
			t.Fatal(err)
		}
		s.runApproved(ctx, *got)
		done, err := st.GetApprovalRequest(ctx, req.ID)
		if err != nil {
			t.Fatal(err)
		}
		return done.State + ": " + done.Outcome
	}
	playbook := func(u *store.User) string {
		return replay(u, "playbooks.run", "POST", "/api/playbooks/pb-none/run", map[string]string{"id": "pb-none"})
	}
	update := func(u *store.User) string {
		return replay(u, "POST /api/agents/{id}/update", "POST", "/api/agents/agt-none/update", map[string]string{"id": "agt-none"})
	}

	// Control: a requester who still holds deploy.manage reaches the
	// handler (here it finds no such playbook).
	ok := newUser(auth.PermDeployManage, auth.PermFleetRead)
	if got := playbook(ok); !strings.Contains(got, "no such playbook") {
		t.Fatalf("a permitted requester did not reach the handler: %s", got)
	}

	// Lost the permission while the request waited.
	lost := newUser(auth.PermFleetRead)
	if got := playbook(lost); !strings.HasPrefix(got, "failed") || !strings.Contains(got, auth.PermDeployManage) {
		t.Errorf("playbooks.run replayed for a requester without deploy.manage: %s", got)
	}
	if got := update(lost); !strings.HasPrefix(got, "failed") || !strings.Contains(got, auth.PermDeployManage) || ran != 0 {
		t.Errorf("a gated route replayed for a requester without deploy.manage (ran %d): %s", ran, got)
	}

	// Disabled while the request waited, still holding the permission.
	off := newUser(auth.PermDeployManage, auth.PermFleetRead)
	if _, err := st.SetUserActive(ctx, off.ID, false); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(*store.User) string{"playbooks.run": playbook, "agent update": update} {
		if got := run(off); !strings.HasPrefix(got, "failed") || !strings.Contains(got, "disabled") || ran != 0 {
			t.Errorf("%s replayed for a disabled requester (ran %d): %s", name, ran, got)
		}
	}
}
