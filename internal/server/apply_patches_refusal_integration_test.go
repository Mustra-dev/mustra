package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// applyPatches posts to /api/agents/{id}/apply-patches as u.
func (f *patchDeployAuditFixture) applyPatches(t *testing.T, u *store.User, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/agents/"+id+"/apply-patches", strings.NewReader(body))
	r.SetPathValue("id", id)
	r = r.WithContext(auth.WithUser(r.Context(), u))
	w := httptest.NewRecorder()
	f.s.handleApplyPatches(w, r)
	return w
}

// runsNaming returns the recorded deployments whose target names any of
// the given endpoint IDs or hostnames, which are unique to the test.
func (f *patchDeployAuditFixture) runsNaming(t *testing.T, names ...string) []store.PatchJobRun {
	t.Helper()
	runs, err := f.st.ListPatchJobRuns(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.PatchJobRun
	for _, run := range runs {
		for _, n := range names {
			if strings.Contains(run.TargetDesc, n) {
				out = append(out, run)
				break
			}
		}
	}
	return out
}

// A one-off apply that is refused never started a deployment, so it leaves
// none in Deployments: not for an endpoint the inventory lacks, not for an
// override its user may not ask for, and not for a restart option the
// agent would not understand.
func TestApplyPatchesRefusedRecordsNoRun(t *testing.T) {
	f := newPatchDeployAuditFixture(t)
	f.s.auth = auth.New(context.Background(), f.st, nil, false, slog.Default())
	operator := &store.User{ID: idgen.New("usr-"), Username: idgen.New("patch-operator-"), Active: true}
	unknown := idgen.New("agt-")
	hostname := "patch-audit-" + f.agent

	for _, c := range []struct {
		name string
		user *store.User
		id   string
		body string
		want int
	}{
		{"unknown endpoint", f.user, unknown, `{}`, http.StatusNotFound},
		{"override without permission", operator, f.agent, `{"override_windows":true}`, http.StatusForbidden},
		{"bad restart option", f.user, f.agent, `{"restart_mode":"sometimes"}`, http.StatusBadRequest},
	} {
		if w := f.applyPatches(t, c.user, c.id, c.body); w.Code != c.want {
			t.Errorf("%s: status %d, want %d: %s", c.name, w.Code, c.want, w.Body)
		}
	}
	if runs := f.runsNaming(t, unknown, hostname); len(runs) != 0 {
		t.Fatalf("refused requests left deployments behind: %+v", runs)
	}
}
