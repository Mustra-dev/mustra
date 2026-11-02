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

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// catalogDecideFixture is the Self Service approval queue against a real
// store: one endpoint, one package it may ask for, and an operator whose
// name is unique to the test, so the audit rows it reads are its own.
type catalogDecideFixture struct {
	s     *Server
	st    *store.Store
	agent string
	host  string
	pkg   string
	user  *store.User
}

func newCatalogDecideFixture(t *testing.T) *catalogDecideFixture {
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

	f := &catalogDecideFixture{st: st, agent: idgen.New("agt-")}
	f.host = "catalog-decide-" + f.agent
	if err := st.UpsertOnRegister(ctx, f.agent, proto.AgentInfo{Hostname: f.host, OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), f.agent) })
	p, err := st.UpsertSoftwarePackage(ctx, store.SoftwarePackage{
		ID: idgen.New("pkg-"), Name: "Catalog decide test", Kind: "package",
		Commands:    map[string]store.SoftwareOps{"linux": {Install: "apt-get install -y jq"}},
		SelfService: true, AllowRequests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.pkg = p.ID
	t.Cleanup(func() { _ = st.DeleteSoftwarePackage(context.Background(), f.pkg) })
	f.user = &store.User{ID: idgen.New("usr-"), Username: idgen.New("catalog-decider-"), IsAdmin: true, Active: true}
	f.s = &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}}
	return f
}

// request files a pending request from the fixture's endpoint.
func (f *catalogDecideFixture) request(t *testing.T) string {
	t.Helper()
	id := idgen.New("creq-")
	if err := f.st.CreateCatalogRequest(context.Background(), store.CatalogRequest{
		ID: id, ItemID: f.pkg, AgentID: f.agent, RequestedBy: "alice", Reason: "need jq",
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *catalogDecideFixture) decide(t *testing.T, id, status string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/catalog/requests/"+id+"/decide", strings.NewReader(`{"status":"`+status+`"}`))
	r.SetPathValue("id", id)
	r = r.WithContext(auth.WithUser(r.Context(), f.user))
	w := httptest.NewRecorder()
	f.s.handleDecideCatalogRequest(w, r)
	return w
}

func TestDecideCatalogRequest(t *testing.T) {
	f := newCatalogDecideFixture(t)

	t.Run("an unknown request is a 404", func(t *testing.T) {
		if w := f.decide(t, idgen.New("creq-missing-"), "approved"); w.Code != http.StatusNotFound {
			t.Fatalf("status %d, want 404: %s", w.Code, w.Body)
		}
	})

	t.Run("a pending request older than the newest 200 can be decided", func(t *testing.T) {
		// The action gate names the endpoint a decision is for; it used to
		// look the request up in the approval queue's list, which stops at
		// 200 rows.
		old := f.request(t)
		for range 200 {
			f.request(t)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/catalog/requests/"+old+"/decide", nil)
		r.SetPathValue("id", old)
		a, err := resolveCatalogDecision(f.s, r, nil)
		if err != nil {
			t.Fatalf("the gate did not find the request: %v", err)
		}
		if len(a.Explicit) != 1 || a.Explicit[0] != f.agent {
			t.Fatalf("the gate names %v, want [%s]", a.Explicit, f.agent)
		}
	})

	t.Run("a decision is audited with the endpoint and the package", func(t *testing.T) {
		id := f.request(t)
		if w := f.decide(t, id, "approved"); w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		evs, err := f.st.ListAuditEvents(context.Background(), "catalog_request.", f.user.Username, "", 50)
		if err != nil {
			t.Fatal(err)
		}
		var found *store.AuditEvent
		for i := range evs {
			if strings.Contains(evs[i].Detail, id) {
				found = &evs[i]
			}
		}
		if found == nil {
			t.Fatalf("no catalog_request audit row for %s in %+v", id, evs)
		}
		if found.Action != "catalog_request.approved" || found.AgentID != f.agent || found.Target != "Catalog decide test" {
			t.Fatalf("audit row = %+v", *found)
		}
	})

	t.Run("a decided request is a 409 and keeps its decision", func(t *testing.T) {
		id := f.request(t)
		if w := f.decide(t, id, "denied"); w.Code != http.StatusOK {
			t.Fatalf("first decision: status %d: %s", w.Code, w.Body)
		}
		if w := f.decide(t, id, "approved"); w.Code != http.StatusConflict {
			t.Fatalf("second decision: status %d, want 409: %s", w.Code, w.Body)
		}
		got, err := f.st.GetCatalogRequest(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got.Status != "denied" || got.DecidedBy != f.user.Username {
			t.Fatalf("the denial is now %+v", got)
		}
	})
}

// A branding change is sent to every endpoint's Self Service window, so it
// belongs in the audit log, with the version endpoints will report.
func TestSelfServiceBrandingUpdateIsAudited(t *testing.T) {
	f := newCatalogDecideFixture(t)
	ctx := context.Background()
	before, err := f.st.GetSetting(ctx, settingSelfServiceBranding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.st.SetSetting(context.Background(), settingSelfServiceBranding, before, "test-cleanup") })

	r := httptest.NewRequest(http.MethodPut, "/api/selfservice/branding", strings.NewReader(`{"org_name":"Audit Test Org"}`))
	r = r.WithContext(auth.WithUser(r.Context(), f.user))
	w := httptest.NewRecorder()
	f.s.handleUpdateSelfServiceBranding(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp selfServiceBrandingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	evs, err := f.st.ListAuditEvents(ctx, "selfservice.branding_update", f.user.Username, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || !strings.Contains(evs[0].Detail, resp.Version) {
		t.Fatalf("want one selfservice.branding_update row naming version %s, got %+v", resp.Version, evs)
	}
}
