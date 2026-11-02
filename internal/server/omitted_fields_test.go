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

// A field left out of a request used to read as false or "", which on
// these routes switched something off (issue #56). These run without a
// database: the server has no store, so a handler that got as far as
// reading or writing one would panic rather than answer 400.

func TestUserFlagsWithoutTheFieldAreRefused(t *testing.T) {
	s := &Server{logger: slog.Default()}
	root := &store.User{ID: "usr-root", Username: "root", Active: true, IsAdmin: true}
	for _, c := range []struct {
		route   string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"active", s.handleSetUserActive},
		{"admin", s.handleSetUserAdmin},
	} {
		for _, body := range []string{`{}`, `{"active":null,"is_admin":null}`} {
			req := httptest.NewRequest("POST", "/api/admin/users/usr-other/"+c.route, strings.NewReader(body))
			req.SetPathValue("id", "usr-other")
			rec := httptest.NewRecorder()
			c.handler(rec, asUser(req, root))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s with %s: %d, want 400", c.route, body, rec.Code)
			}
		}
	}
}

// A body that is there but cannot be read is a mistake, not a request to
// acknowledge.
func TestFindingAcksRefuseAMalformedBody(t *testing.T) {
	s := &Server{logger: slog.Default()}
	root := &store.User{ID: "usr-root", Username: "root", Active: true, IsAdmin: true}
	for _, c := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"indicator", s.handleAckIOCFinding},
		{"signal", s.handleAckSignalFinding},
	} {
		for _, body := range []string{`{"acknowledged":`, `{"acknowledged":"no"}`, `not json`} {
			req := httptest.NewRequest("POST", "/api/hunt/findings/f1/ack", strings.NewReader(body))
			req.SetPathValue("id", "f1")
			rec := httptest.NewRecorder()
			c.handler(rec, asUser(req, root))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s ack with %s: %d, want 400", c.name, body, rec.Code)
			}
		}
	}
}

func TestCriticalityWithoutAnEndpointIsRefused(t *testing.T) {
	s := &Server{logger: slog.Default()}
	root := &store.User{ID: "usr-root", Username: "root", Active: true, IsAdmin: true}
	for _, body := range []string{`{"level":"critical"}`, `{"level":"critical","agent_id":"  "}`} {
		req := httptest.NewRequest("POST", "/api/risk/criticality", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleSetCriticality(rec, asUser(req, root))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", body, rec.Code)
		}
	}
}

// The rest needs the records the handlers change, so it runs against a
// disposable database.
func TestOmittedFieldsAgainstTheStore(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{logger: slog.Default(), store: st, auth: auth.New(ctx, st, nil, false, slog.Default()), syslog: &syslogSink{}, live: &liveConfig{}}
	root := &store.User{ID: "usr-root", Username: "root", Active: true, IsAdmin: true}
	call := func(h func(http.ResponseWriter, *http.Request), method, target, body string, path map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, target, nil)
		} else {
			req = httptest.NewRequest(method, target, strings.NewReader(body))
		}
		for k, v := range path {
			req.SetPathValue(k, v)
		}
		rec := httptest.NewRecorder()
		h(rec, asUser(req, root))
		return rec
	}

	agentID := idgen.New("agt-")
	if err := st.UpsertOnRegister(ctx, agentID, proto.AgentInfo{Hostname: "omitted-fields"}); err != nil {
		t.Fatal(err)
	}

	t.Run("user flags without the field change nothing", func(t *testing.T) {
		u, err := st.CreateLocalUser(ctx, idgen.New("usr-"), idgen.New("omitted-"), "x", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.SetUserAdmin(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
		token := idgen.New("tok-")
		if _, err := st.CreateSession(ctx, token, u.ID, time.Hour); err != nil {
			t.Fatal(err)
		}
		for _, h := range []struct {
			route string
			fn    func(http.ResponseWriter, *http.Request)
		}{{"active", s.handleSetUserActive}, {"admin", s.handleSetUserAdmin}} {
			rec := call(h.fn, "POST", "/api/admin/users/"+u.ID+"/"+h.route, `{}`, map[string]string{"id": u.ID})
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s with {}: %d, want 400", h.route, rec.Code)
			}
		}
		got, err := st.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Active || !got.IsAdmin {
			t.Errorf("after {}: active=%v admin=%v, want both still true", got.Active, got.IsAdmin)
		}
		if who, err := st.GetSessionUser(ctx, token, 0); err != nil || who == nil {
			t.Errorf("the user's session did not survive a refused request: %v, %v", who, err)
		}
	})

	t.Run("both finding acks acknowledge without the field and re-open on false", func(t *testing.T) {
		ioc, err := st.UpsertIOC(ctx, store.IOC{ID: idgen.New("ioc-"), Name: "ack test", Kind: store.IOCProcessName, Value: idgen.New("p-"), Severity: "warning"})
		if err != nil {
			t.Fatal(err)
		}
		iocFinding := idgen.New("iocf-")
		if _, err := st.RecordIOCFinding(ctx, store.IOCFinding{ID: iocFinding, IOCID: ioc.ID, AgentID: agentID, MatchedValue: ioc.Value}); err != nil {
			t.Fatal(err)
		}
		signalID := idgen.New("sig-")
		if err := st.UpsertSignal(ctx, store.Signal{ID: signalID, Name: "ack test", Expression: "process.name equals 'x'", Objects: []string{"process"}, Severity: "warning"}); err != nil {
			t.Fatal(err)
		}
		sigFinding := idgen.New("sigf-")
		if _, err := st.RecordSignalFinding(ctx, store.SignalFinding{ID: sigFinding, SignalID: signalID, AgentID: agentID, Kind: "process", Summary: "x"}); err != nil {
			t.Fatal(err)
		}
		iocAcked := func() bool {
			list, err := st.ListIOCFindings(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range list {
				if f.ID == iocFinding {
					return f.Acknowledged
				}
			}
			t.Fatal("indicator finding not listed")
			return false
		}
		sigAcked := func() bool {
			list, err := st.ListSignalFindings(ctx, 1000)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range list {
				if f.ID == sigFinding {
					return f.Acknowledged
				}
			}
			t.Fatal("signal finding not listed")
			return false
		}
		for _, c := range []struct {
			name   string
			fn     func(http.ResponseWriter, *http.Request)
			target string
			id     string
			acked  func() bool
		}{
			{"indicator", s.handleAckIOCFinding, "/api/hunt/findings/" + iocFinding + "/ack", iocFinding, iocAcked},
			{"signal", s.handleAckSignalFinding, "/api/hunt/signal-findings/" + sigFinding + "/ack", sigFinding, sigAcked},
		} {
			for _, step := range []struct {
				body   string
				status int
				want   bool
			}{
				{"", http.StatusNoContent, true},
				{`{"acknowledged":false}`, http.StatusNoContent, false},
				{`{}`, http.StatusNoContent, true},
				{`{"acknowledged":false}`, http.StatusNoContent, false},
				// Malformed: refused, and the finding stays open.
				{`{"acknowledged":`, http.StatusBadRequest, false},
				{`{"acknowledged":true}`, http.StatusNoContent, true},
			} {
				rec := call(c.fn, "POST", c.target, step.body, map[string]string{"id": c.id})
				if rec.Code != step.status {
					t.Fatalf("%s ack %q: %d, want %d", c.name, step.body, rec.Code, step.status)
				}
				if got := c.acked(); got != step.want {
					t.Errorf("%s ack %q: acknowledged=%v, want %v", c.name, step.body, got, step.want)
				}
			}
		}
	})

	t.Run("agent trust keeps allow_http when it is left out", func(t *testing.T) {
		rec := call(s.handlePutAgentTrust, "PUT", "/api/agent-trust", `{"public_url":"http://mustra.lan:8080","allow_http":true}`, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("set an http URL: %d %s", rec.Code, rec.Body)
		}
		rec = call(s.handlePutAgentTrust, "PUT", "/api/agent-trust", `{"public_url":"http://mustra2.lan:8080"}`, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("change the URL without allow_http: %d %s", rec.Code, rec.Body)
		}
		if v, _ := st.GetSetting(ctx, settingAgentPublicURLHTTPOK); v != "true" {
			t.Errorf("allow_http after a PUT without it: %q, want true", v)
		}
		if v, _ := st.GetSetting(ctx, settingAgentPublicURL); v != "http://mustra2.lan:8080" {
			t.Errorf("public URL: %q", v)
		}
		// Switching plain HTTP off under an http URL would leave a setting
		// no agent can use.
		rec = call(s.handlePutAgentTrust, "PUT", "/api/agent-trust", `{"allow_http":false}`, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("allow_http false under an http URL: %d, want 400", rec.Code)
		}
		if v, _ := st.GetSetting(ctx, settingAgentPublicURLHTTPOK); v != "true" {
			t.Errorf("allow_http after a refused change: %q, want true", v)
		}
		rec = call(s.handlePutAgentTrust, "PUT", "/api/agent-trust", `{"public_url":"https://mustra.example.com","allow_http":false}`, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("set an https URL: %d %s", rec.Code, rec.Body)
		}
		if v, _ := st.GetSetting(ctx, settingAgentPublicURLHTTPOK); v != "false" {
			t.Errorf("allow_http after an explicit false: %q, want false", v)
		}
	})

	t.Run("criticality for an unknown endpoint is not found", func(t *testing.T) {
		rec := call(s.handleSetCriticality, "POST", "/api/risk/criticality", `{"level":"high","agent_id":"agt-nobody"}`, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("unknown endpoint: %d %s, want 404", rec.Code, rec.Body)
		}
		rec = call(s.handleSetCriticality, "POST", "/api/risk/criticality", `{"level":"high","agent_id":"`+agentID+`"}`, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("known endpoint: %d %s", rec.Code, rec.Body)
		}
		levels, err := st.ListCriticality(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if levels[agentID] != "high" {
			t.Errorf("stored level %q, want high", levels[agentID])
		}
	})

	t.Run("an indicator created without enabled is enabled", func(t *testing.T) {
		body := `{"name":"no enabled","kind":"process_name","value":"` + idgen.New("p-") + `"}`
		rec := call(s.handleUpsertIOC, "POST", "/api/hunt/iocs", body, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("create: %d %s", rec.Code, rec.Body)
		}
		var out store.IOC
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if !out.Enabled {
			t.Error("created without enabled: disabled, want enabled")
		}
		rec = call(s.handleUpsertIOC, "POST", "/api/hunt/iocs", strings.Replace(body, "{", `{"enabled":false,`, 1), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("create disabled: %d %s", rec.Code, rec.Body)
		}
		var off store.IOC
		_ = json.Unmarshal(rec.Body.Bytes(), &off)
		if off.Enabled {
			t.Error("created with enabled false: enabled")
		}
		// An update replaces the whole indicator, as it always has.
		rec = call(s.handleUpsertIOC, "PUT", "/api/hunt/iocs/"+out.ID, body, map[string]string{"id": out.ID})
		if rec.Code != http.StatusOK {
			t.Fatalf("update: %d %s", rec.Code, rec.Body)
		}
		var upd store.IOC
		_ = json.Unmarshal(rec.Body.Bytes(), &upd)
		if upd.Enabled {
			t.Error("updated without enabled: still enabled, want the full replace to switch it off")
		}
	})

	t.Run("an approval policy keeps the enabled it was created with", func(t *testing.T) {
		create := func(body string) store.ApprovalPolicy {
			t.Helper()
			rec := call(s.handleSaveApprovalPolicy, "POST", "/api/approval-policies", body, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("create %s: %d %s", body, rec.Code, rec.Body)
			}
			var p store.ApprovalPolicy
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			return p
		}
		off := create(`{"name":"off","module":"deploy","enabled":false}`)
		if stored, err := st.GetApprovalPolicy(ctx, off.ID); err != nil || stored == nil || stored.Enabled {
			t.Errorf("created with enabled false: stored %+v, %v; want disabled", stored, err)
		}
		on := create(`{"name":"default","module":"deploy"}`)
		if !on.Enabled {
			t.Error("created without enabled: disabled, want enabled")
		}
		rec := call(s.handleSaveApprovalPolicy, "PUT", "/api/approval-policies/"+on.ID, `{"name":"default","module":"deploy"}`, map[string]string{"id": on.ID})
		if rec.Code != http.StatusOK {
			t.Fatalf("update: %d %s", rec.Code, rec.Body)
		}
		if stored, _ := st.GetApprovalPolicy(ctx, on.ID); stored == nil || stored.Enabled {
			t.Error("updated without enabled: still enabled, want the full replace to switch it off")
		}
	})
}
