package server

import (
	"context"
	"encoding/json"
	"fmt"
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

// saveRouteServer is a Server on the disposable database the opt-in store
// tests use, enough for the save handlers: no NATS, no vault.
func saveRouteServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	st, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return &Server{logger: slog.Default(), store: st, syslog: &syslogSink{}, live: &liveConfig{}}, st
}

// callSave sends body to h as method on path, with {id} set to id when it
// is not empty, as user "tester".
func callSave(h http.HandlerFunc, method, path, id, body string) *httptest.ResponseRecorder {
	return callSaveAs(h, "tester", method, path, id, body)
}

// callSaveAs is callSave as the named user.
func callSaveAs(h http.HandlerFunc, user, method, path, id, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if id != "" {
		r.SetPathValue("id", id)
	}
	r = r.WithContext(auth.WithUser(r.Context(), &store.User{ID: "u-" + user, Username: user, Active: true}))
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// withID is body with "id" set, as a client that sends one writes it.
func withID(t *testing.T, body, id string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	m["id"] = id
	b, _ := json.Marshal(m)
	return string(b)
}

func idOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.ID == "" {
		t.Fatalf("no id in the answer %q: %v", w.Body.String(), err)
	}
	return v.ID
}

// A POST creates and a PUT updates. A POST naming an existing record's id
// once overwrote that record, and a PUT to an unknown id created one; an
// id in a body now decides nothing (#57).
func TestSaveRoutesPostCreatesPutUpdates(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()

	// What the records point at, made for this test and nothing else.
	agentID := idgen.New("agt-saveids-")
	if err := st.UpsertOnRegister(ctx, agentID, proto.AgentInfo{Hostname: "saveids", OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), agentID) })
	// An empty static group, so a profile pushes to no endpoint.
	grp, err := st.UpsertComputerGroup(ctx, store.ComputerGroup{ID: idgen.New("cgrp-saveids-"), Name: "save ids", Kind: "static", MatchMode: "all"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _, _ = st.DeleteComputerGroupAndOrphans(context.Background(), grp.ID) })
	pbID := idgen.New("pb-saveids-")
	if err := st.UpsertPlaybook(ctx, store.Playbook{ID: pbID, Name: "save ids", Steps: json.RawMessage(`[]`)}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeletePlaybook(context.Background(), pbID) })

	type nameFn func(id string) (name string, found bool)
	cases := []struct {
		record  string
		handler http.HandlerFunc
		path    string
		body    func(name string) string
		name    nameFn
		cleanup func(id string)
	}{
		{
			record: "managed certificate", handler: s.handleSaveManagedCert, path: "/api/certificates/managed",
			body: func(name string) string {
				return `{"agent_id":"` + agentID + `","name":"` + name + `","names":["` + name + `.example.com"],"cert_path":"/etc/ssl/` + name + `.crt",
					"key_path":"/etc/ssl/` + name + `.key","ca":"private","renew_days":30,"approval":"approve","enabled":false}`
			},
			name: func(id string) (string, bool) {
				m, err := st.GetManagedCert(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if m == nil {
					return "", false
				}
				return m.Name, true
			},
			cleanup: func(id string) { _ = st.DeleteManagedCert(context.Background(), id) },
		},
		{
			record: "client profile", handler: s.handleSaveClientProfile, path: "/api/clients/profiles",
			body: func(name string) string { return `{"name":"` + name + `","group_ids":["` + grp.ID + `"]}` },
			name: func(id string) (string, bool) {
				p, err := st.GetClientProfile(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if p == nil {
					return "", false
				}
				return p.Name, true
			},
			cleanup: func(id string) { _ = st.DeleteClientProfile(context.Background(), id) },
		},
		{
			record: "deployment template", handler: s.handleSaveDeploymentTemplate, path: "/api/deploy/templates",
			body: func(name string) string { return `{"name":"` + name + `"}` },
			name: func(id string) (string, bool) {
				d, err := st.GetDeploymentTemplate(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if d == nil {
					return "", false
				}
				return d.Name, true
			},
			cleanup: func(id string) { _ = st.DeleteDeploymentTemplate(context.Background(), id) },
		},
		{
			record: "deployment plan", handler: s.handleUpsertPlan, path: "/api/deployment-plans",
			body: func(name string) string {
				return `{"name":"` + name + `","rings":[{"name":"all","group_id":"` + grp.ID + `"}]}`
			},
			name: func(id string) (string, bool) {
				p, err := st.GetDeploymentPlan(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if p == nil {
					return "", false
				}
				return p.Name, true
			},
			cleanup: func(id string) { _ = st.DeleteDeploymentPlan(context.Background(), id) },
		},
		{
			record: "maintenance window", handler: s.handleSaveMaintenanceWindow, path: "/api/maintenance-windows",
			body: func(name string) string {
				return `{"name":"` + name + `","group_ids":["` + grp.ID + `"],"weekdays":[6],"start_time":"02:00","duration_minutes":120,"timezone":"UTC"}`
			},
			name: func(id string) (string, bool) {
				m, err := st.GetMaintenanceWindow(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if m == nil {
					return "", false
				}
				return m.Name, true
			},
			cleanup: func(id string) { _ = st.DeleteMaintenanceWindow(context.Background(), id) },
		},
		{
			record: "patch list", handler: s.handleSavePatchPolicy, path: "/api/patch-policies",
			body: func(name string) string {
				return `{"name":"` + name + `","kind":"allow","group_ids":["` + grp.ID + `"],"rules":{"severities":["security"]}}`
			},
			name: func(id string) (string, bool) {
				p, err := st.GetPatchPolicy(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if p == nil {
					return "", false
				}
				return p.Name, true
			},
			cleanup: func(id string) { _ = st.DeletePatchPolicy(context.Background(), id) },
		},
		{
			// A trigger has no name: its event source stands in for one.
			record: "playbook trigger", handler: s.handleUpsertPlaybookTrigger, path: "/api/playbook-triggers",
			body: func(name string) string {
				return `{"playbook_id":"` + pbID + `","kind":"event","enabled":false,"source":"` + name + `"}`
			},
			name: func(id string) (string, bool) {
				tr, err := st.GetPlaybookTrigger(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if tr == nil {
					return "", false
				}
				return tr.Source, true
			},
			cleanup: func(id string) { _ = st.DeletePlaybookTrigger(context.Background(), id) },
		},
		{
			record: "survey", handler: s.handleUpsertSurvey, path: "/api/surveys",
			body: func(name string) string {
				return `{"name":"` + name + `","title":"How was it?","questions":[{"kind":"rating","text":"Rate it"}]}`
			},
			name: func(id string) (string, bool) {
				v, err := st.GetSurvey(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if v == nil {
					return "", false
				}
				return v.Name, true
			},
			cleanup: func(id string) { _ = st.DeleteSurvey(context.Background(), id) },
		},
		{
			record: "end-user notification", handler: s.handleUpsertEUN, path: "/api/eun",
			body: func(name string) string { return `{"name":"` + name + `","title":"Heads up","kind":"notice"}` },
			name: func(id string) (string, bool) {
				m, err := st.GetEUNMessage(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if m == nil {
					return "", false
				}
				return m.Name, true
			},
			cleanup: func(id string) { _ = st.DeleteEUNMessage(context.Background(), id) },
		},
		{
			// A credential's application is part of its identity, which an
			// update keeps; its display name is a setting, so it stands in.
			record: "app credential", handler: s.handleSaveAppCred, path: "/api/certificates/apps/credentials",
			body: func(name string) string {
				return `{"app_name":"save ids","display_name":"` + name + `","cred_type":"certificate","mode":"remind","renew_days":30}`
			},
			name: func(id string) (string, bool) {
				c, err := st.GetAppCredential(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if c == nil {
					return "", false
				}
				return c.DisplayName, true
			},
			cleanup: func(id string) { _ = st.DeleteAppCredential(context.Background(), id) },
		},
	}
	for _, c := range cases {
		t.Run(c.record, func(t *testing.T) {
			w := callSave(c.handler, "POST", c.path, "", c.body("first"))
			if w.Code != http.StatusOK {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			first := idOf(t, w)
			t.Cleanup(func() { c.cleanup(first) })

			w = callSave(c.handler, "POST", c.path, "", withID(t, c.body("second"), first))
			if w.Code != http.StatusOK {
				t.Fatalf("create naming an existing id: %d %s", w.Code, w.Body.String())
			}
			second := idOf(t, w)
			t.Cleanup(func() { c.cleanup(second) })
			if second == first {
				t.Fatalf("a POST naming %s overwrote it rather than creating a record", first)
			}
			if got, _ := c.name(first); got != "first" {
				t.Errorf("the existing record now reads %q, want it left as %q", got, "first")
			}
			if got, _ := c.name(second); got != "second" {
				t.Errorf("the new record reads %q, want %q", got, "second")
			}

			ghost := idgen.New("ghost-")
			w = callSave(c.handler, "PUT", c.path+"/"+ghost, ghost, c.body("ghost"))
			if w.Code != http.StatusNotFound {
				t.Errorf("PUT to an unknown id: %d %s, want 404", w.Code, w.Body.String())
			}
			if _, found := c.name(ghost); found {
				c.cleanup(ghost)
				t.Error("a PUT to an unknown id created the record")
			}

			// An update still updates, whatever id its body carries.
			w = callSave(c.handler, "PUT", c.path+"/"+first, first, withID(t, c.body("renamed"), second))
			if w.Code != http.StatusOK {
				t.Fatalf("update: %d %s", w.Code, w.Body.String())
			}
			if got, _ := c.name(first); got != "renamed" {
				t.Errorf("the updated record reads %q, want %q", got, "renamed")
			}
			if got, _ := c.name(second); got != "second" {
				t.Errorf("the record the update's body named reads %q, want it left as %q", got, "second")
			}
		})
	}
}

// A record's creator is whoever's session created it. A POST once stored
// the body's created_by as the creator when it also carried an id, though
// the audit event named the real user (#106, #87).
func TestSaveRoutesTakeTheCreatorFromTheSession(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	cases := []struct {
		record  string
		handler http.HandlerFunc
		path    string
		body    string
		creator func(id string) string
		cleanup func(id string)
	}{
		{
			record: "end-user notification", handler: s.handleUpsertEUN, path: "/api/eun",
			body: `{"name":"creator","title":"Heads up","kind":"notice"}`,
			creator: func(id string) string {
				m, err := st.GetEUNMessage(ctx, id)
				if err != nil || m == nil {
					t.Fatalf("the created message %s is not there: %v", id, err)
				}
				return m.CreatedBy
			},
			cleanup: func(id string) { _ = st.DeleteEUNMessage(context.Background(), id) },
		},
		{
			record: "app credential", handler: s.handleSaveAppCred, path: "/api/certificates/apps/credentials",
			body: `{"app_name":"creator","cred_type":"certificate","mode":"remind","renew_days":30}`,
			creator: func(id string) string {
				c, err := st.GetAppCredential(ctx, id)
				if err != nil || c == nil {
					t.Fatalf("the created credential %s is not there: %v", id, err)
				}
				return c.CreatedBy
			},
			cleanup: func(id string) { _ = st.DeleteAppCredential(context.Background(), id) },
		},
	}
	for _, c := range cases {
		t.Run(c.record, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal([]byte(c.body), &m); err != nil {
				t.Fatal(err)
			}
			m["id"], m["created_by"] = idgen.New("chosen-"), "mallory"
			b, _ := json.Marshal(m)
			w := callSave(c.handler, "POST", c.path, "", string(b))
			if w.Code != http.StatusOK {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			id := idOf(t, w)
			t.Cleanup(func() { c.cleanup(id) })
			if got := c.creator(id); got != "tester" {
				t.Errorf("the new record's creator is %q, want the caller %q", got, "tester")
			}

			// An edit by someone else keeps the creator, whatever its body
			// says, in the record and in the answer.
			w = callSaveAs(c.handler, "editor", "PUT", c.path+"/"+id, id, string(b))
			if w.Code != http.StatusOK {
				t.Fatalf("update: %d %s", w.Code, w.Body.String())
			}
			if got := c.creator(id); got != "tester" {
				t.Errorf("after an update the creator is %q, want %q", got, "tester")
			}
			var answer struct {
				CreatedBy string `json:"created_by"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
				t.Fatal(err)
			}
			if answer.CreatedBy != "tester" {
				t.Errorf("the update answers with creator %q, want %q", answer.CreatedBy, "tester")
			}
		})
	}
}

// A new app connection always needs its secret. A body id once skipped
// the check, so a POST could store a connection with none (#57). The
// check comes before the store is touched, so this runs without one.
func TestAppConnectionCreateNeedsSecretWhateverItsBodyID(t *testing.T) {
	s := &Server{logger: slog.Default()}
	w := callSave(s.handleSaveAppCredConnection, "POST", "/api/certificates/apps/connections", "",
		`{"id":"acc-chosen","kind":"gcp","name":"No secret","config":{"project_id":"p"}}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "needs its secret") {
		t.Fatalf("POST with an id and no secret: %d %s, want 400", w.Code, w.Body.String())
	}
}

// A POST naming an existing connection creates another rather than
// rewriting the first's name and config.
func TestAppConnectionPostWithExistingIDCreates(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	// A GCP key that does not parse fails its test without going anywhere.
	body := func(name string) string {
		return `{"kind":"gcp","name":"` + name + `","config":{"project_id":"p-` + name + `"},"secret":"not a key"}`
	}
	const path = "/api/certificates/apps/connections"
	w := callSave(s.handleSaveAppCredConnection, "POST", path, "", body("first"))
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	first := idOf(t, w)
	t.Cleanup(func() { _ = st.DeleteAppCredConnection(context.Background(), first) })
	w = callSave(s.handleSaveAppCredConnection, "POST", path, "", withID(t, body("second"), first))
	if w.Code != http.StatusOK {
		t.Fatalf("create naming an existing id: %d %s", w.Code, w.Body.String())
	}
	second := idOf(t, w)
	t.Cleanup(func() { _ = st.DeleteAppCredConnection(context.Background(), second) })
	if second == first {
		t.Fatal("a POST naming an existing connection overwrote it")
	}
	if c, _ := st.GetAppCredConnection(ctx, first); c == nil || c.Name != "first" || c.Config["project_id"] != "p-first" {
		t.Errorf("the existing connection changed: %+v", c)
	}
	ghost := idgen.New("acc-ghost-")
	w = callSave(s.handleSaveAppCredConnection, "PUT", path+"/"+ghost, ghost, body("ghost"))
	if w.Code != http.StatusNotFound {
		t.Errorf("PUT to an unknown id: %d, want 404", w.Code)
	}
	if c, _ := st.GetAppCredConnection(ctx, ghost); c != nil {
		t.Error("a PUT to an unknown id created a connection")
	}
}

// A trigger has a webhook token exactly while it is a webhook. The server
// chooses it, whatever the body says; it is shown in the answer that
// issued it and nowhere else (#57).
func TestPlaybookTriggerWebhookTokens(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	pbID := idgen.New("pb-tokens-")
	if err := st.UpsertPlaybook(ctx, store.Playbook{ID: pbID, Name: "tokens", Steps: json.RawMessage(`[]`)}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeletePlaybook(context.Background(), pbID) })
	const path = "/api/playbook-triggers"
	body := func(kind string) string {
		return `{"playbook_id":"` + pbID + `","kind":"` + kind + `","enabled":false,
			"token":"chosen-by-the-client","has_token":true,"fire_count":99,"created_by":"mallory"}`
	}
	save := func(method, id, kind string) store.PlaybookTrigger {
		t.Helper()
		p := path
		if id != "" {
			p += "/" + id
		}
		w := callSave(s.handleUpsertPlaybookTrigger, method, p, id, body(kind))
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, kind, w.Code, w.Body.String())
		}
		var out store.PlaybookTrigger
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	opens := func(token, id string) bool {
		t.Helper()
		got, err := st.GetPlaybookTriggerByToken(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		return got != nil && got.ID == id
	}

	hook := save("POST", "", store.TriggerWebhook)
	t.Cleanup(func() { _ = st.DeletePlaybookTrigger(context.Background(), hook.ID) })
	if hook.Token == "" || hook.Token == "chosen-by-the-client" || !hook.HasToken {
		t.Fatalf("a new webhook trigger's token is %q (has_token %v); want one the server chose", hook.Token, hook.HasToken)
	}
	if !opens(hook.Token, hook.ID) {
		t.Fatal("the issued token does not open its trigger")
	}
	if opens("chosen-by-the-client", hook.ID) {
		t.Fatal("the body's token opens the trigger")
	}
	if hook.FireCount != 0 || hook.CreatedBy != "tester" {
		t.Errorf("server-set fields taken from the body: fire_count %d, created_by %q", hook.FireCount, hook.CreatedBy)
	}

	// Saved again as a webhook it keeps its token, which is not shown again.
	again := save("PUT", hook.ID, store.TriggerWebhook)
	if again.Token != "" || !again.HasToken || !opens(hook.Token, hook.ID) {
		t.Fatalf("an update of a webhook changed or showed its token: %q, has_token %v", again.Token, again.HasToken)
	}

	// No longer a webhook, it loses its token: the old URL stops working.
	event := save("PUT", hook.ID, store.TriggerEvent)
	if event.Token != "" || event.HasToken || opens(hook.Token, hook.ID) {
		t.Fatalf("an event trigger kept its webhook token (has_token %v)", event.HasToken)
	}

	// A webhook again, it gets a new one.
	back := save("PUT", hook.ID, store.TriggerWebhook)
	if back.Token == "" || back.Token == hook.Token || back.Token == "chosen-by-the-client" || !back.HasToken {
		t.Fatalf("a trigger switched to webhook has token %q (has_token %v); want a new one", back.Token, back.HasToken)
	}
	if !opens(back.Token, hook.ID) || opens(hook.Token, hook.ID) {
		t.Fatal("the switched trigger answers the wrong token")
	}

	// An event trigger made a webhook is the case that once got no token.
	ev := save("POST", "", store.TriggerEvent)
	t.Cleanup(func() { _ = st.DeletePlaybookTrigger(context.Background(), ev.ID) })
	if ev.Token != "" || ev.HasToken {
		t.Fatalf("an event trigger was given a token")
	}
	switched := save("PUT", ev.ID, store.TriggerWebhook)
	if switched.Token == "" || !opens(switched.Token, ev.ID) {
		t.Fatalf("an event trigger switched to webhook got no working token: %q", switched.Token)
	}
}

// A sent survey keeps the anonymity it was sent with: answers to an
// anonymous prompt must not be stored with their endpoint because the
// survey was switched afterwards. An unsent survey can still change.
func TestSentSurveyKeepsItsAnonymity(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	body := func(anon bool) string {
		return fmt.Sprintf(`{"name":"anon-%d","title":"How was it?","anonymous":%v,"questions":[{"kind":"rating","text":"Rate it"}]}`, time.Now().UnixNano(), anon)
	}
	w := callSave(s.handleUpsertSurvey, "POST", "/api/surveys", "", body(true))
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := idOf(t, w)
	t.Cleanup(func() { _ = st.DeleteSurvey(context.Background(), id) })

	if w := callSave(s.handleUpsertSurvey, "PUT", "/api/surveys/"+id, id, body(false)); w.Code != http.StatusOK {
		t.Fatalf("unsent survey switched to named: %d %s", w.Code, w.Body.String())
	}
	if w := callSave(s.handleUpsertSurvey, "PUT", "/api/surveys/"+id, id, body(true)); w.Code != http.StatusOK {
		t.Fatalf("unsent survey switched back: %d %s", w.Code, w.Body.String())
	}
	if err := st.UpsertOnRegister(ctx, "agt-anon-test", proto.AgentInfo{Hostname: "anon-test", OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordSurveySend(ctx, id, "agt-anon-test", "run-anon-test"); err != nil {
		t.Fatal(err)
	}
	if w := callSave(s.handleUpsertSurvey, "PUT", "/api/surveys/"+id, id, body(false)); w.Code != http.StatusConflict {
		t.Fatalf("sent anonymous survey made named: %d %s, want 409", w.Code, w.Body.String())
	}
	if v, err := st.GetSurvey(ctx, id); err != nil || v == nil || !v.Anonymous {
		t.Fatalf("survey after refused switch: %+v %v, want still anonymous", v, err)
	}
	// Other edits to a sent survey are still allowed.
	if w := callSave(s.handleUpsertSurvey, "PUT", "/api/surveys/"+id, id, body(true)); w.Code != http.StatusOK {
		t.Fatalf("sent survey, anonymity unchanged: %d %s", w.Code, w.Body.String())
	}
}

// Saving an app credential answers the record as stored, not the body: a
// create used to answer an empty state and a year-1 created_at (#86).
func TestAppCredentialSaveAnswersTheStoredRecord(t *testing.T) {
	s, st := saveRouteServer(t)
	body := `{"app_name":"Payroll SSO","cred_type":"client_secret","mode":"remind","renew_days":30,"expires_at":"2027-03-31T00:00:00Z"}`
	w := callSave(s.handleSaveAppCred, "POST", "/api/certificates/apps/credentials", "", body)
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var got store.AppCredential
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAppCredential(context.Background(), got.ID) })
	if got.State != "idle" || got.CreatedAt.IsZero() || got.CreatedBy != "tester" {
		t.Fatalf("create answered state %q, created_at %v, created_by %q; want the stored idle record", got.State, got.CreatedAt, got.CreatedBy)
	}
	w = callSaveAs(s.handleSaveAppCred, "someone-else", "PUT", "/api/certificates/apps/credentials/"+got.ID, got.ID,
		`{"app_name":"Payroll SSO","cred_type":"client_secret","mode":"remind","renew_days":30,"grace_days":7,"expires_at":"2027-03-31T00:00:00Z"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	var upd store.AppCredential
	if err := json.Unmarshal(w.Body.Bytes(), &upd); err != nil {
		t.Fatal(err)
	}
	if upd.State != "idle" || !upd.CreatedAt.Equal(got.CreatedAt) || upd.CreatedBy != "tester" || upd.GraceDays != 7 {
		t.Fatalf("update answered %+v; want the stored record with the change", upd)
	}
}
