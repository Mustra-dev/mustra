package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

func TestSensorFieldOwnership(t *testing.T) {
	for field, want := range map[string]string{
		"hostname":                          "",
		"os":                                "",
		"installed_apps.name":               "installed_apps",
		"installed_apps.name[contains ssh]": "installed_apps",
		"custom_x1.value":                   "custom_x1",
	} {
		if got := sensorOfField(field); got != want {
			t.Errorf("sensorOfField(%q) = %q, want %q", field, got, want)
		}
	}
}

// Content sets restrict sensors only when a set lists some: roles whose
// sets name only packages keep reading inventory, a set naming sensors
// means exactly those, and identity fields are never refused.
func TestSensorContentSetsPostgres(t *testing.T) {
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

	newUser := func(contents map[string][]string) *store.User {
		t.Helper()
		u, err := st.CreateLocalUser(ctx, idgen.New("usr-"), idgen.New("sensor-cs-"), "x", "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteUser(context.Background(), u.ID) })
		if contents == nil {
			return u
		}
		role, err := st.CreateRole(ctx, idgen.New("role-"), idgen.New("sensor-cs-role-"), "", []string{}, []string{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteRole(context.Background(), role.ID) })
		set := store.ContentSet{ID: idgen.New("cset-"), Name: idgen.New("sensor-cs-set-"), Contents: contents}
		if err := st.UpsertContentSet(ctx, set); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteContentSet(context.Background(), set.ID) })
		if err := st.SetRoleContentSets(ctx, role.ID, []string{set.ID}); err != nil {
			t.Fatal(err)
		}
		if err := st.AssignUserRole(ctx, u.ID, role.ID); err != nil {
			t.Fatal(err)
		}
		return u
	}
	as := func(u *store.User) context.Context { return auth.WithUser(ctx, u) }

	free := newUser(nil)
	pkgOnly := newUser(map[string][]string{"packages": {"pkg-x"}})
	appsOnly := newUser(map[string][]string{"sensors": {"installed_apps"}})
	admin := &store.User{ID: idgen.New("usr-"), Username: "admin-x", IsAdmin: true, Active: true}

	rules := []groups.Rule{{Field: "processes.name", Op: "equals", Value: "sshd"}}
	for _, c := range []struct {
		name  string
		user  *store.User
		get   []string
		rules []groups.Rule
		ok    bool
	}{
		{"no content set reads anything", free, []string{"processes.name"}, nil, true},
		{"a packages-only set leaves sensors open", pkgOnly, []string{"processes.name"}, nil, true},
		{"a listed sensor is readable", appsOnly, []string{"hostname", "installed_apps.name"}, nil, true},
		{"identity fields are always readable", appsOnly, []string{"hostname", "os", "ip"}, nil, true},
		{"an unlisted sensor is refused", appsOnly, []string{"processes.name"}, nil, false},
		{"filtering on an unlisted sensor is refused", appsOnly, []string{"hostname"}, rules, false},
		{"an administrator reads anything", admin, []string{"processes.name"}, rules, true},
	} {
		err := s.checkSensorFields(as(c.user), c.get, c.rules)
		var denied errSensorNotGranted
		if c.ok && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && !errors.As(err, &denied) {
			t.Errorf("%s: want a refusal, got %v", c.name, err)
		}
	}

	// The cached-sensor route answers 403 before looking anything up.
	req := httptest.NewRequest("GET", "/api/agents/agt-x/sensor/processes", nil).WithContext(as(appsOnly))
	req.SetPathValue("id", "agt-x")
	req.SetPathValue("kind", "processes")
	rec := httptest.NewRecorder()
	s.handleGetCachedSensor(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "processes sensor") {
		t.Errorf("cached processes for an installed_apps-only role: %d %q", rec.Code, rec.Body.String())
	}
}
