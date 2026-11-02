package server

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// PUT /api/deploy/packages/{id} changes a package's details only. Its
// body has its own type now, so the fields it never copied (kind,
// version, commands, detection, …) are not in the spec; a client that
// still sends them must find them ignored, as before. Every detail field
// is copied as sent, so one left out is cleared.
func TestDeployPackageMetadataCopiesOnlyDetails(t *testing.T) {
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
	id := idgen.New("sw-")
	defer func() { _ = st.DeleteSoftwarePackage(ctx, id) }()
	before := store.SoftwarePackage{
		ID: id, Kind: store.KindSoftware, Name: "Before", Vendor: "Old vendor", Version: "1.0",
		Category: "old", Description: "old description", Enabled: true, ExpireSeconds: 60,
		Commands:               map[string]store.SoftwareOps{"linux": {Install: "apt-get install -y before"}},
		Detect:                 store.SoftwareDetect{AppName: "before"},
		RequireExplicitTargets: true, CommandTimeoutSeconds: 120, Source: "manual", CreatedBy: "test",
	}
	if _, err := st.UpsertSoftwarePackage(ctx, before); err != nil {
		t.Fatal(err)
	}

	s := &Server{logger: slog.Default(), store: st, syslog: &syslogSink{}}
	// No enabled and no group_ids: both are cleared. The rest are the
	// fields this route ignores.
	body := `{"name": "After", "description": "new description", "vendor": "New vendor", "category": "new",
		"self_service": true, "allow_requests": true, "self_service_follow_latest": true, "expire_seconds": 300,
		"kind": "action", "version": "9.9", "commands": {"windows": {"install": "evil.exe"}},
		"detect": {"app_name": "other"}, "require_explicit_targets": false, "command_timeout_seconds": 5,
		"source": "discovered", "id": "sw-other"}`
	req := httptest.NewRequest("PUT", "/api/deploy/packages/"+id, strings.NewReader(body))
	req.SetPathValue("id", id)
	req = req.WithContext(auth.WithUser(req.Context(), &store.User{ID: "u", Username: "u", IsAdmin: true}))
	rec := httptest.NewRecorder()
	s.handleDeployPackageMetadata(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}

	got, err := st.GetSoftwarePackage(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("package after the update: %v, %v", got, err)
	}
	if got.Name != "After" || got.Description != "new description" || got.Vendor != "New vendor" || got.Category != "new" ||
		!got.SelfService || !got.AllowRequests || !got.SelfServiceFollowLatest || got.ExpireSeconds != 300 {
		t.Errorf("details not copied: %+v", got)
	}
	if got.Enabled || len(got.GroupIDs) != 0 {
		t.Errorf("enabled = %v, group_ids = %v; left out, they are cleared", got.Enabled, got.GroupIDs)
	}
	if got.Kind != before.Kind || got.Version != before.Version || got.Detect.AppName != before.Detect.AppName ||
		!got.RequireExplicitTargets || got.CommandTimeoutSeconds != before.CommandTimeoutSeconds || got.Source != before.Source {
		t.Errorf("a field this route ignores changed: %+v", got)
	}
	if ops, ok := got.Commands["linux"]; !ok || ops.Install != before.Commands["linux"].Install || len(got.Commands) != 1 {
		t.Errorf("commands changed: %v", got.Commands)
	}
	if slices.ContainsFunc(mustListSoftware(t, st), func(p store.SoftwarePackage) bool { return p.ID == "sw-other" }) {
		t.Error("the body's id created or addressed another package")
	}
}

func mustListSoftware(t *testing.T, st *store.Store) []store.SoftwarePackage {
	t.Helper()
	list, err := st.ListSoftwarePackages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return list
}
