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
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// A jump policy naming a group that does not exist covers nothing, so the
// endpoints it was written for would need no reason, approval or time
// limit. The save has to refuse it, as maintenance windows, client
// profiles and patch policies already do (issue #58).
func TestSaveJumpPolicyRefusesUnknownGroup(t *testing.T) {
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
	s := &Server{logger: slog.Default(), store: st, syslog: &syslogSink{}}
	userCtx := auth.WithUser(ctx, &store.User{Username: "jump-test"})

	g, err := st.UpsertComputerGroup(ctx, store.ComputerGroup{ID: idgen.New("cgrp-"), Name: "jump test " + idgen.New(""),
		Kind: "static", MatchMode: "all", CreatedBy: "jump-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _, _ = st.DeleteComputerGroupAndOrphans(context.Background(), g.ID) })

	save := func(method, path, id, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(userCtx)
		if id != "" {
			req.SetPathValue("id", id)
		}
		rec := httptest.NewRecorder()
		s.handleSaveJumpPolicy(rec, req)
		return rec
	}
	countNamed := func(name string) int {
		t.Helper()
		list, err := st.ListJumpPolicies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, p := range list {
			if p.Name == name {
				n++
			}
		}
		return n
	}

	missing := idgen.New("cgrp-")
	name := "unknown group " + idgen.New("")
	body, _ := json.Marshal(map[string]any{"name": name, "group_ids": []string{g.ID, missing}, "require_approval": true, "enabled": true})
	rec := save("POST", "/api/jump/policies", "", string(body))
	if rec.Code != http.StatusBadRequest || strings.TrimSpace(rec.Body.String()) != "unknown group "+missing {
		t.Fatalf("create with an unknown group: %d %q, want 400 %q", rec.Code, rec.Body.String(), "unknown group "+missing)
	}
	if n := countNamed(name); n != 0 {
		t.Fatalf("a refused create stored %d policies", n)
	}

	// A real group saves.
	body, _ = json.Marshal(map[string]any{"name": name, "group_ids": []string{g.ID}, "require_approval": true, "enabled": true})
	rec = save("POST", "/api/jump/policies", "", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("create with a real group: %d %q", rec.Code, rec.Body.String())
	}
	var saved store.JumpPolicy
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteJumpPolicy(context.Background(), saved.ID) })
	if len(saved.GroupIDs) != 1 || saved.GroupIDs[0] != g.ID {
		t.Fatalf("saved groups = %v, want [%s]", saved.GroupIDs, g.ID)
	}

	// An edit naming an unknown group is refused and leaves the stored
	// policy as it was.
	body, _ = json.Marshal(map[string]any{"name": name, "group_ids": []string{missing}, "require_approval": false, "enabled": true})
	rec = save("PUT", "/api/jump/policies/"+saved.ID, saved.ID, string(body))
	if rec.Code != http.StatusBadRequest || strings.TrimSpace(rec.Body.String()) != "unknown group "+missing {
		t.Fatalf("edit with an unknown group: %d %q, want 400 %q", rec.Code, rec.Body.String(), "unknown group "+missing)
	}
	after, err := st.GetJumpPolicy(ctx, saved.ID)
	if err != nil || after == nil {
		t.Fatalf("reload policy: %v %v", after, err)
	}
	if len(after.GroupIDs) != 1 || after.GroupIDs[0] != g.ID || !after.RequireApproval {
		t.Fatalf("a refused edit changed the policy: groups %v approval %v", after.GroupIDs, after.RequireApproval)
	}
}
