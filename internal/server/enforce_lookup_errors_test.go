package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// A policy lookup that fails is a database problem, not a missing policy
// (issue #89). The request's context is cancelled, so every read fails;
// the handlers answer 500 rather than 404 "no such policy". Every write
// fails too, so the save cases show the status, not that a save stops
// before writing.
func TestEnforceLookupErrorIsNotAMissingPolicy(t *testing.T) {
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

	for _, c := range []struct {
		name    string
		method  string
		body    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"get", "GET", "", s.handleGetEnforcePolicy},
		{"delete", "DELETE", "", s.handleDeleteEnforcePolicy},
		{"run", "POST", `{"dry_run":true}`, s.handleRunEnforcePolicy},
		{"reset", "POST", "", s.handleResetEnforcePolicy},
		{"save", "PUT", `{"id":"enf-lookup","name":"Lookup","os":"linux","settings":[{"name":"chronyd is running","rules":["p:chronyd"]}]}`, s.handleSaveEnforcePolicy},
		// The group read fails first: not "no such computer group".
		{"save with a group", "PUT", `{"name":"Lookup","os":"linux","group_id":"cgrp-lookup","settings":[{"name":"chronyd is running","rules":["p:chronyd"]}]}`, s.handleSaveEnforcePolicy},
	} {
		req := httptest.NewRequest(c.method, "/api/enforce/policies/enf-lookup", strings.NewReader(c.body))
		req.SetPathValue("id", "enf-lookup")
		cancelled, cancel := context.WithCancel(req.Context())
		cancel()
		rec := httptest.NewRecorder()
		c.handler(rec, asUser(req.WithContext(cancelled), root))
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s with a failing lookup: %d %q, want 500", c.name, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
}
