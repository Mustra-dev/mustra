package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// A temporary account outlives nothing: an idle session is ended, its
// account is queued for removal, a failed removal backs off and is
// retried, and a confirmed removal leaves the queue.
func TestRemoteSessionLifecycle(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to disposable Postgres")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	agent := idgen.New("agt-rs-")
	if _, err := s.pool.Exec(ctx, `INSERT INTO agents(agent_id,hostname,os,arch,site) VALUES($1,'win-01','windows','amd64','lab')`, agent); err != nil {
		t.Fatal(err)
	}
	id := idgen.New("rs")
	if err := s.CreateRemoteSession(ctx, RemoteSession{ID: id, AgentID: agent, Hostname: "win-01", Username: "alex", Protocol: "rdp", Provider: "guacamole",
		Recording: id, JITUsername: "mustra-abcdefgh", JITState: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRemoteSessionToken(ctx, id, "sealed", "hash-"+id); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.RemoteSessionByTokenHash(ctx, "hash-"+id); got != id {
		t.Fatalf("by token: %q", got)
	}
	// Open and seen just now: not due, and its account is not removed
	// while the session is still open.
	due, err := s.RemoteSessionsToEnd(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range due {
		if r.ID == id {
			t.Fatal("a live session was ended")
		}
	}
	if q, _ := s.RemoteJITToRemove(ctx); containsSession(q, id) {
		t.Fatal("an open session's account was queued for removal")
	}
	// Idle past the grace.
	if _, err := s.pool.Exec(ctx, `UPDATE remote_sessions SET last_seen_at = now() - interval '10 minutes' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	due, _ = s.RemoteSessionsToEnd(ctx, time.Minute)
	var found *RemoteSession
	for i := range due {
		if due[i].ID == id {
			found = &due[i]
		}
	}
	if found == nil || found.EndReason != "disconnected" || found.JITUsername != "mustra-abcdefgh" {
		t.Fatalf("idle session: %+v", found)
	}
	if err := s.EndRemoteSession(ctx, id, found.EndReason); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.RemoteSessionByTokenHash(ctx, "hash-"+id); got != "" {
		t.Fatal("an ended session is still found by its token")
	}
	q, _ := s.RemoteJITToRemove(ctx)
	if !containsSession(q, id) {
		t.Fatal("the ended session's account is not queued for removal")
	}
	n, err := s.RemoteJITFailed(ctx, id, "offline", time.Hour)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if q, _ := s.RemoteJITToRemove(ctx); containsSession(q, id) {
		t.Fatal("a failed removal was retried before its backoff")
	}
	if _, err := s.pool.Exec(ctx, `UPDATE remote_sessions SET jit_next_try_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.RemoteJITToRemove(ctx); !containsSession(q, id) {
		t.Fatal("a failed removal was not retried after its backoff")
	}
	if err := s.RemoteJITRemoved(ctx, id); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.RemoteJITToRemove(ctx); containsSession(q, id) {
		t.Fatal("a removed account is still queued")
	}
	got, err := s.GetRemoteSession(ctx, id)
	if err != nil || got == nil || got.JITState != "removed" || got.JITRemovedAt == nil || got.EndedAt == nil || got.Recording != id || got.JITAttempts != 1 {
		t.Fatalf("final row: %+v %v", got, err)
	}
	list, err := s.ListRemoteSessions(ctx, 10)
	if err != nil || !containsSession(list, id) {
		t.Fatalf("list: %v", err)
	}
	if missing, err := s.GetRemoteSession(ctx, idgen.New("rs")); err != nil || missing != nil {
		t.Fatalf("missing session: %+v %v", missing, err)
	}
}

func containsSession(list []RemoteSession, id string) bool {
	for _, r := range list {
		if r.ID == id {
			return true
		}
	}
	return false
}
