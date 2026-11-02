package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func openIntegrityTestServer(t *testing.T) *Server {
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
	return &Server{logger: slog.Default(), store: st, live: &liveConfig{}}
}

// An endpoint under no monitor is listed with "monitors": [], not null:
// the console maps over it for every row it keeps (issue #92).
func TestWatchStatusListsNoMonitorsAsEmpty(t *testing.T) {
	s := openIntegrityTestServer(t)
	ctx := context.Background()
	agent := idgen.New("agt-ws-")
	// Applied an earlier set, then left every monitor: the row the console
	// keeps because have_revision is set.
	if err := s.store.RecordFacts(ctx, proto.Facts{AgentID: agent, Hostname: "ws-01", OS: "linux", Arch: "amd64", WatchRevision: "rev-before"}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.handleWatchStatus(rec, httptest.NewRequest("GET", "/api/integrity/watch-status", nil))
	if rec.Code != 200 {
		t.Fatalf("watch-status: %d %s", rec.Code, rec.Body)
	}
	var body struct {
		Endpoints []map[string]json.RawMessage `json:"endpoints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, e := range body.Endpoints {
		var id string
		_ = json.Unmarshal(e["agent_id"], &id)
		if id != agent {
			continue
		}
		if got := string(e["monitors"]); got != "[]" {
			t.Fatalf("monitors: %s, want []", got)
		}
		return
	}
	t.Fatalf("%s not listed", agent)
}

// Every change record carries a file's hash in full, so an added file's
// hash matches the "was" of its next modification (issue #92).
func TestIntegrityChangeHashesHaveOneLength(t *testing.T) {
	s := openIntegrityTestServer(t)
	ctx := context.Background()
	agent := idgen.New("agt-fim-")
	if err := s.store.RecordFacts(ctx, proto.Facts{AgentID: agent, Hostname: "fim-01", OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)
	snapshot := func(files ...proto.IntegrityFile) []byte {
		b, err := json.Marshal(files)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ingest := func(data []byte) {
		s.diffIntegritySnapshot(ctx, agent, data)
		if err := s.store.UpsertSensorData(ctx, agent, string(proto.SensorIntegrity), time.Now(), data); err != nil {
			t.Fatal(err)
		}
	}
	ingest(snapshot())
	ingest(snapshot(proto.IntegrityFile{Path: "/etc/app.conf", Hash: hashA, Mode: "0644"}))
	ingest(snapshot(proto.IntegrityFile{Path: "/etc/app.conf", Hash: hashB, Mode: "0644"}))

	changes, err := s.store.ListIntegrityChanges(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	var added, modified *store.IntegrityChange
	for i := range changes {
		c := &changes[i]
		if c.AgentID != agent {
			continue
		}
		switch c.Kind {
		case "added":
			added = c
		case "modified":
			modified = c
		}
	}
	if added == nil || modified == nil {
		t.Fatalf("added %v, modified %v", added, modified)
	}
	if added.Now != modified.Was {
		t.Errorf("added now %q, next modification was %q", added.Now, modified.Was)
	}
	// In full: a cut hash cannot be looked up once the file has changed.
	if added.Now != hashA || modified.Now != hashB {
		t.Errorf("added now %q, modified now %q, want the full hashes", added.Now, modified.Now)
	}
}
