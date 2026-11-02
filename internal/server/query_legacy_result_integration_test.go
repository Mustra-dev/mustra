package server

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// A shared-credential holder answers live queries on the identity-free
// legacy subject with any agent_id it types. One that names an enrolled
// agent is a forgery, since that agent answers on its own subject; it must
// be dropped (review F6). A per-agent subject is always trusted.
func TestAttributeQueryResultDropsForgedLegacyIdentity(t *testing.T) {
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

	enrolled := idgen.New("agt-")
	if _, _, err := st.EnrollWithToken(ctx, "", "", enrolled, "secret"); err != nil {
		// EnrollWithToken needs a token; issue the credential directly via
		// legacy enrolment of a known legacy-era agent instead.
		if err := st.UpsertOnRegister(ctx, enrolled, proto.AgentInfo{Hostname: "h"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.EnrollLegacy(ctx, enrolled, enrolled, "secret"); err != nil {
			t.Fatal(err)
		}
	}
	legacyOnly := idgen.New("agt-")

	s := &Server{logger: slog.Default(), store: st} // no trust: identity not enforced, legacy accepted

	cases := []struct {
		name    string
		subject string
		body    string
		want    bool
		wantID  string
	}{
		{"per-agent subject trusted", bnats.ResultFrom("q1", enrolled), enrolled, true, enrolled},
		{"legacy result for an enrolled id dropped", bnats.Result("q1"), enrolled, false, ""},
		{"legacy result for an unenrolled id kept", bnats.Result("q1"), legacyOnly, true, legacyOnly},
	}
	for _, c := range cases {
		result := proto.QueryResult{QueryID: "q1", AgentID: c.body}
		got := s.attributeQueryResult(ctx, c.subject, &result)
		if got != c.want {
			t.Errorf("%s: accepted=%v, want %v", c.name, got, c.want)
		}
		if got && result.AgentID != c.wantID {
			t.Errorf("%s: attributed to %q, want %q", c.name, result.AgentID, c.wantID)
		}
	}
}
