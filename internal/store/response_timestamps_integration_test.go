package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/exploitintel"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
)

// openTestStore opens the disposable database, skipping when there is
// none.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// testAgent registers an endpoint for rows that reference one.
func testAgent(t *testing.T, s *Store) string {
	t.Helper()
	ctx := context.Background()
	id := idgen.New("agt-ts-")
	if err := s.UpsertOnRegister(ctx, id, proto.AgentInfo{Hostname: "ts-host", OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(context.Background(), id) })
	return id
}

// A new grant comes back as stored, with the database's requested_at,
// so POST /api/jump/requests does not answer year 1 (#102).
func TestCreateJumpGrantReturnsTheStoredGrant(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	agent := testAgent(t, s)

	g, err := s.CreateJumpGrant(ctx, JumpGrant{ID: idgen.New("jg-"), AgentID: agent, Hostname: "ts-host",
		PolicyID: "jp-test", PolicyName: "test", RequestedBy: "ts-user", Reason: "#102", MaxMinutes: 30, State: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetJumpGrant(ctx, g.ID)
	if err != nil || stored == nil {
		t.Fatalf("get grant: %v, %v", stored, err)
	}
	if g.RequestedAt.IsZero() || !g.RequestedAt.Equal(stored.RequestedAt) {
		t.Fatalf("returned requested_at %v, stored %v", g.RequestedAt, stored.RequestedAt)
	}
	if g.State != "pending" || g.RequestedBy != "ts-user" || g.MaxMinutes != 30 {
		t.Fatalf("returned grant %+v does not match what was created", g)
	}
}

// EPSS scores are stored single-precision; they come back as FIRST
// published them, not with float32's rounding widened into a float64
// (0.2731 as 0.27309998869895935) (#100).
func TestLookupExploitIntelReturnsEPSSAsPublished(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	// Rows of its own, written as ReplaceEPSS writes them, rather than
	// ReplaceEPSS itself, which would empty the feed of whatever database
	// this is.
	run := strings.ToUpper(idgen.New("")[:8])
	scores := []exploitintel.EPSSScore{
		{CVE: "CVE-TEST-" + run + "-1", EPSS: 0.2731, Percentile: 0.9661},
		{CVE: "CVE-TEST-" + run + "-2", EPSS: 0.0118, Percentile: 0.7802},
		{CVE: "CVE-TEST-" + run + "-3", EPSS: 0.00043, Percentile: 0.12345},
		{CVE: "CVE-TEST-" + run + "-4", EPSS: 0.97575, Percentile: 1},
	}
	cves := make([]string, 0, len(scores))
	for _, sc := range scores {
		if _, err := s.pool.Exec(ctx, `INSERT INTO epss_scores (cve, epss, percentile) VALUES ($1,$2,$3)`,
			sc.CVE, float32(sc.EPSS), float32(sc.Percentile)); err != nil {
			t.Fatal(err)
		}
		cves = append(cves, sc.CVE)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), `DELETE FROM epss_scores WHERE cve = ANY($1)`, cves)
	})
	got, err := s.LookupExploitIntel(ctx, cves)
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range scores {
		x, ok := got[sc.CVE]
		if !ok || !x.Scored {
			t.Fatalf("%s not scored", sc.CVE)
		}
		if x.EPSS != sc.EPSS || x.Percentile != sc.Percentile {
			t.Errorf("%s: epss %v percentile %v, want %v and %v", sc.CVE, x.EPSS, x.Percentile, sc.EPSS, sc.Percentile)
		}
	}
}

// The session list carries the Jump Gate half of a session, as one
// session's read does, so Direct Connect can hide a session whose access
// has ended instead of offering to resume it (#116).
func TestListShellSessionsCarriesJumpGateAccess(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	agent := testAgent(t, s)

	gated, plain := idgen.New("sh-"), idgen.New("sh-")
	for _, id := range []string{gated, plain} {
		if err := s.CreateShellSession(ctx, ShellSession{ID: id, AgentID: agent, OpenedBy: "ts-user", WorkingDir: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	expires := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	if err := s.SetSessionAccess(ctx, gated, "INC-2041", "jg-ts", &expires); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListShellSessions(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, sess := range list {
		switch sess.ID {
		case gated:
			found++
			if sess.Reason != "INC-2041" || sess.GrantID != "jg-ts" || sess.ExpiresAt == nil || !sess.ExpiresAt.Equal(expires) {
				t.Errorf("gated session listed as reason %q grant %q expires %v; want INC-2041, jg-ts, %v",
					sess.Reason, sess.GrantID, sess.ExpiresAt, expires)
			}
		case plain:
			found++
			if sess.Reason != "" || sess.GrantID != "" || sess.ExpiresAt != nil {
				t.Errorf("ungated session listed with access %q %q %v", sess.Reason, sess.GrantID, sess.ExpiresAt)
			}
		}
	}
	if found != 2 {
		t.Fatalf("listed %d of the 2 sessions", found)
	}
}

// A run is stored with the time its rendering began, so one that took
// longer than a later run can be the oldest on its shelf when it is saved.
// Pruning must not delete the run it is saving: its caller answers with
// that run's ID.
func TestSaveReportRunKeepsTheRunItSaves(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	rep := Report{ID: idgen.New("rep-"), Name: "prune " + idgen.New(""), ScheduleKind: "manual", UpdatedBy: "ts-user"}
	if err := s.UpsertReport(ctx, rep, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteReport(context.Background(), rep.ID) })

	now := time.Now()
	for i := 0; i < maxPreviewKept; i++ {
		if err := s.SaveReportRun(ctx, ReportRun{ID: idgen.New("rpt-"), ReportID: rep.ID, Name: rep.Name,
			GeneratedAt: now, Preview: true}); err != nil {
			t.Fatal(err)
		}
	}
	slow := ReportRun{ID: idgen.New("rpt-"), ReportID: rep.ID, Name: rep.Name, GeneratedAt: now.Add(-time.Minute), Preview: true}
	if err := s.SaveReportRun(ctx, slow); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetReportRun(ctx, slow.ID); err != nil || got == nil {
		t.Fatalf("the run just saved was pruned: %v, %v", got, err)
	}
	runs, err := s.ListReportRuns(ctx, rep.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != maxPreviewKept {
		t.Fatalf("%d previews kept, want %d", len(runs), maxPreviewKept)
	}
}
