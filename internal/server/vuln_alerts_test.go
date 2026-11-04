package server

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func vulnRow(agent, host, id, sev string) store.AgentVulnRow {
	return store.AgentVulnRow{AgentID: agent, Hostname: host, VulnID: id, Severity: sev, PackageName: "openssl", CVEIDs: []string{id}}
}

func TestVulnEventSeverityMapsOntoTheIntegrationFloor(t *testing.T) {
	for _, c := range []struct {
		sev  string
		kev  bool
		want string
	}{
		{"critical", false, "critical"}, {"high", false, "warning"}, {"medium", false, "notice"},
		{"low", false, "info"}, {"", false, "notice"}, {"unknown", false, "notice"},
		{"low", true, "critical"}, {"", true, "critical"},
	} {
		if got := vulnEventSeverity(c.sev, c.kev); got != c.want {
			t.Errorf("%q kev=%v: %s, want %s", c.sev, c.kev, got, c.want)
		}
	}
	// "Only the big ones" has to mean exactly that at the floor people pick.
	if severityRank["warning"] >= severityRank["error"] || severityRank["critical"] < severityRank["error"] {
		t.Error("a floor of error must take critical findings and nothing below")
	}
}

func TestNewVulnFindingsAnnouncesOnceAndAgainOnlyWhenWorse(t *testing.T) {
	a := store.VulnAlertKey{AgentID: "a1", VulnID: "CVE-2026-1001"}
	rows := []store.AgentVulnRow{vulnRow("a1", "web", "CVE-2026-1001", "high")}

	fresh, marks := newVulnFindings(rows, nil, map[store.VulnAlertKey]int{})
	if len(fresh) != 1 || marks[a] != severityRank["warning"] {
		t.Fatalf("first sight: %v %v", fresh, marks)
	}
	if fresh, _ := newVulnFindings(rows, nil, marks); len(fresh) != 0 {
		t.Errorf("announced twice: %v", fresh)
	}
	worse := []store.AgentVulnRow{vulnRow("a1", "web", "CVE-2026-1001", "critical")}
	if fresh, _ := newVulnFindings(worse, nil, marks); len(fresh) != 1 {
		t.Error("a move to critical was not announced")
	}
	exploited := map[string]store.ExploitIntel{"CVE-2026-1001": {KEV: true}}
	if fresh, _ := newVulnFindings(rows, exploited, marks); len(fresh) != 1 || fresh[0].Tier != "critical" {
		t.Errorf("joining the KEV catalog was not announced: %v", fresh)
	}
	better := []store.AgentVulnRow{vulnRow("a1", "web", "CVE-2026-1001", "low")}
	if fresh, _ := newVulnFindings(better, nil, marks); len(fresh) != 0 {
		t.Errorf("a downgrade was announced: %v", fresh)
	}
	other := []store.AgentVulnRow{vulnRow("a2", "db", "CVE-2026-1001", "high")}
	if fresh, _ := newVulnFindings(other, nil, marks); len(fresh) != 1 {
		t.Error("the same CVE on another endpoint is news")
	}
}

func TestNewVulnFindingsSkipsWhatTheDistributionSaysNeedsNoAction(t *testing.T) {
	r := vulnRow("a1", "web", "CVE-2026-1001", "critical")
	r.Suppressed = true
	fresh, marks := newVulnFindings([]store.AgentVulnRow{r}, nil, map[store.VulnAlertKey]int{})
	if len(fresh) != 0 || len(marks) != 0 {
		t.Errorf("suppressed finding: %v %v", fresh, marks)
	}
}

func TestVulnDigestsAreOnePerTierAndBounded(t *testing.T) {
	var findings []vulnFinding
	add := func(agent, id, tier string, kev bool, epss float64) {
		r := vulnRow(agent, agent+"-host", id, "")
		findings = append(findings, vulnFinding{AgentVulnRow: r, Tier: tier, KEV: kev, EPSS: epss})
	}
	add("a1", "CVE-LOW", "info", false, 0)
	add("a1", "CVE-QUIET", "critical", false, 0.01)
	add("a2", "CVE-QUIET", "critical", false, 0.01)
	add("a3", "CVE-KEV", "critical", true, 0.2)
	for i := range vulnDigestRows + 5 {
		add("a1", "CVE-H"+strings.Repeat("x", i), "warning", false, 0)
	}
	evs := vulnDigests(findings)
	if len(evs) != 3 || evs[0].Severity != "critical" || evs[1].Severity != "warning" || evs[2].Severity != "info" {
		t.Fatalf("tiers: %+v", evs)
	}
	crit := evs[0]
	if crit.Type != "vulnerability" || crit.Link != "/risk" {
		t.Errorf("event: %+v", crit)
	}
	if crit.Title != "2 new critical vulnerabilities on 3 endpoints" {
		t.Errorf("title %q", crit.Title)
	}
	if !strings.HasPrefix(crit.Body, "- CVE-KEV") || !strings.Contains(crit.Body, "actively exploited") {
		t.Errorf("the exploited one should lead: %q", crit.Body)
	}
	if evs[2].Title != "1 new low vulnerability on 1 endpoint" {
		t.Errorf("title %q", evs[2].Title)
	}
	if !strings.Contains(evs[1].Body, "… and 5 more.") || strings.Count(evs[1].Body, "\n") != vulnDigestRows {
		t.Errorf("not bounded: %q", evs[1].Body)
	}
}

func TestFindingRowsCarryExploitDataAndAgreeWithTheRiskPage(t *testing.T) {
	kev := vulnRow("a1", "web", "CVE-2026-1001", "high")
	hidden := vulnRow("a1", "web", "CVE-2026-1002", "critical")
	hidden.Suppressed = true
	unrated := vulnRow("a1", "web", "CVE-2026-1003", "")
	rows := findingRows([]store.AgentVulnRow{kev, hidden, unrated},
		map[string]store.ExploitIntel{"CVE-2026-1001": {KEV: true, Ransomware: true, EPSS: 0.5}})
	if len(rows) != 2 {
		t.Fatalf("rows: %v", rows)
	}
	if rows[0]["kev"] != true || rows[0]["ransomware"] != true || rows[0]["epss"] != 0.5 {
		t.Errorf("exploit data: %v", rows[0])
	}
	if got := filterRows(rows, "kev", "true"); len(got) != 1 || got[0]["vuln_id"] != "CVE-2026-1001" {
		t.Errorf("a report filter on kev: %v", got)
	}
	if rows[1]["severity"] != "unknown" {
		t.Errorf("unrated: %v", rows[1])
	}
	cols := strings.Join(defaultReportColumns("findings", rows), ",")
	if !strings.Contains(cols, "severity") {
		t.Errorf("default columns lost severity: %s", cols)
	}
}

// Against a real database: the first scan only takes stock, later ones
// announce what is new, once, and it survives the store's round trip.
func TestAnnounceNewVulnerabilitiesAgainstTheStore(t *testing.T) {
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
	s := &Server{store: st, logger: slog.Default()}
	if err := st.SetSetting(ctx, settingVulnAlertsBaselined, "", "test"); err != nil {
		t.Fatal(err)
	}
	agent := idgen.New("agt-")
	drain := func() []integrationEvent {
		var out []integrationEvent
		for {
			select {
			case ev := <-s.integrations().queue:
				// Other packages' tests may share this database.
				if strings.Contains(ev.Body, agent) {
					out = append(out, ev)
				}
			default:
				return out
			}
		}
	}
	if err := st.UpsertOnRegister(ctx, agent, proto.AgentInfo{Hostname: "alert-" + agent, OS: "linux", Arch: "amd64", Version: "1.0.0"}); err != nil {
		t.Fatal(err)
	}
	replace := func(ids ...string) {
		rows := make([]store.AgentVulnerability, 0, len(ids))
		for _, id := range ids {
			rows = append(rows, store.AgentVulnerability{AgentID: agent, PackageName: "openssl", PackageVersion: "1",
				VulnID: id + agent, Severity: "critical", CheckedAt: time.Now()})
		}
		if err := st.ReplaceAgentVulnerabilities(ctx, agent, rows); err != nil {
			t.Fatal(err)
		}
	}

	replace("OLD-")
	if err := s.announceNewVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	if evs := drain(); len(evs) != 0 {
		t.Fatalf("the first scan announced: %+v", evs)
	}
	replace("OLD-", "NEW-")
	if err := s.announceNewVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	evs := drain()
	if len(evs) != 1 || !strings.Contains(evs[0].Body, "NEW-") || strings.Contains(evs[0].Body, "OLD-") {
		t.Fatalf("second scan: %+v", evs)
	}
	if err := s.announceNewVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	if evs := drain(); len(evs) != 0 {
		t.Fatalf("announced twice: %+v", evs)
	}
	// Gone and back within the window is not news.
	replace("OLD-")
	if err := s.announceNewVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	replace("OLD-", "NEW-")
	if err := s.announceNewVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	if evs := drain(); len(evs) != 0 {
		t.Fatalf("a finding that came back was announced: %+v", evs)
	}
	// Past the window it is.
	if err := st.PruneVulnAlerts(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.announceNewVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	if evs := drain(); len(evs) != 1 {
		t.Fatalf("after forgetting: %+v", evs)
	}
}

func TestVulnDigestLineReadsLikeACVE(t *testing.T) {
	f := vulnFinding{AgentVulnRow: store.AgentVulnRow{Hostname: "web", PackageName: "curl"}, EPSS: 0.004}
	line := vulnDigestLine("DEBIAN-CVE-2026-1001", []vulnFinding{f})
	if line != "- CVE-2026-1001 in curl on web" {
		t.Errorf("line %q", line)
	}
	f.EPSS, f.FixedVersion = 0.42, "8.1"
	line = vulnDigestLine("DEBIAN-CVE-2026-1001", []vulnFinding{f})
	if !strings.HasSuffix(line, ": EPSS 42%, fixed in 8.1") {
		t.Errorf("line %q", line)
	}
}

func TestFindingRowsPutTheWorstFirst(t *testing.T) {
	rows := findingRows([]store.AgentVulnRow{
		vulnRow("a", "h", "CVE-2026-1001", ""),
		vulnRow("a", "h", "CVE-2026-1002", "low"),
		vulnRow("a", "h", "CVE-2026-1003", "critical"),
		vulnRow("a", "h", "CVE-2026-1004", "medium"),
		vulnRow("a", "h", "CVE-2026-1005", "medium"),
		vulnRow("a", "h", "CVE-2026-1006", "low"),
	}, map[string]store.ExploitIntel{
		"CVE-2026-1006": {KEV: true},
		"CVE-2026-1005": {EPSS: 0.3},
	})
	var got []string
	for _, r := range rows {
		got = append(got, strings.TrimPrefix(r["vuln_id"].(string), "CVE-2026-"))
	}
	if want := "1006,1003,1005,1004,1002,1001"; strings.Join(got, ",") != want {
		t.Errorf("order %v, want %s", got, want)
	}
}
