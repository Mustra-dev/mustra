package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// The catalog finds the product, not its namesakes: Plex is not libmplex,
// BIND's name server is not its client tools, an OS rule is every
// endpoint on the OS, and a vulnerability-scan match outranks a product
// match on the same endpoint.
func TestThreatEvaluate(t *testing.T) {
	f := &threatFleet{
		agents: map[string]store.AgentRecord{
			"a-media": {AgentID: "a-media", Hostname: "media-01", OS: "linux", Online: true},
			"a-web":   {AgentID: "a-web", Hostname: "web-01", OS: "linux"},
			"a-dns":   {AgentID: "a-dns", Hostname: "dns-01", OS: "linux"},
			"a-win":   {AgentID: "a-win", Hostname: "WS-01", OS: "windows", Platform: "Microsoft Windows 11 Pro", PlatformVersion: "10.0.26100"},
		},
		software: map[string][]store.SoftwareRow{
			"a-media": {{AgentID: "a-media", Name: "plexmediaserver", Version: "1.43.1"}, {AgentID: "a-media", Name: "libmplex2-2.1-0", Version: "2.1"}},
			"a-web":   {{AgentID: "a-web", Name: "libmplex2-2.1-0", Version: "2.1"}, {AgentID: "a-web", Name: "bind9-dnsutils", Version: "9.18"}, {AgentID: "a-web", Name: "php8.3-fpm", Version: "8.3.6"}},
			"a-dns":   {{AgentID: "a-dns", Name: "bind9", Version: "9.18"}, {AgentID: "a-dns", Name: "bind9-dnsutils", Version: "9.18"}},
		},
		findings: map[string][]store.CVEFinding{
			"CVE-2026-1": {{CVE: "CVE-2026-1", AgentID: "a-web", PackageName: "php8.3-fpm", PackageVersion: "8.3.6", FixedVersion: "8.3.36"}},
		},
	}
	hosts := func(eps []threatEndpoint) string {
		var out []string
		for _, e := range eps {
			out = append(out, e.Hostname+"="+e.Status)
		}
		return strings.Join(out, ",")
	}
	plex, _ := kevRule("Plex", "Media Server")
	if eps, _ := f.evaluate([]string{"CVE-2026-96656"}, plex); hosts(eps) != "media-01=present" {
		got := hosts(eps)
		t.Errorf("plex: %s, want media-01 only (not libmplex on web-01)", got)
	}
	bind, _ := kevRule("ISC", "BIND")
	if eps, _ := f.evaluate(nil, bind); hosts(eps) != "dns-01=present" {
		got := hosts(eps)
		t.Errorf("bind: %s, want the name server only (not bind9-dnsutils)", got)
	}
	win, _ := kevRule("Microsoft", "Windows")
	if eps, _ := f.evaluate(nil, win); len(eps) != 1 || eps[0].Hostname != "WS-01" || eps[0].Version != "10.0.26100" {
		t.Errorf("windows: %+v, want WS-01 with its OS version", eps)
	}
	php, _ := kevRule("PHP", "PHP")
	eps, _ := f.evaluate([]string{"cve-2026-1"}, php)
	if len(eps) != 1 || eps[0].Status != "vulnerable" || eps[0].Fixed != "8.3.36" || len(eps[0].CVEs) != 1 {
		t.Errorf("php: %+v, want web-01 vulnerable (the scan match), fixed in 8.3.36", eps)
	}
	// A Linux endpoint whose vulnerability scan ran has had the package
	// checked: no finding for the CVE means cleared, not present.
	f.scanned = map[string]bool{"a-dns": true}
	if eps, cleared := f.evaluate(nil, bind); len(eps) != 0 || cleared != 1 {
		t.Errorf("bind on a scanned host: %+v cleared %d, want cleared", eps, cleared)
	}
	f.scanned = nil
	if _, ok := kevRule("Fortinet", "FortiMail"); !ok {
		t.Error("a vendor's appliance rule should cover its products")
	}
	if r, _ := kevRule("Fortinet", "FortiMail"); !r.Appliance || ruleChecks(r) {
		t.Error("an appliance is not checked on endpoints")
	}
	if _, ok := kevRule("Nobody", "Nothing"); ok {
		t.Error("an unknown product has no rule")
	}
}

// Every catalog pattern compiles as the matcher builds it.
func TestKEVProductRulesCompile(t *testing.T) {
	f := &threatFleet{}
	for k, r := range kevProductRules {
		if len(r.Apps) > 0 && f.appMatcher(r) == nil {
			t.Errorf("%s: patterns do not compile: %v", k, r.Apps)
		}
		if r.Label == "" {
			t.Errorf("%s: no label", k)
		}
	}
}

func TestKEVRefs(t *testing.T) {
	notes := "https://forums.plex.tv/t/x/1 ; ; BOD 26-04: https://www.cisa.gov/bod ; Forensics Triage Requirements: BOD 26-04: guidance | CISA ;  https://nvd.nist.gov/vuln/detail/CVE-2026-96656"
	refs := kevRefs(notes, "CVE-2026-96656")
	if len(refs) != 3 {
		t.Fatalf("refs %+v, want 3 links", refs)
	}
	if refs[0].Label != "forums.plex.tv" || refs[1].Label != "BOD 26-04" || refs[2].Label != "NVD: CVE-2026-96656" {
		t.Errorf("labels %+v", refs)
	}
}

// Hunting questions use the rule's own patterns, and parse as Interact
// questions (the operator words the query box knows).
func TestThreatQuestions(t *testing.T) {
	plex, _ := kevRule("Plex", "Media Server")
	qs := threatQuestions(plex)
	if len(qs) != 3 || !strings.Contains(qs[0], `installed_apps.name matches_regex "(?i)^(plex media server|plexmediaserver)$"`) ||
		!strings.Contains(qs[1], `processes.name matches_regex`) || !strings.Contains(qs[2], `services.name matches_regex`) {
		t.Errorf("questions %q", qs)
	}
	win, _ := kevRule("Microsoft", "Windows")
	if qs := threatQuestions(win); len(qs) != 1 || !strings.Contains(qs[0], "with os in windows") {
		t.Errorf("windows questions %q", qs)
	}
}

func TestSaveThreatRequestClean(t *testing.T) {
	for _, c := range []struct {
		req  saveThreatRequest
		want string
	}{
		{saveThreatRequest{}, "title"},
		{saveThreatRequest{Title: "x", CVEs: []string{"CVE-26-1"}}, "not a CVE"},
		{saveThreatRequest{Title: "x", Refs: []store.ThreatRef{{URL: "javascript:alert(1)"}}}, "http(s)"},
		{saveThreatRequest{Title: "x", Rule: store.ThreatRule{Apps: []string{"("}}}, "pattern"},
		{saveThreatRequest{Title: "x", Rule: store.ThreatRule{OS: []string{"bsd"}}}, "linux, windows or darwin"},
	} {
		if err := c.req.clean(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want an error about %s", c.req, err, c.want)
		}
	}
	ok := saveThreatRequest{Title: " PHP2Shell ", CVEs: []string{"cve-2026-109618", "CVE-2026-109618", ""}, Refs: []store.ThreatRef{{URL: "https://www.php.net/x"}}}
	if err := ok.clean(); err != nil || ok.Title != "PHP2Shell" || len(ok.CVEs) != 1 || ok.CVEs[0] != "CVE-2026-109618" || ok.Refs[0].Label != "www.php.net" {
		t.Errorf("clean: %v %+v", err, ok)
	}
}

// A written briefing: saved, listed in place of the KEV briefing for its
// CVE, opened, and deleted.
func TestThreatBriefLifecycle(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	body := `{"title":"Test briefing","cves":["CVE-2099-0001"],"summary":"First paragraph.\n\nSecond.","refs":[{"label":"Advisory","url":"https://example.com/a"}],"rule":{"label":"Nothing","apps":["no-such-package-xyz"]},"questions":["get hostname from all machines"]}`
	w := callSave(s.handleSaveThreat, "POST", "/api/threats", "", body)
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var b store.ThreatBrief
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	t.Cleanup(func() { _ = st.DeleteThreatBrief(context.Background(), b.ID) })
	if b.CreatedBy != "tester" || len(b.Refs) != 1 {
		t.Fatalf("saved %+v", b)
	}
	set, err := s.threatBriefings(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, x := range set.briefs {
		found = found || (x.ID == b.ID && x.Kind == "custom" && x.Rule.Checked)
	}
	if !found {
		t.Fatalf("the written briefing is not listed: %+v", set.briefs)
	}
	if w := callSave(s.handleSaveThreat, "PUT", "/x", "tb-missing", body); w.Code != http.StatusNotFound {
		t.Errorf("update of a missing briefing: %d, want 404", w.Code)
	}
	if w := callSave(s.handleDeleteThreat, "DELETE", "/x", b.ID, ""); w.Code != http.StatusOK {
		t.Errorf("delete: %d", w.Code)
	}
	if got, _ := st.GetThreatBrief(ctx, b.ID); got != nil {
		t.Error("still there after delete")
	}
}
