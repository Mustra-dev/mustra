package server

// Threat briefings: a dashboard per vulnerability being exploited now.
//
// Every CISA KEV entry added in the last 30 days (threats.window_days) has
// a briefing, and so does any older entry that is found in the fleet.
// Briefings written by hand (threat_briefs) group CVEs under one name with
// notes, mitigation, a detection rule and hunting questions; a CVE in one
// of those is shown there rather than twice.
//
// An endpoint is affected in one of two ways, kept apart because they mean
// different things:
//
//   - vulnerable: the vulnerability scan matched an installed package's
//     version against the advisory (OSV) -- confirmed;
//   - product present: the product is installed (or, for an operating
//     system, the endpoint runs it) but nothing checked its version against
//     this CVE -- the endpoint needs looking at.
//
// A product with no detection rule is "not checked", and a network
// appliance or hosted service is said to be outside what an endpoint agent
// sees, rather than either counting as zero.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingThreatWindowDays = "threats.window_days"
	defaultThreatWindowDays = 30
	threatTrendDays         = 30
)

// threatRuleView is a briefing's detection rule as the page shows it.
type threatRuleView struct {
	Label string `json:"label"`
	// Checked is false when no rule says how to find the product.
	Checked   bool   `json:"checked"`
	Appliance bool   `json:"appliance"`
	Note      string `json:"note,omitempty"`
}

// threatBriefing is one briefing in the list.
type threatBriefing struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"` // kev | custom
	Title      string     `json:"title"`
	CVEs       []string   `json:"cves"`
	Vendor     string     `json:"vendor,omitempty"`
	Product    string     `json:"product,omitempty"`
	Summary    string     `json:"summary"`
	DateAdded  *time.Time `json:"date_added,omitempty"`
	DueDate    *time.Time `json:"due_date,omitempty"`
	Ransomware bool       `json:"ransomware"`
	// KEV says CISA lists at least one of the CVEs as exploited in the
	// wild.
	KEV  bool           `json:"kev"`
	EPSS *float64       `json:"epss,omitempty"`
	CVSS *float64       `json:"cvss,omitempty"`
	Rule threatRuleView `json:"rule"`
	// Vulnerable and Present count endpoints (see the file comment);
	// an endpoint is counted once, as vulnerable when it is both.
	Vulnerable int `json:"vulnerable"`
	Present    int `json:"present"`
	// Cleared counts Linux endpoints with the product whose vulnerability
	// scan checked it and does not flag these CVEs.
	Cleared int `json:"cleared"`
}

// threatEndpoint is one affected endpoint.
type threatEndpoint struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Online   bool   `json:"online"`
	// Status is vulnerable or present.
	Status  string `json:"status"`
	Product string `json:"product"`
	Version string `json:"version"`
	// Fixed is the version the advisory names as fixed, when known.
	Fixed string   `json:"fixed,omitempty"`
	CVEs  []string `json:"cves,omitempty"`
	// Packages are the installed packages the scan found vulnerable to
	// these CVEs here (Product is the first of them): what a remediation
	// that updates only the affected software installs.
	Packages []string `json:"packages,omitempty"`
}

// threatVersion is one installed version and how many endpoints run it.
type threatVersion struct {
	OS      string `json:"os"`
	Product string `json:"product"`
	Version string `json:"version"`
	Count   int    `json:"count"`
}

// threatCVE is one CVE of a briefing, with what CISA and FIRST say.
type threatCVE struct {
	CVE            string     `json:"cve"`
	Name           string     `json:"name,omitempty"`
	Description    string     `json:"description,omitempty"`
	KEV            bool       `json:"kev"`
	DateAdded      *time.Time `json:"date_added,omitempty"`
	DueDate        *time.Time `json:"due_date,omitempty"`
	RequiredAction string     `json:"required_action,omitempty"`
	Ransomware     bool       `json:"ransomware"`
	EPSS           *float64   `json:"epss,omitempty"`
	Percentile     *float64   `json:"percentile,omitempty"`
}

// threatDetail is one briefing's whole dashboard: GET /api/threats/{id}.
type threatDetail struct {
	threatBriefing
	Mitigation string              `json:"mitigation,omitempty"`
	CVEDetails []threatCVE         `json:"cve_details"`
	Refs       []store.ThreatRef   `json:"refs"`
	Endpoints  []threatEndpoint    `json:"endpoints"`
	Versions   []threatVersion     `json:"versions"`
	Trend      []store.ThreatCount `json:"trend"`
	// Questions are Interact questions for hunting: where the product is,
	// and what it is running.
	Questions []string `json:"questions"`
	// Editable is set when the caller may edit or delete a written
	// briefing (alerts.triage).
	Editable bool `json:"editable"`
	// Custom is the written briefing as saved, for the editor.
	Custom *store.ThreatBrief `json:"custom,omitempty"`
	// RuleSpec is the detection rule in full, to start a written briefing
	// from a KEV one.
	RuleSpec store.ThreatRule `json:"rule_spec"`
	// Catalog lists the Software catalog packages that install the
	// affected product, with the affected endpoints each one detects; only
	// for callers with deploy.manage, who can deploy them.
	Catalog []threatCatalogFix `json:"catalog,omitempty"`
}

// threatCatalogFix is a catalog package that can update an affected
// product: the fix for software the operating system's updater does not
// manage, such as a browser installed from its vendor's installer.
type threatCatalogFix struct {
	PackageID string `json:"package_id"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	// Operation is what to run: update when the package has an update
	// step for the endpoints' systems, else install.
	Operation string   `json:"operation"`
	AgentIDs  []string `json:"agent_ids"`
}

// threatFleet is what one evaluation reads, once.
type threatFleet struct {
	agents map[string]store.AgentRecord
	// scanned are Linux endpoints whose vulnerability scan ran in the last
	// week: it checks every distribution package against the
	// distribution's own security data, so a package it did not flag for
	// a CVE has been checked, not just seen.
	scanned  map[string]bool
	software map[string][]store.SoftwareRow // by agent
	findings map[string][]store.CVEFinding  // by CVE
	regexps  sync.Map
}

// loadThreatFleet reads the endpoints the caller may see (all of them
// for the system's own sweep, wholeFleet), their software and the
// findings for cves.
func (s *Server) loadThreatFleet(ctx context.Context, cves []string, wholeFleet bool) (*threatFleet, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	var scope map[string]bool
	if !wholeFleet {
		if scope, err = s.endpointScope(ctx); err != nil {
			return nil, err
		}
	}
	f := &threatFleet{agents: map[string]store.AgentRecord{}, software: map[string][]store.SoftwareRow{}, findings: map[string][]store.CVEFinding{}}
	for _, a := range agents {
		if a.Managed && (scope == nil || scope[a.AgentID]) {
			f.agents[a.AgentID] = a
		}
	}
	sw, err := s.store.ListSoftwareRows(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range sw {
		if _, ok := f.agents[r.AgentID]; ok {
			f.software[r.AgentID] = append(f.software[r.AgentID], r)
		}
	}
	if f.scanned, err = s.store.VulnScannedSince(ctx, time.Now().Add(-7*24*time.Hour)); err != nil {
		return nil, err
	}
	found, err := s.store.ListCVEFindings(ctx, cves)
	if err != nil {
		return nil, err
	}
	for _, x := range found {
		if _, ok := f.agents[x.AgentID]; ok {
			f.findings[x.CVE] = append(f.findings[x.CVE], x)
		}
	}
	return f, nil
}

// appMatcher compiles a rule's app patterns into one whole-name,
// case-insensitive expression; nil when the rule has none.
func (f *threatFleet) appMatcher(rule store.ThreatRule) *regexp.Regexp {
	if len(rule.Apps) == 0 {
		return nil
	}
	src := `(?i)^(?:` + strings.Join(rule.Apps, "|") + `)$`
	if re, ok := f.regexps.Load(src); ok {
		return re.(*regexp.Regexp)
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil
	}
	f.regexps.Store(src, re)
	return re
}

func ruleChecks(rule store.ThreatRule) bool {
	return !rule.Appliance && (len(rule.Apps) > 0 || len(rule.OS) > 0)
}

// evaluate finds a briefing's affected endpoints, and counts the Linux
// endpoints that have the product but whose vulnerability scan checked it
// and found nothing for these CVEs (cleared).
func (f *threatFleet) evaluate(cves []string, rule store.ThreatRule) ([]threatEndpoint, int) {
	cleared := 0
	by := map[string]*threatEndpoint{}
	for _, cve := range cves {
		for _, x := range f.findings[strings.ToUpper(cve)] {
			a := f.agents[x.AgentID]
			e := by[x.AgentID]
			if e == nil || e.Status != "vulnerable" {
				e = &threatEndpoint{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Online: a.Online, Status: "vulnerable",
					Product: x.PackageName, Version: x.PackageVersion, Fixed: x.FixedVersion}
				by[x.AgentID] = e
			}
			if !containsString(e.CVEs, strings.ToUpper(cve)) {
				e.CVEs = append(e.CVEs, strings.ToUpper(cve))
			}
			if x.PackageName != "" && !containsString(e.Packages, x.PackageName) {
				e.Packages = append(e.Packages, x.PackageName)
			}
		}
	}
	if ruleChecks(rule) {
		re := f.appMatcher(rule)
		for id, a := range f.agents {
			if by[id] != nil || (len(rule.OS) > 0 && !containsString(rule.OS, a.OS)) {
				continue
			}
			if re == nil {
				// An operating-system rule: the endpoint runs it.
				by[id] = &threatEndpoint{AgentID: id, Hostname: a.Hostname, OS: a.OS, Online: a.Online, Status: "present",
					Product: firstNonEmpty(a.Platform, a.OS), Version: a.PlatformVersion}
				continue
			}
			for _, sw := range f.software[id] {
				if re.MatchString(sw.Name) {
					if a.OS == "linux" && f.scanned[id] {
						cleared++
					} else {
						by[id] = &threatEndpoint{AgentID: id, Hostname: a.Hostname, OS: a.OS, Online: a.Online, Status: "present", Product: sw.Name, Version: sw.Version, Packages: []string{sw.Name}}
					}
					break
				}
			}
		}
	}
	out := make([]threatEndpoint, 0, len(by))
	for _, e := range by {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Status != out[j].Status {
			return out[i].Status == "vulnerable"
		}
		return strings.ToLower(out[i].Hostname) < strings.ToLower(out[j].Hostname)
	})
	return out, cleared
}

func countStatus(eps []threatEndpoint) (vulnerable, present int) {
	for _, e := range eps {
		if e.Status == "vulnerable" {
			vulnerable++
		} else {
			present++
		}
	}
	return
}

func (s *Server) threatWindowDays(ctx context.Context) int {
	if v, err := s.store.GetSetting(ctx, settingThreatWindowDays); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 && n <= 365 {
			return n
		}
	}
	return defaultThreatWindowDays
}

// threatSet is every current briefing, evaluated.
type threatSet struct {
	briefs []threatBriefing
	// epss holds EPSS for written briefings' CVEs that are not in KEV
	// (EPSS scores every published CVE, KEV only the exploited ones).
	epss      map[string]store.ExploitIntel
	kev       map[string]store.KEVEntry
	custom    map[string]store.ThreatBrief
	endpoints map[string][]threatEndpoint
	rules     map[string]store.ThreatRule
}

// threatBriefings builds and evaluates every briefing over the endpoints
// the caller can see, or the whole fleet (wholeFleet, the system's sweep).
func (s *Server) threatBriefings(ctx context.Context, wholeFleet bool) (*threatSet, error) {
	kevs, err := s.store.ListKEVEntries(ctx)
	if err != nil {
		return nil, err
	}
	custom, err := s.store.ListThreatBriefs(ctx)
	if err != nil {
		return nil, err
	}
	set := &threatSet{epss: map[string]store.ExploitIntel{}, kev: map[string]store.KEVEntry{}, custom: map[string]store.ThreatBrief{}, endpoints: map[string][]threatEndpoint{}, rules: map[string]store.ThreatRule{}}
	cves := []string{}
	for _, k := range kevs {
		set.kev[strings.ToUpper(k.CVE)] = k
		cves = append(cves, k.CVE)
	}
	covered := map[string]bool{}
	for _, b := range custom {
		set.custom[b.ID] = b
		if b.Archived {
			continue
		}
		for _, c := range b.CVEs {
			covered[strings.ToUpper(c)] = true
			cves = append(cves, c)
		}
	}
	fleet, err := s.loadThreatFleet(ctx, cves, wholeFleet)
	if err != nil {
		return nil, err
	}
	var notKEV []string
	for _, b := range custom {
		for _, c := range b.CVEs {
			if _, ok := set.kev[strings.ToUpper(c)]; !ok {
				notKEV = append(notKEV, c)
			}
		}
	}
	if set.epss, err = s.store.LookupExploitIntel(ctx, notKEV); err != nil {
		return nil, err
	}
	since := time.Now().AddDate(0, 0, -s.threatWindowDays(ctx))

	for _, b := range custom {
		if b.Archived {
			continue
		}
		eps, cleared := fleet.evaluate(b.CVEs, b.Rule)
		br := threatBriefing{Cleared: cleared, ID: b.ID, Kind: "custom", Title: b.Title, CVEs: b.CVEs, Summary: b.Summary,
			Rule: threatRuleView{Label: b.Rule.Label, Checked: ruleChecks(b.Rule), Appliance: b.Rule.Appliance, Note: b.Rule.Note}}
		for _, c := range b.CVEs {
			if k, ok := set.kev[strings.ToUpper(c)]; ok {
				br.KEV = true
				br.Ransomware = br.Ransomware || k.Ransomware
				br.EPSS = maxFloat(br.EPSS, k.EPSS)
				if br.DateAdded == nil || (k.DateAdded != nil && k.DateAdded.After(*br.DateAdded)) {
					br.DateAdded = k.DateAdded
				}
				if k.DueDate != nil && (br.DueDate == nil || k.DueDate.Before(*br.DueDate)) {
					br.DueDate = k.DueDate
				}
			}
			if x, ok := set.epss[strings.ToUpper(c)]; ok && x.Scored {
				e := x.EPSS
				br.EPSS = maxFloat(br.EPSS, &e)
			}
			for _, x := range fleet.findings[strings.ToUpper(c)] {
				br.CVSS = maxFloat(br.CVSS, x.CVSS)
			}
		}
		br.Vulnerable, br.Present = countStatus(eps)
		set.briefs = append(set.briefs, br)
		set.endpoints[b.ID] = eps
		set.rules[b.ID] = b.Rule
	}
	for _, k := range kevs {
		cve := strings.ToUpper(k.CVE)
		if covered[cve] {
			continue
		}
		rule, known := kevRule(k.Vendor, k.Product)
		if !known {
			rule = store.ThreatRule{Label: strings.TrimSpace(k.Vendor + " " + k.Product)}
		}
		eps, cleared := fleet.evaluate([]string{cve}, rule)
		vuln, present := countStatus(eps)
		recent := k.DateAdded != nil && k.DateAdded.After(since)
		// Older entries only when the scan confirms them. An installed
		// product alone would bring back Heartbleed for every OpenSSL,
		// and an operating system every Windows entry since 2021.
		if !recent && vuln == 0 {
			continue
		}
		br := threatBriefing{ID: "kev-" + cve, Kind: "kev", Title: firstNonEmpty(k.Name, cve), CVEs: []string{cve}, Vendor: k.Vendor, Product: k.Product,
			Summary: k.Description, DateAdded: k.DateAdded, DueDate: k.DueDate, Ransomware: k.Ransomware, KEV: true, EPSS: k.EPSS,
			Rule:       threatRuleView{Label: rule.Label, Checked: ruleChecks(rule), Appliance: rule.Appliance, Note: rule.Note},
			Vulnerable: vuln, Present: present, Cleared: cleared}
		for _, x := range fleet.findings[cve] {
			br.CVSS = maxFloat(br.CVSS, x.CVSS)
		}
		set.briefs = append(set.briefs, br)
		set.endpoints[br.ID] = eps
		set.rules[br.ID] = rule
	}
	sort.SliceStable(set.briefs, func(i, j int) bool {
		a, b := set.briefs[i], set.briefs[j]
		if (a.Vulnerable > 0) != (b.Vulnerable > 0) {
			return a.Vulnerable > 0
		}
		if (a.Present > 0) != (b.Present > 0) {
			return a.Present > 0
		}
		if a.Kind != b.Kind {
			return a.Kind == "custom"
		}
		ad, bd := time.Time{}, time.Time{}
		if a.DateAdded != nil {
			ad = *a.DateAdded
		}
		if b.DateAdded != nil {
			bd = *b.DateAdded
		}
		return ad.After(bd)
	})
	return set, nil
}

func maxFloat(cur, v *float64) *float64 {
	if v == nil {
		return cur
	}
	if cur == nil || *v > *cur {
		x := *v
		return &x
	}
	return cur
}

// threatsResponse is what GET /api/threats answers.
type threatsResponse struct {
	Briefings []threatBriefing `json:"briefings"`
	// WindowDays is how far back CISA KEV additions are listed even when
	// the fleet does not have them.
	WindowDays int `json:"window_days"`
	// KEVFetchedAt is when the CISA catalog was last downloaded.
	KEVFetchedAt string `json:"kev_fetched_at,omitempty"`
	// Editable is set when the caller may write briefings
	// (alerts.triage).
	Editable bool `json:"editable"`
}

func (s *Server) canWriteThreats(r *http.Request) bool {
	can, _ := s.auth.HasPermission(r.Context(), auth.CurrentUser(r.Context()), auth.PermAlertsTriage)
	return can
}

// GET /api/threats: every current briefing, most affecting first.
func (s *Server) handleListThreats(w http.ResponseWriter, r *http.Request) {
	set, err := s.threatBriefings(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fetched, _ := s.store.GetSetting(r.Context(), "exploitintel.kev_fetched_at")
	out := threatsResponse{Briefings: set.briefs, WindowDays: s.threatWindowDays(r.Context()), KEVFetchedAt: fetched, Editable: s.canWriteThreats(r)}
	if out.Briefings == nil {
		out.Briefings = []threatBriefing{}
	}
	writeJSONResponse(w, out)
}

// kevRefs reads the links out of a KEV entry's notes: "Label: url ; url".
func kevRefs(notes, cve string) []store.ThreatRef {
	out := []store.ThreatRef{}
	seen := map[string]bool{}
	for _, part := range strings.Split(notes, ";") {
		part = strings.TrimSpace(part)
		i := strings.Index(part, "https://")
		if i < 0 {
			i = strings.Index(part, "http://")
		}
		if i < 0 {
			continue
		}
		link := strings.Fields(part[i:])[0]
		u, err := url.Parse(link)
		if err != nil || u.Host == "" || seen[link] {
			continue
		}
		seen[link] = true
		label := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part[:i]), ":"))
		if label == "" {
			label = u.Host
			if strings.Contains(u.Host, "nvd.nist.gov") {
				label = "NVD: " + cve
			}
		}
		out = append(out, store.ThreatRef{Label: label, URL: link})
	}
	return out
}

// threatQuestions are hunting questions for a rule: where the product is
// installed, and where it is running.
func threatQuestions(rule store.ThreatRule) []string {
	out := []string{}
	if len(rule.Apps) > 0 {
		re := `(?i)^(` + strings.Join(rule.Apps, "|") + `)$`
		out = append(out, fmt.Sprintf(`get hostname and installed_apps.name and installed_apps.version from all machines with installed_apps.name matches_regex %q`, re))
	} else if len(rule.OS) > 0 && !rule.Appliance {
		out = append(out, fmt.Sprintf(`get hostname and os and platform_version from all machines with os in %s`, strings.Join(rule.OS, ",")))
	}
	if len(rule.Processes) > 0 {
		out = append(out, fmt.Sprintf(`get hostname and processes.name from all machines with processes.name matches_regex %q`, `(?i)^(`+regexpAlternation(rule.Processes)+`)$`))
	}
	if len(rule.Services) > 0 {
		out = append(out, fmt.Sprintf(`get hostname and services.name and services.status from all machines with services.name matches_regex %q`, `(?i)^(`+regexpAlternation(rule.Services)+`)$`))
	}
	return out
}

func regexpAlternation(names []string) string {
	q := make([]string, 0, len(names))
	for _, n := range names {
		q = append(q, regexp.QuoteMeta(n))
	}
	return strings.Join(q, "|")
}

// GET /api/threats/{id}: one briefing's dashboard.
func (s *Server) handleGetThreat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	set, err := s.threatBriefings(ctx, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var br *threatBriefing
	for i := range set.briefs {
		if set.briefs[i].ID == id {
			br = &set.briefs[i]
		}
	}
	if br == nil {
		// A KEV entry out of the window, or an archived briefing, still
		// opens from a link.
		if c, ok := set.custom[id]; ok {
			br = &threatBriefing{ID: c.ID, Kind: "custom", Title: c.Title, CVEs: c.CVEs, Summary: c.Summary}
			set.rules[id] = c.Rule
		} else if k, ok := set.kev[strings.ToUpper(strings.TrimPrefix(id, "kev-"))]; ok && strings.HasPrefix(id, "kev-") {
			rule, _ := kevRule(k.Vendor, k.Product)
			br = &threatBriefing{ID: id, Kind: "kev", Title: firstNonEmpty(k.Name, k.CVE), CVEs: []string{k.CVE}, Vendor: k.Vendor, Product: k.Product,
				Summary: k.Description, DateAdded: k.DateAdded, DueDate: k.DueDate, Ransomware: k.Ransomware, KEV: true, EPSS: k.EPSS,
				Rule: threatRuleView{Label: rule.Label, Checked: ruleChecks(rule), Appliance: rule.Appliance, Note: rule.Note}}
			set.rules[id] = rule
		} else {
			http.Error(w, "no such briefing", http.StatusNotFound)
			return
		}
		fleet, err := s.loadThreatFleet(ctx, br.CVEs, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		set.endpoints[id], br.Cleared = fleet.evaluate(br.CVEs, set.rules[id])
		br.Vulnerable, br.Present = countStatus(set.endpoints[id])
	}
	d := threatDetail{threatBriefing: *br, Endpoints: set.endpoints[id], Refs: []store.ThreatRef{}, CVEDetails: []threatCVE{},
		Versions: []threatVersion{}, Questions: threatQuestions(set.rules[id]), Editable: s.canWriteThreats(r), RuleSpec: set.rules[id]}
	if d.Endpoints == nil {
		d.Endpoints = []threatEndpoint{}
	}
	if c, ok := set.custom[id]; ok {
		d.Mitigation = c.Mitigation
		d.Refs = append(d.Refs, c.Refs...)
		d.Questions = append(append([]string{}, c.Questions...), d.Questions...)
		cc := c
		d.Custom = &cc
	}
	for _, cve := range br.CVEs {
		k, ok := set.kev[strings.ToUpper(cve)]
		tc := threatCVE{CVE: strings.ToUpper(cve)}
		if ok {
			tc = threatCVE{CVE: k.CVE, Name: k.Name, Description: k.Description, KEV: true, DateAdded: k.DateAdded, DueDate: k.DueDate,
				RequiredAction: k.RequiredAction, Ransomware: k.Ransomware, EPSS: k.EPSS, Percentile: k.Percentile}
			d.Refs = append(d.Refs, kevRefs(k.Notes, k.CVE)...)
		} else {
			if x, ok := set.epss[tc.CVE]; ok && x.Scored {
				e, p := x.EPSS, x.Percentile
				tc.EPSS, tc.Percentile = &e, &p
			}
			d.Refs = append(d.Refs, store.ThreatRef{Label: "NVD: " + tc.CVE, URL: "https://nvd.nist.gov/vuln/detail/" + tc.CVE})
		}
		d.CVEDetails = append(d.CVEDetails, tc)
	}
	counts := map[string]int{}
	for _, e := range d.Endpoints {
		counts[e.OS+"\x00"+e.Product+"\x00"+e.Version]++
	}
	for k, n := range counts {
		p := strings.SplitN(k, "\x00", 3)
		d.Versions = append(d.Versions, threatVersion{OS: p[0], Product: p[1], Version: p[2], Count: n})
	}
	sort.Slice(d.Versions, func(i, j int) bool {
		if d.Versions[i].Count != d.Versions[j].Count {
			return d.Versions[i].Count > d.Versions[j].Count
		}
		return d.Versions[i].Version < d.Versions[j].Version
	})
	trend, err := s.store.ThreatCounts(ctx, id, time.Now().AddDate(0, 0, -threatTrendDays))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.Trend = trend
	if can, _ := s.auth.HasPermission(ctx, auth.CurrentUser(ctx), auth.PermDeployManage); can {
		d.Catalog = s.threatCatalogFixes(ctx, d.Endpoints)
	}
	writeJSONResponse(w, d)
}

// threatCatalogFixes matches the affected endpoints' products against the
// enabled software packages' own detection rules, the same test that
// decides whether a package counts as installed on an endpoint.
func (s *Server) threatCatalogFixes(ctx context.Context, eps []threatEndpoint) []threatCatalogFix {
	if len(eps) == 0 {
		return nil
	}
	pkgs, err := s.store.ListSoftwarePackages(ctx)
	if err != nil {
		s.logger.Warn("list software packages for a briefing", "error", err)
		return nil
	}
	var out []threatCatalogFix
	for _, p := range pkgs {
		if !p.Enabled || p.Kind == store.KindAction || p.Detect.Fact != "" {
			continue
		}
		fix := threatCatalogFix{PackageID: p.ID, Name: p.Name, Version: p.Version}
		allUpdate := true
		for _, e := range eps {
			ops, hasOS := p.Commands[e.OS]
			if p.DeployRevision == "" && (!hasOS || (ops.Install == "" && ops.Update == "")) {
				continue
			}
			apps := map[string]string{}
			for _, name := range append([]string{e.Product}, e.Packages...) {
				if name != "" {
					apps[strings.ToLower(name)] = e.Version
				}
			}
			if matchInstalled(p.Detect, p.Name, apps) == "" {
				continue
			}
			fix.AgentIDs = append(fix.AgentIDs, e.AgentID)
			if p.DeployRevision == "" && ops.Update == "" {
				allUpdate = false
			}
		}
		fix.Operation = "install"
		if allUpdate {
			fix.Operation = "update"
		}
		if len(fix.AgentIDs) > 0 {
			out = append(out, fix)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// saveThreatRequest is the body of POST /api/threats and PUT
// /api/threats/{id}: a briefing written by hand.
type saveThreatRequest struct {
	Title string `json:"title" api:"required"`
	// CVEs it covers, e.g. ["CVE-2026-109618", "CVE-2026-109619"]. A
	// CVE in a written briefing is shown there, not as its own KEV
	// briefing.
	CVEs []string `json:"cves"`
	// Summary and Mitigation are plain text; a blank line starts a new
	// paragraph.
	Summary    string            `json:"summary"`
	Mitigation string            `json:"mitigation"`
	Refs       []store.ThreatRef `json:"refs"`
	// Rule says how to find the product on an endpoint.
	Rule store.ThreatRule `json:"rule"`
	// Questions are extra Interact questions for hunting.
	Questions []string `json:"questions"`
	Archived  bool     `json:"archived"`
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func (req *saveThreatRequest) clean() error {
	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" {
		return fmt.Errorf("a briefing needs a title")
	}
	cves := []string{}
	for _, c := range req.CVEs {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if !cvePattern.MatchString(c) {
			return fmt.Errorf("%q is not a CVE ID (CVE-2026-12345)", c)
		}
		if !containsString(cves, c) {
			cves = append(cves, c)
		}
	}
	req.CVEs = cves
	refs := []store.ThreatRef{}
	for _, ref := range req.Refs {
		u, err := url.Parse(strings.TrimSpace(ref.URL))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("reference %q is not an http(s) link", ref.URL)
		}
		refs = append(refs, store.ThreatRef{Label: firstNonEmpty(strings.TrimSpace(ref.Label), u.Host), URL: u.String()})
	}
	req.Refs = refs
	for _, p := range req.Rule.Apps {
		if _, err := regexp.Compile(`(?i)^(?:` + p + `)$`); err != nil {
			return fmt.Errorf("application pattern %q: %v", p, err)
		}
	}
	for _, o := range req.Rule.OS {
		if o != "linux" && o != "windows" && o != "darwin" {
			return fmt.Errorf("operating system %q: use linux, windows or darwin", o)
		}
	}
	qs := []string{}
	for _, q := range req.Questions {
		if q = strings.TrimSpace(q); q != "" {
			qs = append(qs, q)
		}
	}
	req.Questions = qs
	if len(req.Summary) > 20000 || len(req.Mitigation) > 20000 {
		return fmt.Errorf("the summary and mitigation are limited to 20,000 characters each")
	}
	return nil
}

func (s *Server) handleSaveThreat(w http.ResponseWriter, r *http.Request) {
	var req saveThreatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := req.clean(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	b := store.ThreatBrief{Title: req.Title, CVEs: req.CVEs, Summary: req.Summary, Mitigation: req.Mitigation, Refs: req.Refs,
		Rule: req.Rule, Questions: req.Questions, Archived: req.Archived}
	if id := r.PathValue("id"); id != "" {
		old, err := s.store.GetThreatBrief(ctx, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if old == nil {
			http.Error(w, "no such briefing", http.StatusNotFound)
			return
		}
		b.ID, b.CreatedBy = old.ID, old.CreatedBy
	} else {
		b.ID, b.CreatedBy = newID("tb-"), who
	}
	saved, err := s.store.SaveThreatBrief(ctx, b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "threats.briefing.save", Actor: who, Target: saved.Title, Severity: "notice",
		Detail: map[string]any{"id": saved.ID, "cves": saved.CVEs, "archived": saved.Archived}})
	writeJSONResponse(w, saved)
}

// deleteThreatResponse is what DELETE /api/threats/{id} answers.
type deleteThreatResponse struct {
	Deleted string `json:"deleted"`
}

func (s *Server) handleDeleteThreat(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.GetThreatBrief(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if b == nil {
		http.Error(w, "no such briefing", http.StatusNotFound)
		return
	}
	if err := s.store.DeleteThreatBrief(r.Context(), b.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "threats.briefing.delete", Actor: auth.CurrentUser(r.Context()).Username, Target: b.Title, Severity: "notice",
		Detail: map[string]any{"id": b.ID}})
	writeJSONResponse(w, deleteThreatResponse{Deleted: b.ID})
}

// threatLoop keeps each briefing's trend (one count a day, refreshed
// hourly) and notifies once when an actively exploited vulnerability is
// found in the fleet: confirmed, or an installed product. An operating
// system alone does not notify -- every month's Windows entry would.
func (s *Server) threatLoop(ctx context.Context) {
	tick := func() {
		// The whole fleet: there is no user here to scope it to.
		set, err := s.threatBriefings(ctx, true)
		if err != nil {
			s.logger.Warn("threat briefings: evaluation failed", "error", err)
			return
		}
		alerted, err := s.store.ThreatAlerted(ctx)
		if err != nil {
			return
		}
		for _, b := range set.briefs {
			_ = s.store.RecordThreatCount(ctx, b.ID, b.Vulnerable, b.Present)
			rule := set.rules[b.ID]
			found := b.Vulnerable
			if len(rule.Apps) > 0 {
				found += b.Present
			}
			switch {
			case found > 0 && !alerted[b.ID]:
				what := fmt.Sprintf("%d endpoint(s): %d vulnerable", found, b.Vulnerable)
				if len(rule.Apps) > 0 {
					what += fmt.Sprintf(", %d with %s installed", b.Present, firstNonEmpty(rule.Label, "the product"))
				}
				s.notify(ctx, "warning", "Threat briefings", "Actively exploited: "+b.Title, what, "/threats#"+url.PathEscape(b.ID))
				s.audit(ctx, auditEvent{Action: "threats.found", Actor: "system", Target: b.Title, Severity: "warning",
					Detail: map[string]any{"id": b.ID, "cves": b.CVEs, "vulnerable": b.Vulnerable, "present": b.Present}})
				_ = s.store.MarkThreatAlerted(ctx, b.ID, found, false)
			case found == 0 && alerted[b.ID]:
				_ = s.store.MarkThreatAlerted(ctx, b.ID, 0, true)
			}
		}
		_ = s.store.PruneThreatCounts(ctx, time.Now().AddDate(0, 0, -(threatTrendDays+7)))
		s.remediateThreats(ctx, set)
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	tick()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
