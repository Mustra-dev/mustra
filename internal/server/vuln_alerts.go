package server

// New-vulnerability events. After each scan, findings nobody has been told
// about go to the integrations taking "vulnerability" events, as one digest
// per severity tier rather than one message per CVE and endpoint: a scan can
// turn up hundreds of findings, and a fleet's worth of mail stops being read.
//
// A tier maps onto the severity floor every integration already has, so the
// same setting chooses "everything" or "only the big ones":
//
//	critical, or in CISA's KEV catalog   critical
//	high                                 warning
//	medium, or not rated yet             notice
//	low                                  info
//
// Each endpoint's finding is announced once, and again only if it moves to a
// higher tier: when OSV's details arrive for one that was unrated, or when
// CISA adds it to the catalog. The first scan after this existed only takes
// stock. Telling an operator about every finding the fleet already has is
// not news, and it is all on the Risk page.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingVulnAlertsBaselined = "vuln_alerts.baselined"
	// vulnAlertForget is how long a finding must be gone before its coming
	// back counts as new. Long enough that an endpoint offline for a month's
	// holiday does not announce everything again on its return.
	vulnAlertForget = 90 * 24 * time.Hour
	// vulnDigestRows is how many vulnerabilities a digest names.
	vulnDigestRows = 20
)

var vulnTierLabels = map[string]string{
	"critical": "critical", "warning": "high", "notice": "medium or unrated", "info": "low",
}

// vulnEventSeverity is the tier of a finding, as an event severity.
func vulnEventSeverity(severity string, kev bool) string {
	if kev {
		return "critical"
	}
	switch severity {
	case "critical":
		return "critical"
	case "high":
		return "warning"
	case "low":
		return "info"
	}
	return "notice"
}

type vulnFinding struct {
	store.AgentVulnRow
	Tier       string
	KEV        bool
	Ransomware bool
	EPSS       float64
}

// newVulnFindings picks what has not been announced at this tier or higher,
// and every finding's mark for the store. A package can appear twice for one
// vulnerability on an endpoint; the mark holds the higher tier.
func newVulnFindings(rows []store.AgentVulnRow, intel map[string]store.ExploitIntel, seen map[store.VulnAlertKey]int) ([]vulnFinding, map[store.VulnAlertKey]int) {
	var fresh []vulnFinding
	marks := make(map[store.VulnAlertKey]int, len(rows))
	for _, r := range rows {
		if r.Suppressed {
			continue
		}
		f := vulnFinding{AgentVulnRow: r}
		if x, ok := vulnIntel(r, intel); ok {
			f.KEV, f.Ransomware, f.EPSS = x.KEV, x.Ransomware, x.EPSS
		}
		f.Tier = vulnEventSeverity(r.Severity, f.KEV)
		rank := severityRank[f.Tier]
		key := store.VulnAlertKey{AgentID: r.AgentID, VulnID: r.VulnID}
		if prev, ok := seen[key]; !ok || rank > prev {
			fresh = append(fresh, f)
		}
		if prev, ok := marks[key]; !ok || rank > prev {
			marks[key] = rank
		}
	}
	return fresh, marks
}

// vulnDigests turns findings into one event per tier, the most severe first.
func vulnDigests(findings []vulnFinding) []integrationEvent {
	byTier := map[string]map[string][]vulnFinding{}
	for _, f := range findings {
		if byTier[f.Tier] == nil {
			byTier[f.Tier] = map[string][]vulnFinding{}
		}
		byTier[f.Tier][f.VulnID] = append(byTier[f.Tier][f.VulnID], f)
	}
	var out []integrationEvent
	for _, tier := range []string{"critical", "warning", "notice", "info"} {
		if len(byTier[tier]) > 0 {
			out = append(out, vulnDigest(tier, byTier[tier]))
		}
	}
	return out
}

func vulnDigest(tier string, byVuln map[string][]vulnFinding) integrationEvent {
	ids := make([]string, 0, len(byVuln))
	endpoints := map[string]bool{}
	kev := 0
	for id, fs := range byVuln {
		ids = append(ids, id)
		if fs[0].KEV {
			kev++
		}
		for _, f := range fs {
			endpoints[f.AgentID] = true
		}
	}
	// Exploited first, then likeliest to be, then the most machines.
	sort.Slice(ids, func(i, j int) bool {
		a, b := byVuln[ids[i]], byVuln[ids[j]]
		if a[0].KEV != b[0].KEV {
			return a[0].KEV
		}
		if a[0].EPSS != b[0].EPSS {
			return a[0].EPSS > b[0].EPSS
		}
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		return ids[i] < ids[j]
	})
	lines := make([]string, 0, vulnDigestRows+1)
	for _, id := range ids[:min(len(ids), vulnDigestRows)] {
		lines = append(lines, vulnDigestLine(id, byVuln[id]))
	}
	if more := len(ids) - vulnDigestRows; more > 0 {
		lines = append(lines, fmt.Sprintf("… and %d more.", more))
	}
	title := fmt.Sprintf("%d new %s vulnerabilit%s on %d endpoint%s", len(ids), vulnTierLabels[tier],
		map[bool]string{true: "y", false: "ies"}[len(ids) == 1], len(endpoints), plural(len(endpoints)))
	return integrationEvent{
		Type: "vulnerability", Title: title, Severity: tier, Link: "/risk",
		Body: strings.Join(lines, "\n"),
		Detail: map[string]any{"kind": "new_findings", "vulnerabilities": len(ids), "endpoints": len(endpoints),
			"kev": kev, "ids": ids[:min(len(ids), 50)], "items": vulnDigestItems(ids[:min(len(ids), 50)], byVuln)},
	}
}

// vulnDigestItems is the same list as data, for an email template.
func vulnDigestItems(ids []string, byVuln map[string][]vulnFinding) []map[string]any {
	items := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		fs := byVuln[id]
		var hosts []string
		for _, f := range fs {
			if !containsString(hosts, f.Hostname) {
				hosts = append(hosts, f.Hostname)
			}
		}
		sort.Strings(hosts)
		items = append(items, map[string]any{"id": vulnDisplayName(id, fs[0]), "package": fs[0].PackageName, "hosts": hosts,
			"kev": fs[0].KEV, "ransomware": fs[0].Ransomware, "epss": fs[0].EPSS, "fixed": fs[0].FixedVersion})
	}
	return items
}

// vulnDisplayName is the name people search for, not a source's own
// (DEBIAN-CVE-…).
func vulnDisplayName(id string, f vulnFinding) string {
	if len(f.CVEIDs) > 0 {
		return f.CVEIDs[0]
	}
	return firstNonEmpty(cveFromID(id), id)
}

func vulnDigestLine(id string, fs []vulnFinding) string {
	first := fs[0]
	name := vulnDisplayName(id, first)
	hosts := make([]string, 0, len(fs))
	for _, f := range fs {
		if !containsString(hosts, f.Hostname) {
			hosts = append(hosts, f.Hostname)
		}
	}
	sort.Strings(hosts)
	on := strings.Join(hosts[:min(len(hosts), 3)], ", ")
	if more := len(hosts) - 3; more > 0 {
		on += fmt.Sprintf(" and %d more", more)
	}
	line := fmt.Sprintf("- %s in %s on %s", name, first.PackageName, on)
	var notes []string
	if first.KEV {
		notes = append(notes, "actively exploited (CISA KEV)")
	}
	if first.Ransomware {
		notes = append(notes, "used by ransomware")
	}
	// Below 1% rounds to a number that only looks like a signal.
	if first.EPSS >= 0.01 {
		notes = append(notes, fmt.Sprintf("EPSS %.0f%%", first.EPSS*100))
	}
	if first.FixedVersion != "" {
		notes = append(notes, "fixed in "+first.FixedVersion)
	}
	if len(notes) > 0 {
		line += ": " + strings.Join(notes, ", ")
	}
	return line
}

// announceNewVulnerabilities runs after a scan has stored its results. A
// failure here costs an alert, never the scan: it is logged, and what was not
// recorded is still new next time.
func (s *Server) announceNewVulnerabilities(ctx context.Context) error {
	rows, err := s.store.ListAllAgentVulnerabilities(ctx)
	if err != nil {
		return err
	}
	seen, err := s.store.ListVulnAlerts(ctx)
	if err != nil {
		return err
	}
	baselined, err := s.store.GetSetting(ctx, settingVulnAlertsBaselined)
	if err != nil {
		return err
	}
	fresh, marks := newVulnFindings(rows, s.intelForRows(ctx, rows), seen)
	if err := s.store.RecordVulnAlerts(ctx, marks); err != nil {
		return err
	}
	if baselined == "" {
		return s.store.SetSetting(ctx, settingVulnAlertsBaselined, "done", "system")
	}
	for _, ev := range vulnDigests(fresh) {
		s.emitEvent(ev)
	}
	return s.store.PruneVulnAlerts(ctx, time.Now().Add(-vulnAlertForget))
}
