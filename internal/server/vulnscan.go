package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/debsec"
	"github.com/mustra-dev/mustra/internal/server/osv"
	"github.com/mustra-dev/mustra/internal/store"
)

// ecosystemForPlatform maps an agent's gopsutil-reported Platform to the
// OSV ecosystem vocabulary. Anything not listed here (Windows, macOS,
// RHEL-family) is skipped, not guessed at — OSV's OS-package coverage is
// specifically Debian/Ubuntu/Alpine; claiming coverage beyond what's
// actually there would be worse than just not scanning those hosts yet.
func ecosystemForPlatform(platform string) (string, bool) {
	switch strings.ToLower(platform) {
	case "ubuntu":
		return "Ubuntu", true
	case "debian":
		return "Debian", true
	case "alpine":
		return "Alpine", true
	default:
		return "", false
	}
}

// kernelBuildOnly reports a package built from the kernel's source that is
// not a kernel: headers, linux-libc-dev, bpftool and the like. The kernel
// source carries some ten thousand advisories (Debian's linux, 2026-10),
// all about the running kernel; attributing them to every host that has
// the kernel headers installed for building software would bury every
// real finding. The kernel image itself (linux-image-*, Alpine's linux-lts
// and siblings) is still scanned.
func kernelBuildOnly(app proto.InstalledApp) bool {
	switch src := app.Source; {
	case src == "linux" || strings.HasPrefix(src, "linux-signed"):
		return !strings.HasPrefix(app.Name, "linux-image-")
	case src == "linux-lts" || src == "linux-virt" || src == "linux-edge" || src == "linux-stable" || strings.HasPrefix(src, "linux-rpi"):
		return app.Name != src
	}
	return false
}

// osvEcosystem is the ecosystem a host's packages are queried under, with
// the host's release where OSV files advisories per release:
//   - Alpine, "Alpine:v3.22": a bare "Alpine" matches nothing at all.
//   - Ubuntu, "Ubuntu:25.10": a bare "Ubuntu" matches a package against
//     every release's ranges, so an advisory fixed in this release but
//     open in another still counted (ansible, 25.10: 763 advisories by
//     "Ubuntu", 460 by its own release).
//
// Debian's findings are already checked per release against Debian's own
// tracker.
func osvEcosystem(ecosystem, platformVersion string) string {
	parts := strings.SplitN(strings.TrimSpace(platformVersion), ".", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ecosystem
	}
	switch ecosystem {
	case "Alpine":
		return "Alpine:v" + parts[0] + "." + parts[1]
	case "Ubuntu":
		return "Ubuntu:" + parts[0] + "." + parts[1]
	}
	return ecosystem
}

func isUbuntu(ecosystem string) bool {
	return ecosystem == "Ubuntu" || strings.HasPrefix(ecosystem, "Ubuntu:")
}

// ubuntuSeverity is the severity an Ubuntu host's finding is graded by:
// Ubuntu's own priority, which weighs how the flaw bears on Ubuntu as
// shipped, rather than CVSS, which rates it in the abstract (ansible on
// 26.04: CVSS made it critical, while Ubuntu rated one advisory of 697
// high and none critical). Negligible grades as low; it is also set
// aside as not actionable, as Debian's verdicts are for Debian hosts.
// false when Ubuntu gave no priority, so CVSS stands.
func ubuntuSeverity(priority *string) (string, bool) {
	if priority == nil {
		return "", false
	}
	switch *priority {
	case "critical", "high", "medium", "low":
		return *priority, true
	case "negligible":
		return "low", true
	}
	return "", false
}

type pkgKey struct{ ecosystem, name, version string }

// scanSource is the package and version a vulnerability scan looks an
// installed package up by: its source package when the agent reported one
// (advisories are filed by source package: libssl3t64's are openssl's),
// else the package itself, as agents before Source was reported send.
func scanSource(app proto.InstalledApp) (string, string) {
	if app.Source != "" && app.SourceVersion != "" {
		return app.Source, app.SourceVersion
	}
	return app.Name, app.Version
}

// debsecRefreshLoop keeps the Debian security tracker index current. Daily
// is the right cadence: Debian updates it continuously but a finding's
// status rarely flips within a day, and the payload is ~70 MB.
func (s *Server) debsecRefreshLoop(ctx context.Context) {
	refresh := func() {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if err := s.debsec.Refresh(rctx, nil); err != nil {
			s.logger.Warn("refreshing the Debian security tracker failed", "error", err)
			return
		}
		s.logger.Info("Debian security tracker refreshed", "packages", s.debsec.Len())
	}
	refresh()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

// runVulnScan cross-references every agent's cached installed_apps sensor
// snapshot against OSV.dev and stores the results — the Risk & Compliance
// feature's actual data source. See internal/server/osv's doc comment and
// docs/ARCHITECTURE.md's Risk section for the overall design and its
// tradeoffs. Fleet-wide package+version pairs are deduplicated before
// querying OSV, so a library shared across every host only costs one
// lookup, not one per host.
func (s *Server) runVulnScan(ctx context.Context) error {
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorInstalledApps))
	if err != nil {
		return fmt.Errorf("list installed_apps sensor data: %w", err)
	}

	type agentPkgs struct {
		agentID string
		// The Debian release this host runs, so a finding can be checked
		// against what Debian says for *that* release rather than in
		// general. Empty for non-Debian hosts and for releases the
		// tracker doesn't cover.
		debRelease string
	}
	var scannable []agentPkgs
	// Advisories are filed by source package, so OSV is asked once per
	// source package and version; each finding is then recorded against
	// every installed package built from it, by the name the package
	// manager uses, which is what a remediation patches.
	type owner struct{ agentID, name, version string }
	pkgOwners := map[pkgKey][]owner{} // source package -> installed packages built from it
	seenKey := map[pkgKey]bool{}
	var uniqueQueries []osv.PackageQuery

	for _, row := range rows {
		ecosystem, ok := ecosystemForPlatform(row.Platform)
		if !ok {
			continue
		}
		ecosystem = osvEcosystem(ecosystem, row.PlatformVersion)
		var apps []proto.InstalledApp
		if err := json.Unmarshal(row.Data, &apps); err != nil {
			s.logger.Warn("skipping unparsable installed_apps row for vuln scan", "agent_id", row.AgentID, "error", err)
			continue
		}
		release := ""
		if strings.EqualFold(row.Platform, "debian") || strings.EqualFold(row.Platform, "raspbian") {
			release = debsec.ReleaseForVersion(row.PlatformVersion)
		}
		scannable = append(scannable, agentPkgs{agentID: row.AgentID, debRelease: release})
		for _, app := range apps {
			if app.Name == "" || app.Version == "" {
				continue
			}
			if kernelBuildOnly(app) {
				continue
			}
			src, srcVersion := scanSource(app)
			k := pkgKey{ecosystem: ecosystem, name: src, version: srcVersion}
			pkgOwners[k] = append(pkgOwners[k], owner{agentID: row.AgentID, name: app.Name, version: app.Version})
			if !seenKey[k] {
				seenKey[k] = true
				uniqueQueries = append(uniqueQueries, osv.PackageQuery{Ecosystem: ecosystem, Name: src, Version: srcVersion})
			}
		}
	}

	if len(scannable) == 0 {
		s.logger.Info("vuln scan: no agents with usable installed_apps data yet (needs a Debian/Ubuntu/Alpine host that's published the installed_apps sensor)")
		return nil
	}

	s.logger.Info("vuln scan starting", "agents", len(scannable), "unique_packages", len(uniqueQueries))

	matchResults, err := osv.QueryBatch(ctx, uniqueQueries)
	if err != nil {
		return fmt.Errorf("osv querybatch: %w", err)
	}

	// pkgName and pkgVersion are the installed package; srcName and
	// srcVersion the source package Debian's tracker is keyed by.
	type match struct{ pkgName, pkgVersion, srcName, srcVersion, vulnID, ecosystem string }
	agentMatches := map[string][]match{}
	allVulnIDs := map[string]bool{}
	ubuntuIDs := map[string]bool{} // found on an Ubuntu host, so graded by Ubuntu's priority
	for i, q := range uniqueQueries {
		ids := matchResults[i]
		if len(ids) == 0 {
			continue
		}
		k := pkgKey{ecosystem: q.Ecosystem, name: q.Name, version: q.Version}
		for _, o := range pkgOwners[k] {
			for _, vulnID := range ids {
				agentMatches[o.agentID] = append(agentMatches[o.agentID], match{pkgName: o.name, pkgVersion: o.version,
					srcName: q.Name, srcVersion: q.Version, vulnID: vulnID, ecosystem: q.Ecosystem})
				allVulnIDs[vulnID] = true
				if isUbuntu(q.Ecosystem) {
					ubuntuIDs[vulnID] = true
				}
			}
		}
	}

	idList := make([]string, 0, len(allVulnIDs))
	for id := range allVulnIDs {
		idList = append(idList, id)
	}
	cached, err := s.store.GetCachedVulnDetails(ctx, idList)
	if err != nil {
		return fmt.Errorf("get cached vuln details: %w", err)
	}
	var missing []string
	for _, id := range idList {
		// A detail cached before Ubuntu's priority was recorded is fetched
		// again when an Ubuntu host needs it, and one with no summary (a
		// Debian record cached before the summary fell back to its
		// details) is fetched again to fill it in.
		if d, ok := cached[id]; !ok || (ubuntuIDs[id] && d.UbuntuPriority == nil) || d.Summary == "" {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		s.logger.Info("vuln scan: fetching details for newly-seen vulnerabilities", "count", len(missing))
		fetched := s.fetchVulnDetails(ctx, missing)
		if err := s.store.UpsertVulnDetails(ctx, fetched); err != nil {
			s.logger.Warn("upsert vuln details failed", "error", err)
		}
		for _, d := range fetched {
			cached[d.VulnID] = d
		}
	}

	// Replace every scanned agent's vulnerability set, including agents
	// with zero current matches — that's what actually clears a fixed
	// vulnerability instead of it lingering from a stale scan.
	suppressed := 0
	for _, ap := range scannable {
		matches := agentMatches[ap.agentID]
		vulnRows := make([]store.AgentVulnerability, 0, len(matches))
		for _, m := range matches {
			// Debian backports security fixes without changing the
			// upstream version, so OSV keeps matching CVEs that this host
			// already has the fix for. Ask Debian about each finding and
			// record its own judgement — a finding Debian says is fixed
			// here, or explicitly declined to issue an advisory for, is
			// noise that would otherwise bury the ones that matter.
			var verdict debsec.Verdict
			if ap.debRelease != "" {
				for _, cve := range cached[m.vulnID].CVEIDs {
					v := s.debsec.Lookup(m.srcName, debsec.NormalizeCVE(cve), ap.debRelease, m.srcVersion)
					if v.Known {
						verdict = v
						break
					}
				}
				// OSV reports Debian findings as DEBIAN-CVE-…; the tracker
				// keys them bare, so the ID needs normalizing before it
				// will ever match.
				if !verdict.Known {
					verdict = s.debsec.Lookup(m.srcName, debsec.NormalizeCVE(m.vulnID), ap.debRelease, m.srcVersion)
				}
			}
			row := store.AgentVulnerability{
				AgentID: ap.agentID, PackageName: m.pkgName, PackageVersion: m.pkgVersion,
				VulnID: m.vulnID, Severity: cached[m.vulnID].Severity,
			}
			if verdict.Known && !verdict.Actionable() {
				row.Suppressed = true
				row.SuppressedReason = verdict.Suppressed()
				suppressed++
			}
			if isUbuntu(m.ecosystem) {
				if sev, ok := ubuntuSeverity(cached[m.vulnID].UbuntuPriority); ok {
					row.Severity = sev
				}
				if p := cached[m.vulnID].UbuntuPriority; p != nil && *p == "negligible" {
					row.Suppressed = true
					row.SuppressedReason = "Ubuntu: negligible priority"
					suppressed++
				}
			}
			vulnRows = append(vulnRows, row)
		}
		if err := s.store.ReplaceAgentVulnerabilities(ctx, ap.agentID, vulnRows); err != nil {
			s.logger.Warn("replace agent vulnerabilities failed", "agent_id", ap.agentID, "error", err)
		}
		// The scan itself is a fact worth keeping: a host with no rows is
		// either clean or never looked at, and the level view must tell
		// those apart.
		// Counted by vulnerability, not by row: one openssl advisory is one
		// finding on this host, however many of its packages are installed.
		st := store.VulnScanStatus{AgentID: ap.agentID}
		rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
		found, actionable := map[string]bool{}, map[string]bool{}
		for _, vr := range vulnRows {
			found[vr.VulnID] = true
			if vr.Suppressed {
				continue
			}
			actionable[vr.VulnID] = true
			if rank[vr.Severity] > rank[st.WorstSeverity] {
				st.WorstSeverity = vr.Severity
			}
		}
		st.Findings, st.Actionable = len(found), len(actionable)
		if err := s.store.RecordVulnScanStatus(ctx, st); err != nil {
			s.logger.Warn("record vuln scan status failed", "agent_id", ap.agentID, "error", err)
		}
	}

	if err := s.store.SetLastVulnScan(ctx, time.Now()); err != nil {
		s.logger.Warn("set last vuln scan time failed", "error", err)
	}
	s.logger.Info("vuln scan complete", "agents_scanned", len(scannable),
		"unique_vulnerabilities", len(allVulnIDs), "suppressed_by_distribution", suppressed,
		"debian_index_packages", s.debsec.Len())
	if err := s.announceNewVulnerabilities(ctx); err != nil {
		s.logger.Warn("could not announce new vulnerabilities", "error", err)
	}
	return nil
}

// fetchVulnDetails fetches OSV details for each ID with bounded
// concurrency (a large fleet's first scan can turn up a few hundred
// distinct vulnerabilities across all its packages).
func (s *Server) fetchVulnDetails(ctx context.Context, ids []string) []store.VulnDetail {
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	var out []store.VulnDetail
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d, err := osv.GetDetails(ctx, id)
			if err != nil {
				s.logger.Warn("fetch osv vuln details failed", "vuln_id", id, "error", err)
				return
			}
			mu.Lock()
			priority := d.UbuntuPriority
			out = append(out, store.VulnDetail{VulnID: d.ID, Severity: d.Severity, CVSSScore: d.CVSSScore, Summary: d.Summary,
				CVEIDs: d.CVEIDs, FixedVersions: d.FixedVersions, UbuntuPriority: &priority})
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

// vulnScanLoop runs the vulnerability scan on startup and every 6 hours
// after — OS package vulnerability data doesn't change fast enough to
// need anything more frequent, and OSV is a shared public service not
// worth hammering. handleRiskScanNow (risk_api.go) covers "I just want an
// answer right now" instead of waiting for the next tick.
func (s *Server) vulnScanLoop(ctx context.Context) {
	if err := s.runVulnScan(ctx); err != nil {
		s.logger.Warn("initial vuln scan failed", "error", err)
	}
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.runVulnScan(ctx); err != nil {
				s.logger.Warn("vuln scan failed", "error", err)
			}
		case <-s.vulnKick:
			// A remediation just changed some endpoint's software. Wait for
			// the rest of the run to report, so a deployment to twenty
			// endpoints costs one scan, not twenty.
			select {
			case <-ctx.Done():
				return
			case <-time.After(vulnRescanSettle):
			}
			select {
			case <-s.vulnKick:
			default:
			}
			if err := s.runVulnScan(ctx); err != nil {
				s.logger.Warn("vuln scan after remediation failed", "error", err)
			} else {
				s.logger.Info("vuln scan after remediation finished")
			}
		}
	}
}
