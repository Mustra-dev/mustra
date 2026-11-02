package server

import (
	"context"
	"net/http"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// This file backs the Risk & Compliance page and the home dashboard's
// "Risk and Compliance" group — a real vulnerability count/severity
// breakdown built from OSV.dev matches (see vulnscan.go), never a
// synthesized score.

type riskVulnRow struct {
	AgentID        string   `json:"agent_id"`
	Hostname       string   `json:"hostname"`
	OS             string   `json:"os"`
	Site           string   `json:"site"`
	PackageName    string   `json:"package_name"`
	PackageVersion string   `json:"package_version"`
	VulnID         string   `json:"vuln_id"`
	Severity       string   `json:"severity"`
	Summary        string   `json:"summary"`
	CVEIDs         []string `json:"cve_ids"`
	FixedVersion   string   `json:"fixed_version,omitempty"`
	CheckedAt      string   `json:"checked_at"`
	KEV            bool     `json:"kev,omitempty"`
	Ransomware     bool     `json:"ransomware,omitempty"`
	EPSS           float64  `json:"epss,omitempty"`
}

type riskAgentSummary struct {
	AgentID       string `json:"agent_id"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Site          string `json:"site"`
	VulnCount     int    `json:"vuln_count"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
}

type riskSummaryResponse struct {
	LastScanAt      *string            `json:"last_scan_at"`
	SeverityCounts  map[string]int     `json:"severity_counts"` // critical/high/medium/low/unknown
	Vulnerabilities []riskVulnRow      `json:"vulnerabilities"`
	Agents          []riskAgentSummary `json:"agents"`
	// Suppressed says how many findings the distribution's own security
	// team accounts for — surfaced rather than silently dropped, so the
	// number is visible and the filtering is auditable rather than the
	// list just mysteriously shrinking.
	Suppressed int `json:"suppressed"`
}

func (s *Server) handleRiskSummary(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListAllAgentVulnerabilities(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	intel := s.intelForRows(r.Context(), rows)
	severityCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
	agentSummaries := map[string]*riskAgentSummary{}
	var agentOrder []string
	vulnRows := make([]riskVulnRow, 0, len(rows))

	suppressedCount := 0
	for _, row := range rows {
		// Suppressed findings stay in the database for audit but never
		// reach the page's counts: showing several hundred CVEs a
		// distribution has already fixed is how a vulnerability list stops
		// being read at all.
		if row.Suppressed {
			suppressedCount++
			continue
		}
		sev := row.Severity
		if sev == "" {
			sev = "unknown"
		}
		severityCounts[sev]++

		as, ok := agentSummaries[row.AgentID]
		if !ok {
			as = &riskAgentSummary{AgentID: row.AgentID, Hostname: row.Hostname, OS: row.OS, Site: row.Site}
			agentSummaries[row.AgentID] = as
			agentOrder = append(agentOrder, row.AgentID)
		}
		as.VulnCount++
		if sev == "critical" {
			as.CriticalCount++
		} else if sev == "high" {
			as.HighCount++
		}

		vulnRows = append(vulnRows, riskVulnRow{
			AgentID: row.AgentID, Hostname: row.Hostname, OS: row.OS, Site: row.Site,
			PackageName: row.PackageName, PackageVersion: row.PackageVersion,
			VulnID: row.VulnID, Severity: sev, Summary: row.Summary, CVEIDs: nonNil(row.CVEIDs),
			FixedVersion: row.FixedVersion,
			CheckedAt:    row.CheckedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
		if x, ok := vulnIntel(row, intel); ok {
			last := &vulnRows[len(vulnRows)-1]
			last.KEV, last.Ransomware, last.EPSS = x.KEV, x.Ransomware, x.EPSS
		}
	}

	agents := make([]riskAgentSummary, 0, len(agentOrder))
	for _, id := range agentOrder {
		agents = append(agents, *agentSummaries[id])
	}

	var lastScan *string
	if t, err := s.store.GetLastVulnScan(r.Context()); err == nil && t != nil {
		f := t.UTC().Format("2006-01-02T15:04:05.000Z")
		lastScan = &f
	}

	writeJSONResponse(w, riskSummaryResponse{
		LastScanAt: lastScan, SeverityCounts: severityCounts, Vulnerabilities: vulnRows,
		Agents: agents, Suppressed: suppressedCount,
	})
}

// riskScanNowResponse is what POST /api/risk/scan answers.
type riskScanNowResponse struct {
	OK bool `json:"ok"`
}

// handleRiskScanNow triggers an immediate fleet-wide vulnerability scan
// instead of waiting for the next 6-hour tick — runs synchronously and can
// take a little while on a large fleet's first scan (fetching details for
// every newly-seen vulnerability), same tradeoff as the Patches tab's
// "Deploy now".
func (s *Server) handleRiskScanNow(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r.Context())
	s.logger.Info("risk scan requested", "requested_by", u.Username)

	// Detached from the request: following every page of a source package
	// such as Debian's linux can outlast a proxy's wait (Cloudflare gives
	// up at about 100 seconds), and a scan cancelled with the request
	// would be lost. It finishes either way; the page shows it next load.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Minute)
	defer cancel()
	if err := s.runVulnScan(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, riskScanNowResponse{OK: true})
}
