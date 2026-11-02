package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AgentVulnerability is one (agent, package, known vulnerability) match —
// see schema.sql's agent_vulnerabilities table.
type AgentVulnerability struct {
	AgentID        string
	PackageName    string
	PackageVersion string
	VulnID         string
	Severity       string
	// Suppressed marks a finding that the distribution's own security
	// team says needs no action here — already fixed by a backport, or
	// explicitly declined an advisory. Kept rather than dropped so the
	// record is complete and the judgement is auditable, but excluded from
	// counts and hidden by default.
	Suppressed       bool
	SuppressedReason string
	CheckedAt        time.Time
}

// ReplaceAgentVulnerabilities overwrites the full vulnerability set for one
// agent — a fixed package's row just stops being written on the next scan,
// rather than needing an explicit "resolved" flag.
func (s *Store) ReplaceAgentVulnerabilities(ctx context.Context, agentID string, rows []AgentVulnerability) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace agent vulnerabilities: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM agent_vulnerabilities WHERE agent_id = $1`, agentID); err != nil {
		return fmt.Errorf("clear agent vulnerabilities: %w", err)
	}
	for _, r := range rows {
		const q = `
INSERT INTO agent_vulnerabilities (agent_id, package_name, package_version, vuln_id, severity, suppressed, suppressed_reason, checked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (agent_id, package_name, vuln_id) DO NOTHING`
		if _, err := tx.Exec(ctx, q, agentID, r.PackageName, r.PackageVersion, r.VulnID, r.Severity, r.Suppressed, r.SuppressedReason); err != nil {
			return fmt.Errorf("insert agent vulnerability: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit replace agent vulnerabilities: %w", err)
	}
	return nil
}

// AgentVulnRow is one vulnerability match joined with enough inventory
// context to render the Risk page and the home dashboard's mini charts
// without a second round trip.
type AgentVulnRow struct {
	AgentID        string
	Hostname       string
	OS             string
	Site           string
	PackageName    string
	PackageVersion string
	VulnID         string
	Severity       string
	Summary        string
	CVEIDs         []string
	FixedVersion   string // this package's fixed version per the advisory, if OSV published one
	// Suppressed carries the distribution's own judgement: this finding
	// needs no action on this host. Excluded from counts, kept for audit.
	Suppressed       bool
	SuppressedReason string
	CheckedAt        time.Time
}

// ListAllAgentVulnerabilities returns every current vulnerability match
// across the fleet, joined with agent and vuln-detail context.
func (s *Store) ListAllAgentVulnerabilities(ctx context.Context) ([]AgentVulnRow, error) {
	const q = `
SELECT v.agent_id, a.hostname, a.os, a.site, v.package_name, v.package_version, v.vuln_id, v.severity,
       coalesce(d.summary, ''), coalesce(d.cve_ids, '{}'), coalesce(d.fixed_versions ->> v.package_name, ''),
       v.suppressed, v.suppressed_reason, v.checked_at
FROM agent_vulnerabilities v
JOIN agents a ON a.agent_id = v.agent_id
LEFT JOIN vuln_details_cache d ON d.vuln_id = v.vuln_id
ORDER BY a.hostname, v.severity`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list all agent vulnerabilities: %w", err)
	}
	defer rows.Close()
	var out []AgentVulnRow
	for rows.Next() {
		var r AgentVulnRow
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.OS, &r.Site, &r.PackageName, &r.PackageVersion,
			&r.VulnID, &r.Severity, &r.Summary, &r.CVEIDs, &r.FixedVersion,
			&r.Suppressed, &r.SuppressedReason, &r.CheckedAt); err != nil {
			return nil, fmt.Errorf("scan agent vuln row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListAgentIDsAffectedByVuln returns every agent currently carrying a given
// vuln_id — used both by the Risk page's per-CVE detail (affected-endpoints
// list) and by resolvePatchTargets when a patch deploy/schedule targets a
// CVE directly rather than an OS/site/device.
func (s *Store) ListAgentIDsAffectedByVuln(ctx context.Context, vulnID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT agent_id FROM agent_vulnerabilities WHERE vuln_id = $1`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("list agents affected by vuln: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan affected agent id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// VulnDetail is OSV's full record for one vulnerability ID, cached locally
// so re-scanning doesn't refetch details for a vuln already looked up.
type VulnDetail struct {
	VulnID        string
	Severity      string
	CVSSScore     *float64
	Summary       string
	CVEIDs        []string
	FixedVersions map[string]string // package name -> fixed version
	// UbuntuPriority is Ubuntu's priority for the advisory ("" when it has
	// none); nil for a detail cached before it was recorded.
	UbuntuPriority *string
}

// GetCachedVulnDetails returns whichever of the given IDs are already
// cached — callers fetch the rest from OSV and store them with
// UpsertVulnDetails.
func (s *Store) GetCachedVulnDetails(ctx context.Context, ids []string) (map[string]VulnDetail, error) {
	out := map[string]VulnDetail{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT vuln_id, severity, cvss_score, summary, cve_ids, fixed_versions, ubuntu_priority FROM vuln_details_cache WHERE vuln_id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("get cached vuln details: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d VulnDetail
		var fixedRaw []byte
		if err := rows.Scan(&d.VulnID, &d.Severity, &d.CVSSScore, &d.Summary, &d.CVEIDs, &fixedRaw, &d.UbuntuPriority); err != nil {
			return nil, fmt.Errorf("scan vuln detail: %w", err)
		}
		if len(fixedRaw) > 0 {
			_ = json.Unmarshal(fixedRaw, &d.FixedVersions)
		}
		out[d.VulnID] = d
	}
	return out, rows.Err()
}

// UpsertVulnDetails stores freshly-fetched OSV vulnerability details.
func (s *Store) UpsertVulnDetails(ctx context.Context, details []VulnDetail) error {
	if len(details) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin upsert vuln details: %w", err)
	}
	defer tx.Rollback(ctx)
	const q = `
INSERT INTO vuln_details_cache (vuln_id, severity, cvss_score, summary, cve_ids, fixed_versions, ubuntu_priority, fetched_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (vuln_id) DO UPDATE SET severity = EXCLUDED.severity, cvss_score = EXCLUDED.cvss_score,
    summary = EXCLUDED.summary, cve_ids = EXCLUDED.cve_ids, fixed_versions = EXCLUDED.fixed_versions,
    ubuntu_priority = EXCLUDED.ubuntu_priority, fetched_at = now()`
	for _, d := range details {
		fixed := d.FixedVersions
		if fixed == nil {
			fixed = map[string]string{}
		}
		// A nil slice reaches Postgres as NULL, not as an empty array, and
		// the column is NOT NULL. Plenty of OSV records carry no CVE alias
		// (a GHSA that never got one), and because this is a single
		// transaction, one such record used to discard the entire batch.
		cves := d.CVEIDs
		if cves == nil {
			cves = []string{}
		}
		fixedRaw, err := json.Marshal(fixed)
		if err != nil {
			return fmt.Errorf("marshal fixed versions for %s: %w", d.VulnID, err)
		}
		if _, err := tx.Exec(ctx, q, d.VulnID, d.Severity, d.CVSSScore, d.Summary, cves, fixedRaw, d.UbuntuPriority); err != nil {
			return fmt.Errorf("upsert vuln detail: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// VulnScanState tracks when the fleet-wide vulnerability scan last ran, for
// the Risk page's "last checked" display and to avoid overlapping runs.
func (s *Store) SetLastVulnScan(ctx context.Context, at time.Time) error {
	return s.SetSetting(ctx, "vuln.last_scan_at", at.UTC().Format(time.RFC3339), "vuln-scanner")
}

func (s *Store) GetLastVulnScan(ctx context.Context) (*time.Time, error) {
	all, err := s.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}
	v, ok := all["vuln.last_scan_at"]
	if !ok || v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, nil
	}
	return &t, nil
}
