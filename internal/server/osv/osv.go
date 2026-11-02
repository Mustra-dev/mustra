// Package osv is a small client for osv.dev — a free, public, keyless
// vulnerability database (aggregates GitHub Security Advisories, the
// Debian/Ubuntu/Alpine security trackers, PyPI/npm/Go advisories, etc.)
// used to give mustra's Risk & Compliance feature real CVE data instead of
// a fabricated score. See docs/ARCHITECTURE.md's Risk section for why OSV
// specifically, and the tradeoff against each distro's own tracker.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// batchChunkSize is small because a query's cost is its result count: a
// source package with thousands of advisories (Debian's linux, chromium)
// takes OSV five to seven seconds alone, and 500 queries holding a few of
// them ran past any sensible timeout (2026-10-28).
const batchChunkSize = 100

// maxPages bounds how far one query's results are followed: OSV returns
// at most 1000 advisories a page.
const maxPages = 20

// baseURL is a variable so tests can point it at a fake OSV.
var baseURL = "https://api.osv.dev/v1"

var httpClient = &http.Client{Timeout: 2 * time.Minute}

// PackageQuery identifies one package+version to check, in OSV's ecosystem
// vocabulary (e.g. "Debian", "Ubuntu", "Alpine" for OS packages).
type PackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

type querybatchRequest struct {
	Queries []batchQuery `json:"queries"`
}
type batchQuery struct {
	Version   string       `json:"version,omitempty"`
	Package   batchPackage `json:"package"`
	PageToken string       `json:"page_token,omitempty"`
}
type batchPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type querybatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// QueryBatch checks every package+version against OSV and returns, for
// each input query (same order), the list of matching vulnerability IDs.
// It chunks the queries, and follows a query's next_page_token while OSV
// says more results remain: a source package such as Debian's linux or
// chromium has more than the 1000 advisories one page holds.
func QueryBatch(ctx context.Context, queries []PackageQuery) ([][]string, error) {
	results := make([][]string, len(queries))
	for start := 0; start < len(queries); start += batchChunkSize {
		end := min(start+batchChunkSize, len(queries))
		// pending maps a position in this request to the query's index.
		pending := make([]int, 0, end-start)
		tokens := map[int]string{}
		for i := start; i < end; i++ {
			pending = append(pending, i)
		}
		for page := 0; len(pending) > 0; page++ {
			if page >= maxPages {
				return nil, fmt.Errorf("osv querybatch: still paging after %d pages", maxPages)
			}
			req := querybatchRequest{Queries: make([]batchQuery, len(pending))}
			for j, i := range pending {
				q := queries[i]
				req.Queries[j] = batchQuery{Version: q.Version, Package: batchPackage{Name: q.Name, Ecosystem: q.Ecosystem}, PageToken: tokens[i]}
			}
			parsed, err := postQueryBatch(ctx, req)
			if err != nil {
				return nil, err
			}
			if len(parsed.Results) != len(pending) {
				return nil, fmt.Errorf("osv querybatch: %d results for %d queries", len(parsed.Results), len(pending))
			}
			var next []int
			for j, r := range parsed.Results {
				i := pending[j]
				for _, v := range r.Vulns {
					results[i] = append(results[i], v.ID)
				}
				if r.NextPageToken != "" {
					tokens[i] = r.NextPageToken
					next = append(next, i)
				}
			}
			pending = next
		}
		for i := start; i < end; i++ {
			if results[i] == nil {
				results[i] = []string{}
			}
		}
	}
	return results, nil
}

func postQueryBatch(ctx context.Context, req querybatchRequest) (querybatchResponse, error) {
	var parsed querybatchResponse
	body, err := json.Marshal(req)
	if err != nil {
		return parsed, fmt.Errorf("marshal osv querybatch request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/querybatch", bytes.NewReader(body))
	if err != nil {
		return parsed, fmt.Errorf("build osv querybatch request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return parsed, fmt.Errorf("osv querybatch request: %w", err)
	}
	decErr := json.NewDecoder(resp.Body).Decode(&parsed)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return parsed, fmt.Errorf("osv querybatch returned %s", resp.Status)
	}
	if decErr != nil {
		return parsed, fmt.Errorf("decode osv querybatch response: %w", decErr)
	}
	return parsed, nil
}

// Detail is OSV's full record for one vulnerability, reduced to what
// mustra actually shows — a severity bucket derived from CVSS (or the
// ecosystem's own severity string when no CVSS vector is published), a
// summary, any CVE aliases (an OSV ID is often a GHSA-... with the CVE, if
// any, listed as an alias), and the fixed version(s) the advisory names —
// the Risk page's remediation text is built directly from this rather than
// a fabricated "update your packages" generic.
type Detail struct {
	ID        string
	Severity  string // "critical" | "high" | "medium" | "low" | ""
	CVSSScore *float64
	Summary   string
	CVEIDs    []string
	// FixedVersions maps package name -> the first "fixed" version OSV's
	// affected-ranges data names for it. A single advisory can affect
	// several packages/ecosystems with different fixed versions each
	// (e.g. the same CVE across Debian and Ubuntu), so this is keyed by
	// package name rather than being one flat string.
	FixedVersions map[string]string
	// UbuntuPriority is Ubuntu's own priority for the advisory
	// ("negligible", "low", "medium", "high" or "critical"), from an
	// UBUNTU-CVE record's severity of type "Ubuntu"; "" otherwise.
	UbuntuPriority string
}

type osvVulnResponse struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

// GetDetails fetches and reduces one vulnerability's full OSV record.
func GetDetails(ctx context.Context, id string) (*Detail, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/vulns/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("build osv vuln detail request: %w", err)
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("osv vuln detail request for %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv vuln detail for %s returned %s", id, resp.Status)
	}
	var v osvVulnResponse
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("decode osv vuln detail for %s: %w", id, err)
	}

	d := &Detail{ID: id, Summary: summaryOf(v.Summary, v.Details)}
	for _, sev := range v.Severity {
		if sev.Type == "Ubuntu" {
			d.UbuntuPriority = strings.ToLower(strings.TrimSpace(sev.Score))
		}
	}

	// Severity: prefer a real CVSS v3/v3.1 base score computed from the
	// vector string (most CVEs carry one); fall back to whatever severity
	// string the ecosystem's own advisory data provides (GHSA/Debian/
	// Ubuntu entries commonly set database_specific.severity directly
	// instead of, or in addition to, a CVSS vector).
	for _, sev := range v.Severity {
		if strings.HasPrefix(sev.Type, "CVSS_V3") {
			if score, ok := cvssV3BaseScore(sev.Score); ok {
				d.CVSSScore = &score
				d.Severity = severityBucket(score)
				break
			}
		}
	}
	if d.Severity == "" {
		if s := normalizeSeverityString(v.DatabaseSpecific.Severity); s != "" {
			d.Severity = s
		} else {
			for _, aff := range v.Affected {
				if s := normalizeSeverityString(aff.DatabaseSpecific.Severity); s != "" {
					d.Severity = s
					break
				}
			}
		}
	}

	seen := map[string]bool{}
	if cveIDPattern.MatchString(id) {
		d.CVEIDs = append(d.CVEIDs, id)
		seen[id] = true
	}
	for _, alias := range v.Aliases {
		if cveIDPattern.MatchString(alias) && !seen[alias] {
			d.CVEIDs = append(d.CVEIDs, alias)
			seen[alias] = true
		}
	}

	for _, aff := range v.Affected {
		if aff.Package.Name == "" {
			continue
		}
		if _, already := d.FixedVersions[aff.Package.Name]; already {
			continue
		}
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed == "" {
					continue
				}
				if d.FixedVersions == nil {
					d.FixedVersions = map[string]string{}
				}
				d.FixedVersions[aff.Package.Name] = ev.Fixed
				break
			}
			if d.FixedVersions[aff.Package.Name] != "" {
				break
			}
		}
	}
	return d, nil
}

func normalizeSeverityString(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM", "MODERATE":
		return "medium"
	case "LOW":
		return "low"
	default:
		return ""
	}
}

// severityBucket maps a CVSS v3 base score (0-10) to the same five-bucket
// scale NVD/most vendors use.
func severityBucket(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

// cvssV3BaseScore computes the CVSS v3.0/3.1 base score from a vector
// string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), per the
// published formula (first.org CVSS v3.1 spec section 7.3). Implemented
// directly rather than pulled in as a dependency — it's a fixed, small
// formula over 8 enumerated metrics, not something that needs a library.
func cvssV3BaseScore(vector string) (float64, bool) {
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	c, ok4 := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[metrics["C"]]
	i, ok5 := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[metrics["I"]]
	a, ok6 := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[metrics["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return 0, false
	}

	scopeChanged := metrics["S"] == "C"
	var pr float64
	var okPR bool
	if scopeChanged {
		pr, okPR = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
	} else {
		pr, okPR = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
	}
	if !okPR {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scopeChanged {
		base = roundUpToTenth(math.Min(1.08*(impact+exploitability), 10))
	} else {
		base = roundUpToTenth(math.Min(impact+exploitability, 10))
	}
	return base, true
}

// roundUpToTenth implements CVSS's specified "Roundup" function: round to
// one decimal place, always up, avoiding ordinary floating-point rounding
// error (this exact integer-scaled approach is what the CVSS spec itself
// prescribes).
func roundUpToTenth(x float64) float64 {
	intInput := int(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000
	}
	return float64(intInput/10000+1) / 10
}

// summaryOf is the record's summary, or, when it has none, the first
// sentence of its details. Debian's records (DEBIAN-CVE-*) carry only
// details, which left their Summary column empty.
func summaryOf(summary, details string) string {
	if s := strings.TrimSpace(summary); s != "" {
		return s
	}
	d := strings.Join(strings.Fields(details), " ")
	if i := strings.Index(d, ". "); i >= 0 {
		d = d[:i+1]
	}
	const max = 200
	if r := []rune(d); len(r) > max {
		d = strings.TrimSpace(string(r[:max-1])) + "…"
	}
	return d
}
