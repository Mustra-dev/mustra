// Package debsec consults Debian's security tracker to decide which OSV
// findings actually warrant action on a Debian host.
//
// The problem it solves: OSV matches CVEs against *source package and
// upstream version*, but Debian fixes security bugs by backporting patches
// without changing the upstream version — curl 7.88.1-10+deb12u8 carries
// fixes that OSV still attributes to "curl 7.88.1". Matching naively
// therefore reports every historical CVE for a package's upstream version
// as though it were live. On a real 34-host fleet that produced a median
// of 331 findings and 134 "severe" per host, which is not a work queue,
// it is wallpaper.
//
// Debian publishes its own judgement for every (package, CVE, release):
// whether it is resolved and in which version, and whether it warrants an
// advisory at all. Applying that turns the list back into something
// actionable.
package debsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const trackerURL = "https://security-tracker.debian.org/tracker/data/json"

// Verdict is what Debian says about one CVE in one package on one release.
type Verdict struct {
	Known        bool
	Fixed        bool // resolved, and the installed version has the fix
	FixedVersion string
	NoAdvisory   bool   // Debian decided this doesn't warrant a DSA
	Reason       string // Debian's own words, where it gave them
	Urgency      string
}

// Actionable reports whether a finding should still be shown as a live
// vulnerability. Anything Debian has not spoken about stays actionable —
// silence is not a clearance.
func (v Verdict) Actionable() bool {
	if !v.Known {
		return true
	}
	return !v.Fixed && !v.NoAdvisory
}

// Suppressed explains, in one phrase, why a finding was set aside.
func (v Verdict) Suppressed() string {
	switch {
	case v.Fixed:
		return "fixed in " + v.FixedVersion + " (Debian backport)"
	case v.NoAdvisory && v.Reason != "":
		return "Debian: no advisory — " + v.Reason
	case v.NoAdvisory:
		return "Debian: no advisory needed"
	case v.Urgency == "unimportant":
		return "Debian: unimportant"
	}
	return ""
}

type releaseEntry struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
	NoDSA        string `json:"nodsa"`
	NoDSAReason  string `json:"nodsa_reason"`
}

// Index holds the tracker data for the packages a fleet actually has.
// Filtering on ingest matters: the full dump is ~70 MB and 3,991 source
// packages, and holding all of it to answer questions about a few thousand
// would be wasteful for no benefit.
type Index struct {
	mu        sync.RWMutex
	entries   map[string]map[string]map[string]releaseEntry // pkg -> cve -> release -> entry
	fetchedAt time.Time
}

func NewIndex() *Index {
	return &Index{entries: map[string]map[string]map[string]releaseEntry{}}
}

func (ix *Index) FetchedAt() time.Time {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.fetchedAt
}

func (ix *Index) Len() int {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return len(ix.entries)
}

// Refresh downloads the tracker and rebuilds the index, keeping only the
// packages in `want`. An empty `want` keeps everything.
func (ix *Index) Refresh(ctx context.Context, want map[string]bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trackerURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mustra/1.0 (+https://mustra.dev)")
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("fetch debian security tracker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("debian security tracker returned %s", resp.Status)
	}

	// Streamed rather than read whole: the body is ~70 MB and decoding it
	// into one map would hold both the raw bytes and the parsed structure
	// at once, on a server that also runs everything else.
	dec := json.NewDecoder(resp.Body)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return fmt.Errorf("unexpected tracker payload")
	}

	built := map[string]map[string]map[string]releaseEntry{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		pkg, _ := tok.(string)
		var cves map[string]struct {
			Releases map[string]releaseEntry `json:"releases"`
		}
		if err := dec.Decode(&cves); err != nil {
			return fmt.Errorf("decode tracker entry for %s: %w", pkg, err)
		}
		if len(want) > 0 && !want[pkg] {
			continue
		}
		byCVE := make(map[string]map[string]releaseEntry, len(cves))
		for cve, info := range cves {
			if len(info.Releases) > 0 {
				byCVE[cve] = info.Releases
			}
		}
		if len(byCVE) > 0 {
			built[pkg] = byCVE
		}
	}

	ix.mu.Lock()
	ix.entries = built
	ix.fetchedAt = time.Now()
	ix.mu.Unlock()
	return nil
}

// Lookup asks what Debian says about this CVE in this package, for the
// release the host runs and the version it has installed.
func (ix *Index) Lookup(pkg, cve, release, installedVersion string) Verdict {
	ix.mu.RLock()
	defer ix.mu.RUnlock()

	releases, ok := ix.entries[pkg][cve]
	if !ok {
		return Verdict{}
	}
	entry, ok := releases[release]
	if !ok {
		// The host runs a release the tracker doesn't cover (a testing or
		// unstable snapshot). Saying nothing is right — guessing from a
		// different release's status would be a fabricated clearance.
		return Verdict{}
	}

	v := Verdict{Known: true, Urgency: entry.Urgency, FixedVersion: entry.FixedVersion}
	if entry.NoDSA != "" {
		v.NoAdvisory = true
		v.Reason = strings.TrimSpace(entry.NoDSAReason)
		if v.Reason == "" {
			v.Reason = strings.TrimSpace(entry.NoDSA)
		}
	}
	// "unimportant" is Debian's standing judgement that a issue does not
	// warrant tracking — no separate nodsa marker is issued for these.
	if entry.Urgency == "unimportant" {
		v.NoAdvisory = true
		if v.Reason == "" {
			v.Reason = "unimportant"
		}
	}
	if entry.Status == "resolved" && entry.FixedVersion != "" && installedVersion != "" {
		// Fixed only if the installed version actually carries the fix.
		// A host left behind on an older revision is still vulnerable, and
		// this is the whole reason the version comparison has to be right.
		if Compare(installedVersion, entry.FixedVersion) >= 0 {
			v.Fixed = true
		}
	}
	return v
}

// NormalizeCVE strips the ecosystem prefix OSV puts on distribution
// advisories. OSV reports Debian findings as "DEBIAN-CVE-2026-66486"
// while the security tracker keys them as plain "CVE-2026-66486", so
// without this every lookup misses and nothing is ever suppressed —
// which is exactly what happened on the first run against the real fleet.
func NormalizeCVE(id string) string {
	for _, prefix := range []string{"DEBIAN-", "UBUNTU-", "ALPINE-", "DLA-", "DSA-"} {
		if strings.HasPrefix(id, prefix) {
			trimmed := strings.TrimPrefix(id, prefix)
			// Only a real CVE underneath: DSA-5678-1 is an advisory ID,
			// not a CVE, and returning "5678-1" would be nonsense.
			if strings.HasPrefix(trimmed, "CVE-") {
				return trimmed
			}
			return id
		}
	}
	return id
}

// ReleaseForVersion maps a Debian major version to its codename, which is
// how the tracker keys releases. Unknown versions return "", which makes
// every lookup for that host inconclusive rather than wrong.
func ReleaseForVersion(platformVersion string) string {
	major := platformVersion
	if i := strings.IndexAny(major, ". "); i > 0 {
		major = major[:i]
	}
	switch major {
	case "10":
		return "buster"
	case "11":
		return "bullseye"
	case "12":
		return "bookworm"
	case "13":
		return "trixie"
	case "14":
		return "forky"
	default:
		return ""
	}
}
