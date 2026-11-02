// Package patchpolicy decides which pending patches an endpoint may
// receive. It is pure: lists in, decision out, so the rule semantics can be
// tested without a database or an agent.
//
// The model: a patch list says what MAY be applied, a
// block list says what may NOT, and both are rule-based (severity, OS,
// name pattern, age) rather than hand-picked. The resolution is
//
//	allowed = pending ∩ (union of the patch lists that cover the endpoint)
//	          − (union of the block lists that cover the endpoint)
//
// with one deliberate asymmetry: an endpoint no patch list covers is
// unrestricted (everything pending is allowed), while an endpoint no block
// list covers simply has nothing blocked. A fleet with no lists at all
// therefore behaves exactly as before lists existed.
package patchpolicy

import (
	"path"
	"strings"
	"time"
)

// Rules is the matching part of a list. Empty slices match anything, so a
// list with no rules matches every patch; a list is the AND of its
// non-empty rules, and each rule is the OR of its values.
type Rules struct {
	Severities   []string `json:"severities,omitempty"`    // "security" | "" (unclassified)
	OS           []string `json:"os,omitempty"`            // linux | windows | darwin
	NamePatterns []string `json:"name_patterns,omitempty"` // case-insensitive globs: linux-image-*, KB50*, "2026-09 Cumulative*"
	// MinAgeDays admits a patch only once the fleet has seen it pending
	// for this many days: "nothing younger than a week" is the classic
	// ring-zero rule. Age is measured from first observation anywhere in
	// the fleet, the closest thing to a release date every OS can give.
	MinAgeDays int `json:"min_age_days,omitempty"`
}

// List is a patch list (Kind "allow") or a block list (Kind "block").
type List struct {
	ID      string
	Name    string
	Kind    string // allow | block
	Enabled bool
	Rules   Rules
}

// Patch is one pending update as an endpoint reports it, plus what the
// fleet knows about it.
type Patch struct {
	Name       string
	NewVersion string
	Severity   string
	OS         string
	FirstSeen  time.Time // zero when unknown; treated as brand new
	Superseded bool
}

// Decision is what an endpoint should be told to apply.
type Decision struct {
	Allowed []Patch
	// Blocked maps a patch name to the list that stopped it, or to
	// "not in any patch list" when no allow list admitted it.
	Blocked map[string]string
	// Restricted is whether any list changed the outcome for this
	// endpoint. A dispatcher uses it to decide whether an agent that
	// cannot apply a subset (too old to understand the list) may still be
	// told "apply everything".
	Restricted bool
}

// Match reports whether the rules admit the patch at the given instant.
func (r Rules) Match(p Patch, now time.Time) bool {
	if len(r.OS) > 0 && !containsFold(r.OS, p.OS) {
		return false
	}
	if len(r.Severities) > 0 && !containsFold(r.Severities, p.Severity) {
		return false
	}
	if len(r.NamePatterns) > 0 && !anyGlob(r.NamePatterns, p.Name) {
		return false
	}
	if r.MinAgeDays > 0 {
		if p.FirstSeen.IsZero() {
			return false
		}
		if now.Sub(p.FirstSeen) < time.Duration(r.MinAgeDays)*24*time.Hour {
			return false
		}
	}
	return true
}

// Evaluate applies the lists that cover one endpoint to its pending
// patches. Disabled lists are ignored. Order is preserved so the agent
// applies in the order the endpoint reported.
func Evaluate(pending []Patch, lists []List, now time.Time) Decision {
	d := Decision{Blocked: map[string]string{}}
	var allows, blocks []List
	for _, l := range lists {
		if !l.Enabled {
			continue
		}
		switch l.Kind {
		case "allow":
			allows = append(allows, l)
		case "block":
			blocks = append(blocks, l)
		}
	}
	for _, p := range pending {
		if len(allows) > 0 {
			admitted := false
			for _, l := range allows {
				if l.Rules.Match(p, now) {
					admitted = true
					break
				}
			}
			if !admitted {
				d.Blocked[p.Name] = "not in any patch list"
				d.Restricted = true
				continue
			}
		}
		blocked := false
		for _, l := range blocks {
			if l.Rules.Match(p, now) {
				d.Blocked[p.Name] = "blocked by " + l.Name
				d.Restricted = true
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		d.Allowed = append(d.Allowed, p)
	}
	return d
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

// anyGlob matches case-insensitively with * and ? wildcards. A pattern
// with no wildcard is a substring test, because "cumulative" is what an
// operator types when they mean every cumulative update.
func anyGlob(patterns []string, name string) bool {
	lname := strings.ToLower(name)
	for _, pat := range patterns {
		lpat := strings.ToLower(strings.TrimSpace(pat))
		if lpat == "" {
			continue
		}
		if !strings.ContainsAny(lpat, "*?[") {
			if strings.Contains(lname, lpat) {
				return true
			}
			continue
		}
		if ok, err := path.Match(lpat, lname); err == nil && ok {
			return true
		}
	}
	return false
}

// MarkSuperseded flags, within each (OS, name) family, every version that
// is lower than the highest version any endpoint reports pending. That is
// The rule: a patch is superseded the moment one endpoint has seen
// its replacement. Patches with no version (Windows titles, macOS labels)
// are never superseded this way; their platform hides replaced updates
// itself.
func MarkSuperseded(patches []Patch) {
	type key struct{ os, name string }
	highest := map[key]string{}
	for _, p := range patches {
		if p.NewVersion == "" {
			continue
		}
		k := key{p.OS, p.Name}
		if cur, ok := highest[k]; !ok || CompareVersions(p.NewVersion, cur) > 0 {
			highest[k] = p.NewVersion
		}
	}
	for i := range patches {
		p := &patches[i]
		if p.NewVersion == "" {
			continue
		}
		if h := highest[key{p.OS, p.Name}]; h != "" && CompareVersions(p.NewVersion, h) < 0 {
			p.Superseded = true
		}
	}
}

// CompareVersions orders package-manager version strings well enough to
// tell "newer" from "older" across dpkg, rpm and plain dotted forms: the
// strings are split into digit and non-digit runs, digit runs compare
// numerically and the rest lexically, a tilde sorts before anything (dpkg
// "~rc1" < release), and an epoch "1:" is just a leading number.
func CompareVersions(a, b string) int {
	ra, rb := runs(a), runs(b)
	for i := 0; i < len(ra) || i < len(rb); i++ {
		var x, y string
		if i < len(ra) {
			x = ra[i]
		}
		if i < len(rb) {
			y = rb[i]
		}
		if x == y {
			continue
		}
		// A tilde run sorts below everything, including the end of string.
		xt, yt := strings.HasPrefix(x, "~"), strings.HasPrefix(y, "~")
		if xt != yt {
			if xt {
				return -1
			}
			return 1
		}
		xd, yd := isDigits(x), isDigits(y)
		switch {
		case xd && yd:
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				if len(x) < len(y) {
					return -1
				}
				return 1
			}
			if x < y {
				return -1
			}
			return 1
		case xd:
			return 1 // "1.2.3" > "1.2.3-rc" is not this case; digits beat letters at the same position
		case yd:
			return -1
		default:
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func runs(v string) []string {
	var out []string
	cur := strings.Builder{}
	curDigit := false
	for _, c := range v {
		d := c >= '0' && c <= '9'
		if cur.Len() > 0 && d != curDigit {
			out = append(out, cur.String())
			cur.Reset()
		}
		curDigit = d
		cur.WriteRune(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
