package server

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// A parser for the subset of YAML that Wazuh SCA policies actually use.
//
// Written rather than pulled in as a dependency, deliberately. SCA files
// are a narrow, regular shape — a `checks:` list of maps with scalar
// fields and two string lists — and a general YAML library would be a new
// dependency, a new parser to keep current, and a much larger surface than
// this needs. If policies ever outgrow this shape, swapping in a real YAML
// package is a contained change behind this one function.
//
// What it handles:
//
//	checks:
//	  - id: 28500
//	    title: "Ensure cramfs is not available"
//	    rationale: "..."
//	    remediation: "..."
//	    condition: all
//	    rules:
//	      - 'c:modprobe -n -v cramfs -> r:install /bin/true'
//	      - 'not c:lsmod -> r:cramfs'
//
// Anything it cannot make sense of is skipped rather than guessed at, and
// the count of what was skipped is worth surfacing so a half-read policy
// doesn't pass for a complete one.
func parseSCAPolicy(data []byte) ([]proto.ComplianceCheck, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	inChecks := false
	var checks []proto.ComplianceCheck
	var cur *proto.ComplianceCheck
	var inRules bool
	// The check's `compliance:` block: framework → control IDs, written
	// either as a map (`nist_800_53: ["CM-2"]`, current Wazuh content) or
	// as a list of one-key maps (`- nist_sp_800-53: ["CM-2"]`, older
	// files), each value a flow list or an indented block list.
	inCompliance := false
	complianceIndent, lastFramework := -1, ""
	rulesIndent := -1
	// The indent of the checks list itself. Without tracking it, any
	// nested list — SCA files all carry a `compliance:` block of them —
	// looks like the start of a new check, and every check after the first
	// gets merged into one with all their rules pooled together.
	itemIndent := -1

	flush := func() {
		if cur != nil && len(cur.Controls) == 0 {
			cur.Controls = nil
		}
		inCompliance = false
		// A check with no rules can never produce a result, so keeping it
		// would only inflate the count with entries that always answer
		// "unknown".
		if cur != nil && len(cur.Rules) > 0 {
			if cur.ID == "" {
				cur.ID = slugify(cur.Title)
			}
			checks = append(checks, *cur)
		}
		cur = nil
		inRules = false
		rulesIndent = -1
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)

		if !inChecks {
			if trimmed == "checks:" {
				inChecks = true
			}
			continue
		}

		if inCompliance {
			if indent > complianceIndent {
				item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				if k, v, ok := strings.Cut(item, ":"); ok && !strings.HasPrefix(item, "\"") {
					lastFramework = normalizeFramework(k)
					cur.Controls[lastFramework] = append(cur.Controls[lastFramework], flowList(v)...)
				} else if lastFramework != "" && strings.HasPrefix(trimmed, "- ") {
					cur.Controls[lastFramework] = append(cur.Controls[lastFramework], unquote(item))
				}
				continue
			}
			inCompliance = false
			if len(cur.Controls) == 0 {
				cur.Controls = nil
			}
		}

		// Inside a rules list, every item belongs to it until the indent
		// drops back to the check's own fields. Checked before the
		// new-check test, since a rule is also a list item.
		if inRules {
			if strings.HasPrefix(trimmed, "- ") && indent >= rulesIndent {
				cur.Rules = append(cur.Rules, unquote(strings.TrimPrefix(trimmed, "- ")))
				continue
			}
			inRules = false
		}

		// A list item at the checks list's own indent starts a new check.
		// Anything deeper is a nested list inside the current one — the
		// `compliance:` block, most often — and must not.
		if strings.HasPrefix(trimmed, "- ") {
			if itemIndent == -1 {
				itemIndent = indent
			}
			if indent > itemIndent {
				continue // nested list; nothing here is a check field
			}
			flush()
			cur = &proto.ComplianceCheck{}
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if trimmed == "" {
				continue
			}
		}
		if cur == nil {
			continue
		}
		// A field indented deeper than the check's own fields belongs to a
		// nested structure, not to the check.
		if itemIndent >= 0 && indent > itemIndent+4 {
			continue
		}

		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = unquote(strings.TrimSpace(value))

		switch key {
		case "id":
			cur.ID = value
		// Wazuh SCA uses `name` for the check's title. `title` is accepted
		// too because it is the obvious guess when hand-writing a policy —
		// and a fixture written against that guess is exactly how this was
		// missed until a real published file was parsed.
		case "name", "title":
			if cur.Title == "" {
				cur.Title = value
			}
		case "rationale", "description":
			if cur.Rationale == "" {
				cur.Rationale = value
			}
		case "remediation":
			cur.Remediation = value
		case "condition":
			cur.Condition = value
		case "rules":
			inRules = true
			rulesIndent = indent + 1
		case "compliance":
			inCompliance, complianceIndent, lastFramework = true, indent, ""
			if cur.Controls == nil {
				cur.Controls = map[string][]string{}
			}
		}
	}
	flush()

	if len(checks) == 0 {
		return nil, fmt.Errorf("no checks found — is this a Wazuh SCA policy file?")
	}
	return checks, nil
}

// unquote strips the surrounding quotes YAML scalars often carry, and
// nothing else. Escape handling is deliberately absent: SCA rules are
// mostly regexes, and "helpfully" unescaping them would corrupt patterns.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	// A bare numeric id parses fine as a string; this just normalizes it.
	if n, err := strconv.Atoi(s); err == nil {
		return strconv.Itoa(n)
	}
	return s
}

// normalizeFramework gives one key per framework whichever way a file
// spells it: "nist_sp_800-53" and "nist_800_53" are the same catalogue.
func normalizeFramework(k string) string {
	k = strings.ToLower(strings.Trim(strings.TrimSpace(k), `"'`))
	k = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(k)
	switch k {
	case "nist_sp_800_53", "nist_800_53r5", "nist_sp_800_53r5":
		return "nist_800_53"
	case "nist_sp_800_171", "nist_800_171r2", "nist_800_171r3":
		return "nist_800_171"
	}
	return k
}

// flowList reads a YAML flow sequence of scalars (`["CM-2", 'CM-6']`), or a
// single scalar; an empty value (a block list follows) gives nothing.
func flowList(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	var out []string
	for _, part := range strings.Split(v, ",") {
		if id := unquote(part); id != "" {
			out = append(out, id)
		}
	}
	return out
}
