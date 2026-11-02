package scim

import "regexp"

var eqFilterRE = regexp.MustCompile(`(?i)^\s*(\w+)\s+eq\s+"([^"]*)"\s*$`)

// parseEqFilter recognizes the one SCIM filter shape IdP provisioning
// clients actually send when checking whether a resource already exists:
// `attr eq "value"`. Anything more elaborate (and/or, other operators,
// nested attribute paths) is not supported — see docs/ROADMAP.md.
func parseEqFilter(filter string) (attr, value string, ok bool) {
	m := eqFilterRE.FindStringSubmatch(filter)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}
