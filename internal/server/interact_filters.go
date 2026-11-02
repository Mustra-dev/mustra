package server

// Value filters: a condition in brackets after a field in the get clause,
//
//	get installed_apps.name[contains chrome] and installed_apps.version from all machines
//
// trims what that sensor reports to the rows that match, so the answer is
// the Chrome installs and their versions rather than every app on every
// machine that has Chrome. A machine with no matching row drops out, as it
// would for the same condition in the "with" clause. Several brackets on
// one field, or filters on two fields of the same sensor, all apply to
// each row. A filter on an inventory field (hostname, os) has no rows to
// trim and simply narrows the machines.
//
// The filter travels inside the get entry itself, so saved queries,
// history and exports carry it with no change to what they store.

import (
	"fmt"
	"strings"

	"github.com/mustra-dev/mustra/internal/groups"
)

// valueFilterOps maps the operator words the query box accepts to the rule
// engine's names, as the "with" clause does.
var valueFilterOps = map[string]string{
	"greater_than": groups.OpGT, "less_than": groups.OpLT, "matches_regex": groups.OpRegex,
	"greater_than_or_equal": groups.OpGTE, "less_than_or_equal": groups.OpLTE,
}

// splitGetFilter reads one get entry: "field" or "field[op value][op value]".
func splitGetFilter(item string) (string, []groups.Rule, error) {
	i := strings.IndexByte(item, '[')
	if i < 0 {
		return strings.TrimSpace(item), nil, nil
	}
	field := strings.TrimSpace(item[:i])
	rest := item[i:]
	var rules []groups.Rule
	for rest = strings.TrimSpace(rest); rest != ""; rest = strings.TrimSpace(rest) {
		if rest[0] != '[' {
			return "", nil, fmt.Errorf("%q: expected [operator value] after the field", item)
		}
		// The closing bracket, skipping any inside a quoted value.
		end, quoted := -1, false
		for j := 1; j < len(rest); j++ {
			if rest[j] == '"' {
				quoted = !quoted
			} else if rest[j] == ']' && !quoted {
				end = j
				break
			}
		}
		if end < 0 {
			return "", nil, fmt.Errorf("%q: a [ is not closed", item)
		}
		inner := strings.TrimSpace(rest[1:end])
		rest = rest[end+1:]
		op, value, _ := strings.Cut(inner, " ")
		if mapped, ok := valueFilterOps[op]; ok {
			op = mapped
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		rule := groups.Rule{Field: field, Op: op, Value: value}
		if err := rule.Validate(); err != nil {
			return "", nil, fmt.Errorf("%q: %w", item, err)
		}
		rules = append(rules, rule)
	}
	if field == "" {
		return "", nil, fmt.Errorf("%q: a filter needs a field before it", item)
	}
	return field, rules, nil
}

// valueFilters is a query's filters, by where they apply.
type valueFilters struct {
	bySensor  map[string][]groups.Rule // trims that sensor's rows
	inventory []groups.Rule            // narrows the machines
	all       []groups.Rule
}

// parseGetFilters splits a get list into bare fields and its filters.
func parseGetFilters(get []string) ([]string, valueFilters, error) {
	vf := valueFilters{bySensor: map[string][]groups.Rule{}}
	fields := make([]string, 0, len(get))
	for _, item := range get {
		field, rules, err := splitGetFilter(item)
		if err != nil {
			return nil, vf, err
		}
		fields = append(fields, field)
		for _, r := range rules {
			sensor, key, dotted := strings.Cut(r.Field, ".")
			switch {
			case !dotted:
				vf.inventory = append(vf.inventory, r)
			case sensor == "attr" || key == "count" || strings.HasPrefix(key, "_"):
				return nil, vf, fmt.Errorf("%q: a [filter] works on a sensor's own values, not on %s", item, r.Field)
			default:
				vf.bySensor[sensor] = append(vf.bySensor[sensor], r)
			}
			vf.all = append(vf.all, r)
		}
	}
	return fields, vf, nil
}

// apply returns the device with each filtered sensor cut down to the rows
// every filter on it matches, and false when the device drops out.
func (vf valueFilters) apply(d groups.Device) (groups.Device, bool) {
	for _, r := range vf.inventory {
		if !groups.Matches(d, []groups.Rule{r}, true) {
			return d, false
		}
	}
	if len(vf.bySensor) == 0 {
		return d, true
	}
	sensors := make(map[string][]map[string]any, len(d.Sensors))
	for k, v := range d.Sensors {
		sensors[k] = v
	}
	for sensor, rules := range vf.bySensor {
		var kept []map[string]any
		for _, row := range d.Sensors[sensor] {
			one := d
			one.Sensors = map[string][]map[string]any{sensor: {row}}
			if groups.Matches(one, rules, true) {
				kept = append(kept, row)
			}
		}
		if len(kept) == 0 {
			return d, false
		}
		sensors[sensor] = kept
	}
	d.Sensors = sensors
	return d, true
}
