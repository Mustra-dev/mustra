// Package groups evaluates computer-group membership rules. It's kept
// free of store and HTTP types so the matching logic — the part with all
// the edge cases — can be tested directly.
package groups

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Device is everything a rule can match against: inventory facts plus the
// agent's cached sensor snapshots. Sensors maps a sensor kind
// ("installed_apps", "services", "processes", "patches") to the rows it
// last reported.
type Device struct {
	AgentID         string
	Hostname        string
	OS              string
	Arch            string
	Site            string
	Platform        string
	PlatformVersion string
	KernelVersion   string
	AgentVersion    string
	IPs             []string
	CPUCount        int
	MemTotalMB      int64
	Online          bool
	// Managed is false for a retired endpoint: its record is kept, but it
	// is not part of the fleet an operation acts on.
	Managed bool
	// Attributes are the operator-maintained fields, addressed in a rule
	// as "attr.<name>".
	Attributes        map[string]string
	Sensors           map[string][]map[string]any
	SensorStatus      map[string]map[string]string
	HistoricalSensors map[string][]map[string]any
}

// Rule is one condition. Field is either an inventory field ("hostname")
// or a sensor path ("installed_apps.name", "patches.count").
type Rule struct {
	Field string `json:"field" api:"required"`
	Op    string `json:"op" api:"required"`
	Value string `json:"value"`
}

// Operators. The negative forms mean "nothing matches" when the field is a
// sensor list: not_contains on installed_apps.name is "no installed app's
// name contains this", which is the reading people expect from
// "computers without Docker".
const (
	OpEquals     = "equals"
	OpNotEquals  = "not_equals"
	OpContains   = "contains"
	OpNotContain = "not_contains"
	OpStartsWith = "starts_with"
	OpEndsWith   = "ends_with"
	OpRegex      = "regex"
	OpGT         = "gt"
	OpGTE        = "gte"
	OpLT         = "lt"
	OpLTE        = "lte"
	OpExists     = "exists"
	OpNotExists  = "not_exists"
	// OpIn matches any of a comma-separated list of values, which is how a
	// question narrows to "these endpoints" without one rule per endpoint.
	// Other fleet tools land on the same operator for the same reason.
	OpIn    = "in"
	OpNotIn = "not_in"
)

var negativeOps = map[string]bool{OpNotEquals: true, OpNotContain: true, OpNotExists: true, OpNotIn: true}

// Sensors a rule may reference. Anything else in a field path is rejected
// at validation time rather than silently matching nothing.
var knownSensors = map[string]bool{
	"installed_apps":   true,
	"services":         true,
	"processes":        true,
	"patches":          true,
	"disks":            true,
	"network":          true,
	"users":            true,
	"hardware":         true,
	"privileges":       true,
	"neighbors":        true,
	"certificates":     true,
	"containers":       true,
	"performance":      true,
	"local_admins":     true,
	"security_posture": true,
	"directory":        true,
}

// FieldSpec describes one selectable field for the rule builder UI, so the
// front end doesn't hard-code a list that drifts from what actually works.
type FieldSpec struct {
	Field string   `json:"field"`
	Label string   `json:"label"`
	Kind  string   `json:"kind"` // "string" | "number" | "bool"
	Ops   []string `json:"ops"`
	Hint  string   `json:"hint,omitempty"`
}

var stringOps = []string{OpEquals, OpNotEquals, OpContains, OpNotContain, OpStartsWith, OpEndsWith, OpRegex, OpIn, OpNotIn}
var numberOps = []string{OpEquals, OpNotEquals, OpGT, OpGTE, OpLT, OpLTE}
var boolOps = []string{OpEquals}

// Fields is the catalog the UI offers. Sensor fields are listed explicitly
// rather than "any key", because a typo'd path that matches nothing is a
// worse experience than a shorter list.
func Fields() []FieldSpec {
	return []FieldSpec{
		{Field: "hostname", Label: "Hostname", Kind: "string", Ops: stringOps},
		{Field: "agent_id", Label: "Agent ID", Kind: "string", Ops: stringOps, Hint: "the endpoint's own identifier; \"in\" takes a comma-separated list"},
		{Field: "os", Label: "Operating system", Kind: "string", Ops: stringOps, Hint: "linux, windows, darwin"},
		{Field: "platform", Label: "Platform", Kind: "string", Ops: stringOps, Hint: "debian, ubuntu, rhel, …"},
		{Field: "platform_version", Label: "Platform version", Kind: "string", Ops: stringOps},
		{Field: "kernel_version", Label: "Kernel version", Kind: "string", Ops: stringOps},
		{Field: "arch", Label: "Architecture", Kind: "string", Ops: stringOps, Hint: "amd64, arm64"},
		{Field: "site", Label: "Site", Kind: "string", Ops: stringOps},
		{Field: "ip", Label: "IP address", Kind: "string", Ops: stringOps, Hint: "matches any of the device's addresses"},
		{Field: "agent_version", Label: "Agent version", Kind: "string", Ops: stringOps},
		{Field: "online", Label: "Online", Kind: "bool", Ops: boolOps, Hint: "true or false"},
		{Field: "managed", Label: "Managed", Kind: "bool", Ops: boolOps, Hint: "false for an endpoint retired after going quiet; its record is kept"},
		{Field: "cpu_count", Label: "Processor count", Kind: "number", Ops: numberOps},
		{Field: "mem_total_mb", Label: "Memory (MB)", Kind: "number", Ops: numberOps},

		{Field: "installed_apps.name", Label: "Installed application name", Kind: "string", Ops: stringOps, Hint: "matches if any installed app matches"},
		{Field: "installed_apps.version", Label: "Installed application version", Kind: "string", Ops: stringOps},
		{Field: "installed_apps.count", Label: "Installed application count", Kind: "number", Ops: numberOps},
		{Field: "services.name", Label: "Service name", Kind: "string", Ops: stringOps},
		{Field: "services.status", Label: "Service status", Kind: "string", Ops: stringOps, Hint: "running, stopped"},
		{Field: "processes.name", Label: "Running process name", Kind: "string", Ops: stringOps},
		{Field: "patches.name", Label: "Pending patch name", Kind: "string", Ops: stringOps},
		{Field: "patches.severity", Label: "Pending patch severity", Kind: "string", Ops: stringOps, Hint: "security"},
		{Field: "patches.count", Label: "Pending patch count", Kind: "number", Ops: numberOps},

		{Field: "disks.mountpoint", Label: "Disk mount point", Kind: "string", Ops: stringOps},
		{Field: "disks.fstype", Label: "Disk filesystem", Kind: "string", Ops: stringOps, Hint: "ext4, xfs, ntfs, apfs"},
		{Field: "disks.used_percent", Label: "Disk used %", Kind: "number", Ops: numberOps, Hint: "matches if any volume is this full"},
		{Field: "disks.free_gb", Label: "Disk free (GB)", Kind: "number", Ops: numberOps},
		{Field: "disks.total_gb", Label: "Disk size (GB)", Kind: "number", Ops: numberOps},
		{Field: "disks.count", Label: "Mounted volume count", Kind: "number", Ops: numberOps},

		{Field: "network.name", Label: "Network interface name", Kind: "string", Ops: stringOps},
		{Field: "network.mac", Label: "MAC address", Kind: "string", Ops: stringOps},
		{Field: "network.addresses", Label: "Interface address", Kind: "string", Ops: stringOps},
		{Field: "network.count", Label: "Network interface count", Kind: "number", Ops: numberOps},

		{Field: "local_admins.name", Label: "Local administrator", Kind: "string", Ops: stringOps, Hint: "any principal that can administer the endpoint"},
		{Field: "local_admins.domain", Label: "Local administrator domain", Kind: "string", Ops: stringOps},
		{Field: "local_admins.kind", Label: "Local administrator kind", Kind: "string", Ops: stringOps, Hint: "user, group"},
		{Field: "local_admins.source", Label: "Local administrator source", Kind: "string", Ops: stringOps, Hint: "local, domain, builtin"},
		{Field: "local_admins.count", Label: "Local administrator count", Kind: "number", Ops: numberOps},
		{Field: "security_posture.firewall_enabled", Label: "Firewall enabled", Kind: "bool", Ops: boolOps},
		{Field: "security_posture.firewall_engine", Label: "Firewall engine", Kind: "string", Ops: stringOps, Hint: "windows-defender, ufw, firewalld, nftables, iptables, macos-alf, none"},
		{Field: "security_posture.os_volume_encrypted", Label: "OS volume encrypted", Kind: "bool", Ops: boolOps},
		{Field: "security_posture.encryption_engine", Label: "Disk encryption engine", Kind: "string", Ops: stringOps, Hint: "bitlocker, luks, filevault, none"},
		{Field: "security_posture.antivirus_realtime", Label: "Antimalware real-time protection", Kind: "bool", Ops: boolOps},
		{Field: "security_posture.antivirus_signature_age_hours", Label: "Antimalware signature age (hours)", Kind: "number", Ops: numberOps},
		{Field: "security_posture.antivirus_tamper_protected", Label: "Antimalware tamper protection", Kind: "bool", Ops: boolOps},
		{Field: "security_posture.app_control_mode", Label: "Application control mode", Kind: "string", Ops: stringOps, Hint: "enforce, audit, off, mixed"},
		{Field: "users.user", Label: "Logged-in user", Kind: "string", Ops: stringOps},
		{Field: "users.count", Label: "Logged-in user count", Kind: "number", Ops: numberOps},

		{Field: "hardware.cpu_model", Label: "CPU model", Kind: "string", Ops: stringOps},
		{Field: "hardware.cpu_vendor", Label: "CPU vendor", Kind: "string", Ops: stringOps},
		{Field: "hardware.cpu_cores_physical", Label: "Physical cores", Kind: "number", Ops: numberOps},
		{Field: "hardware.cpu_cores_logical", Label: "Logical cores", Kind: "number", Ops: numberOps},
		{Field: "hardware.mem_total_mb", Label: "Total memory (MB)", Kind: "number", Ops: numberOps},
		{Field: "hardware.mem_used_percent", Label: "Memory used %", Kind: "number", Ops: numberOps},
		{Field: "hardware.swap_total_mb", Label: "Swap total (MB)", Kind: "number", Ops: numberOps},
		{Field: "hardware.virtualization_system", Label: "Virtualization", Kind: "string", Ops: stringOps, Hint: "kvm, lxc, docker, vmware, …"},
		{Field: "hardware.virtualization_role", Label: "Virtualization role", Kind: "string", Ops: stringOps, Hint: "guest or host"},
		{Field: "hardware.os_family", Label: "OS family", Kind: "string", Ops: stringOps, Hint: "debian, rhel, darwin, …"},
		{Field: "hardware.kernel_arch", Label: "Kernel architecture", Kind: "string", Ops: stringOps},
		{Field: "hardware.uptime_hours", Label: "Uptime (hours)", Kind: "number", Ops: numberOps},
		{Field: "hardware.boot_time", Label: "Boot time", Kind: "string", Ops: stringOps},
		{Field: "hardware.load_avg_1", Label: "Load average (1 min)", Kind: "number", Ops: numberOps},
		{Field: "hardware.load_avg_15", Label: "Load average (15 min)", Kind: "number", Ops: numberOps},
		{Field: "hardware.temp_max_c", Label: "Hottest sensor (°C)", Kind: "number", Ops: numberOps},
		{Field: "hardware.host_id", Label: "Machine ID", Kind: "string", Ops: stringOps},

		{Field: "privileges.full_rights", Label: "Fully manageable", Kind: "bool", Ops: boolOps, Hint: "false means something is blocking management — see the endpoint's Privileges tab"},
		{Field: "privileges.elevated", Label: "Running elevated", Kind: "bool", Ops: boolOps, Hint: "root, or a LocalSystem/elevated Windows token"},
		{Field: "privileges.account", Label: "Agent runs as", Kind: "string", Ops: stringOps, Hint: "root, NT AUTHORITY\\SYSTEM, …"},
		{Field: "privileges.full_disk_access", Label: "Full Disk Access (macOS)", Kind: "bool", Ops: boolOps},
		{Field: "privileges.sip_enabled", Label: "SIP enabled (macOS)", Kind: "bool", Ops: boolOps},
		{Field: "privileges.integrity_level", Label: "Integrity level (Windows)", Kind: "string", Ops: stringOps},
		{Field: "privileges.missing_privileges", Label: "Missing Windows privilege", Kind: "string", Ops: stringOps},
		{Field: "privileges.limitations", Label: "Management limitation", Kind: "string", Ops: stringOps},

		{Field: "neighbors.ip", Label: "Neighbour address", Kind: "string", Ops: stringOps, Hint: "a host this endpoint has talked to"},
		{Field: "neighbors.mac", Label: "Neighbour MAC", Kind: "string", Ops: stringOps},
		{Field: "neighbors.count", Label: "Neighbour count", Kind: "number", Ops: numberOps},

		{Field: "certificates.subject", Label: "Certificate subject", Kind: "string", Ops: stringOps},
		{Field: "certificates.issuer", Label: "Certificate issuer", Kind: "string", Ops: stringOps},
		{Field: "certificates.days_left", Label: "Days until expiry", Kind: "number", Ops: numberOps, Hint: "negative means already expired"},
		{Field: "certificates.dns_names", Label: "Certificate hostname", Kind: "string", Ops: stringOps},
		{Field: "certificates.self_signed", Label: "Self-signed certificate", Kind: "bool", Ops: boolOps},
		{Field: "certificates.path", Label: "Certificate path", Kind: "string", Ops: stringOps},
		{Field: "certificates.count", Label: "Certificate count", Kind: "number", Ops: numberOps},

		{Field: "containers.name", Label: "Container name", Kind: "string", Ops: stringOps},
		{Field: "containers.image", Label: "Container image", Kind: "string", Ops: stringOps, Hint: "as configured, e.g. postgres:16.4"},
		{Field: "containers.state", Label: "Container state", Kind: "string", Ops: stringOps, Hint: "running, exited, …"},
		{Field: "containers.update", Label: "Container update status", Kind: "string", Ops: stringOps, Hint: "update_available, up_to_date, not_checked, check_failed"},
		{Field: "containers.compose_project", Label: "Compose project", Kind: "string", Ops: stringOps},
		{Field: "containers.count", Label: "Container count", Kind: "number", Ops: numberOps},

		{Field: "directory.kind", Label: "Directory join", Kind: "string", Ops: stringOps, Hint: "ad, entra, hybrid, workgroup"},
		{Field: "directory.domain", Label: "AD domain", Kind: "string", Ops: stringOps},
		{Field: "directory.site", Label: "AD site", Kind: "string", Ops: stringOps},
		{Field: "directory.ou", Label: "Computer OU", Kind: "string", Ops: stringOps, Hint: "the computer object's container, e.g. OU=Servers,DC=corp,DC=example; ends_with matches an OU and everything under it"},
		{Field: "directory.computer_dn", Label: "Computer DN", Kind: "string", Ops: stringOps},
		{Field: "directory.computer_groups", Label: "Computer AD group", Kind: "string", Ops: stringOps, Hint: "matches if the computer account is in this group"},
		{Field: "directory.users", Label: "Signed-in directory user", Kind: "string", Ops: stringOps, Hint: "sAMAccountName or UPN of anyone signed in"},
		{Field: "directory.user_groups", Label: "Signed-in user's AD group", Kind: "string", Ops: stringOps, Hint: "matches if anyone signed in is in this group, e.g. Finance"},
		{Field: "directory.user_departments", Label: "Signed-in user's department", Kind: "string", Ops: stringOps},
		{Field: "directory.entra_tenant", Label: "Entra tenant", Kind: "string", Ops: stringOps},

		{Field: "performance.cpu_current", Label: "CPU now (%)", Kind: "number", Ops: numberOps},
		{Field: "performance.cpu_peak", Label: "CPU peak 24h (%)", Kind: "number", Ops: numberOps},
		{Field: "performance.cpu_events", Label: "CPU pressure events 24h", Kind: "number", Ops: numberOps},
		{Field: "performance.memory_current", Label: "Memory now (%)", Kind: "number", Ops: numberOps},
		{Field: "performance.memory_events", Label: "Memory pressure events 24h", Kind: "number", Ops: numberOps},
		{Field: "performance.disk_current", Label: "Fullest disk (%)", Kind: "number", Ops: numberOps},
		{Field: "performance.disk_events", Label: "Disk pressure events 24h", Kind: "number", Ops: numberOps},
	}
}

// Validate reports why a rule can't be evaluated, or nil if it's fine.
func (r Rule) Validate() error {
	if r.Field == "" {
		return fmt.Errorf("rule needs a field")
	}
	if sensor, key, ok := strings.Cut(r.Field, "."); ok {
		// "attr.<name>" is an operator-maintained attribute, not a sensor.
		// Any name is accepted: an attribute somebody deletes later should
		// make the rule match nothing, not make the group unsaveable.
		if sensor == "attr" {
			if key == "" {
				return fmt.Errorf("field %q needs an attribute name after attr.", r.Field)
			}
		} else if !knownSensors[sensor] && !regexp.MustCompile(`^custom_csn-[A-Za-z0-9-]+$`).MatchString(sensor) {
			return fmt.Errorf("unknown sensor %q in field %q", sensor, r.Field)
		} else if key == "" {
			return fmt.Errorf("field %q needs a property after the sensor name", r.Field)
		}
	}
	if r.Op == "same_row" {
		sensor, key, ok := strings.Cut(r.Field, ".")
		if !ok || key != "_row" {
			return fmt.Errorf("same_row requires a sensor._row field")
		}
		var children []Rule
		if json.Unmarshal([]byte(r.Value), &children) != nil || len(children) == 0 || len(children) > 64 {
			return fmt.Errorf("same_row needs 1–64 conditions")
		}
		for _, child := range children {
			if child.Op == "same_row" || !strings.HasPrefix(child.Field, sensor+".") || strings.HasSuffix(child.Field, ".count") || strings.Contains(child.Field, "._") {
				return fmt.Errorf("same_row conditions must use ordinary fields from one sensor")
			}
			if err := child.Validate(); err != nil {
				return err
			}
		}
		return nil
	}
	switch r.Op {
	case OpEquals, OpNotEquals, OpContains, OpNotContain, OpStartsWith, OpEndsWith,
		OpGT, OpGTE, OpLT, OpLTE, OpExists, OpNotExists:
	case OpIn, OpNotIn:
		if len(splitList(r.Value)) == 0 {
			return fmt.Errorf("%q needs at least one value, comma-separated", r.Op)
		}
	case OpRegex:
		if _, err := regexp.Compile(r.Value); err != nil {
			return fmt.Errorf("invalid regular expression %q: %w", r.Value, err)
		}
	default:
		return fmt.Errorf("unknown operator %q", r.Op)
	}
	return nil
}

// OpGroup nests conditions: the rule's Value is a RuleGroup as JSON, so a
// query can say "(A or B) and C". Only Interact queries use it; Validate
// still rejects it, so computer groups, policies and the rest keep their
// flat rule lists. ExpandGroups checks a group and returns its conditions.
const OpGroup = "group"

// GroupField is the Field a group rule carries; it names no field.
const GroupField = "_group"

// RuleGroup is a group rule's Value.
type RuleGroup struct {
	All   bool   `json:"all"`
	Rules []Rule `json:"rules"`
}

const maxGroupDepth = 4

// ExpandGroups returns every condition inside rules, groups opened, so a
// caller can validate them as it would a flat list. It errors on a group
// that is malformed, empty, over 64 conditions or nested too deep.
func ExpandGroups(rules []Rule) ([]Rule, error) {
	var out []Rule
	var walk func([]Rule, int) error
	walk = func(rs []Rule, depth int) error {
		for _, r := range rs {
			if r.Op != OpGroup {
				out = append(out, r)
				continue
			}
			if depth >= maxGroupDepth {
				return fmt.Errorf("groups nest at most %d deep", maxGroupDepth)
			}
			var g RuleGroup
			if r.Field != GroupField || json.Unmarshal([]byte(r.Value), &g) != nil || len(g.Rules) == 0 || len(g.Rules) > 64 {
				return fmt.Errorf("a group needs 1–64 conditions")
			}
			if err := walk(g.Rules, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(rules, 0)
	return out, err
}

// Matches reports whether a device satisfies every rule (matchAll) or at
// least one (any). A group with no rules matches nothing: an empty rule set
// is far more likely to be half-built than to mean "the entire fleet".
func Matches(d Device, rules []Rule, matchAll bool) bool {
	if len(rules) == 0 {
		return false
	}
	for _, r := range rules {
		ok := r.matches(d)
		if matchAll && !ok {
			return false
		}
		if !matchAll && ok {
			return true
		}
	}
	return matchAll
}

func (r Rule) matches(d Device) bool {
	if r.Op == OpGroup {
		var g RuleGroup
		if json.Unmarshal([]byte(r.Value), &g) != nil {
			return false
		}
		return Matches(d, g.Rules, g.All)
	}
	if r.Op == "same_row" {
		if r.Validate() != nil {
			return false
		}
		sensor, _, _ := strings.Cut(r.Field, ".")
		var children []Rule
		_ = json.Unmarshal([]byte(r.Value), &children)
		for _, row := range d.Sensors[sensor] {
			one := d
			one.Sensors = map[string][]map[string]any{sensor: {row}}
			if Matches(one, children, true) {
				return true
			}
		}
		return false
	}
	// "attr.<name>" is an operator-maintained attribute, not a sensor path.
	// Checked before the generic dotted-field split, which would otherwise
	// read it as the sensor "attr".
	if sensor, key, isSensor := strings.Cut(r.Field, "."); isSensor && sensor != "attr" {
		return r.matchesSensor(d, sensor, key)
	}
	values, numeric, present := inventoryValue(d, r.Field)
	if r.Op == OpExists {
		return present
	}
	if r.Op == OpNotExists {
		return !present
	}
	if !present {
		return false
	}
	if numeric != nil {
		return compareNumeric(*numeric, r.Op, r.Value)
	}
	return anyOrNone(values, r)
}

func (r Rule) matchesSensor(d Device, sensor, key string) bool {
	if strings.HasPrefix(key, "_") {
		v, ok := d.SensorStatus[sensor][key]
		return ok && anyOrNone([]string{v}, r)
	}
	rows, reported := d.Sensors[sensor]

	if key == "count" {
		// A device that hasn't reported the sensor has no count to compare;
		// treating that as zero would quietly sweep unmeasured devices into
		// "patches.count lt 5" groups.
		if !reported {
			return false
		}
		return compareNumeric(float64(len(rows)), r.Op, r.Value)
	}

	if r.Op == OpExists {
		if strings.HasPrefix(sensor, "custom_") {
			for _, row := range rows {
				if row[key] != nil {
					return true
				}
			}
			return false
		}
		return reported && len(rows) > 0
	}
	if r.Op == OpNotExists {
		return reported && len(rows) == 0
	}
	if !reported {
		return false
	}

	var values []string
	missing := false
	for _, row := range rows {
		if v, ok := row[key]; ok && v != nil {
			// A list-valued field (a user's groups) matches on its items:
			// "in group Finance" is any item equal, "not in" is none.
			if list, isList := v.([]any); isList {
				for _, item := range list {
					values = append(values, fmt.Sprint(item))
				}
				continue
			}
			values = append(values, fmt.Sprint(v))
		} else {
			missing = true
		}
	}
	if strings.HasPrefix(sensor, "custom_") && missing && negativeOps[r.Op] {
		return false
	}
	if strings.HasPrefix(sensor, "custom_") && len(rows) > 0 && len(values) == 0 {
		return false
	}
	return anyOrNone(values, r)
}

// anyOrNone applies a positive operator as "any value matches" and a
// negative one as "no value matches".
func anyOrNone(values []string, r Rule) bool {
	if negativeOps[r.Op] {
		for _, v := range values {
			if compareString(v, positiveForm(r.Op), r.Value) {
				return false
			}
		}
		return true
	}
	for _, v := range values {
		if compareString(v, r.Op, r.Value) {
			return true
		}
	}
	return false
}

func positiveForm(op string) string {
	switch op {
	case OpNotEquals:
		return OpEquals
	case OpNotContain:
		return OpContains
	case OpNotIn:
		return OpIn
	default:
		return op
	}
}

// splitList reads an "in" value: comma-separated, whitespace-trimmed, with
// optional surrounding parentheses so "in (a, b)" reads the way people
// write it.
func splitList(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(strings.TrimPrefix(v, "("), ")")
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// inventoryValue returns a field's string values (usually one, several for
// IPs), or a numeric value, plus whether the field is set at all.
func inventoryValue(d Device, field string) (values []string, numeric *float64, present bool) {
	str := func(s string) ([]string, *float64, bool) { return []string{s}, nil, s != "" }
	// Operator-maintained attributes are addressed as "attr.<name>". An
	// attribute nobody has set on this endpoint is absent rather than
	// empty, so "attr.owner is not set" and "attr.owner is empty" stay
	// distinguishable.
	if name, ok := strings.CutPrefix(field, "attr."); ok {
		v, has := d.Attributes[name]
		if !has {
			return nil, nil, false
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return []string{v}, &f, true
		}
		return []string{v}, nil, true
	}
	num := func(f float64) ([]string, *float64, bool) { return nil, &f, true }

	switch field {
	case "managed":
		return str(boolWord(d.Managed))
	case "hostname":
		return str(d.Hostname)
	case "agent_id":
		return str(d.AgentID)
	case "os":
		return str(d.OS)
	case "arch":
		return str(d.Arch)
	case "site":
		return str(d.Site)
	case "platform":
		return str(d.Platform)
	case "platform_version":
		return str(d.PlatformVersion)
	case "kernel_version":
		return str(d.KernelVersion)
	case "agent_version":
		return str(d.AgentVersion)
	case "ip":
		return d.IPs, nil, len(d.IPs) > 0
	case "online":
		return str(strconv.FormatBool(d.Online))
	case "cpu_count":
		return num(float64(d.CPUCount))
	case "mem_total_mb":
		return num(float64(d.MemTotalMB))
	default:
		return nil, nil, false
	}
}

// Values returns what a field answers for one device, as the strings a
// results grid shows. This is the read half of the same catalog the rule
// engine filters on, so a question can ask for anything a group can match
// on and the two can never drift apart — one field list, one accessor.
//
// A device that has never reported the sensor answers nil, which callers
// render as "no result" rather than as an empty string. That distinction
// matters: "this endpoint has no antivirus" and "this endpoint never told
// us" are different answers, and collapsing them is how inventory tools
// end up quietly wrong.
func Values(d Device, field string) []string {
	if sensor, key, ok := strings.Cut(field, "."); ok {
		if strings.HasPrefix(key, "_") {
			if v, ok := d.SensorStatus[sensor][key]; ok {
				return []string{v}
			}
			return nil
		}
		rows := d.Sensors[sensor]
		if rows == nil {
			return nil // unmeasured, not empty
		}
		if key == "count" {
			return []string{strconv.Itoa(len(rows))}
		}
		// Non-nil from the start: the sensor *was* reported, so an answer
		// of "nothing" is a real answer and must not read as unmeasured.
		out := []string{}
		seen := map[string]bool{}
		for _, row := range rows {
			v, ok := row[key]
			if !ok || v == nil {
				continue
			}
			items := []any{v}
			if list, isList := v.([]any); isList {
				items = list
			}
			for _, item := range items {
				s := formatValue(item)
				if s == "" || seen[s] {
					continue
				}
				seen[s] = true
				out = append(out, s)
			}
		}
		return out
	}

	values, numeric, present := inventoryValue(d, field)
	switch {
	case numeric != nil:
		return []string{strconv.FormatFloat(*numeric, 'f', -1, 64)}
	case !present:
		return nil
	default:
		return values
	}
}

func formatValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func compareString(actual, op, want string) bool {
	a, w := strings.ToLower(actual), strings.ToLower(want)
	switch op {
	case OpEquals:
		return a == w
	case OpContains:
		return strings.Contains(a, w)
	case OpStartsWith:
		return strings.HasPrefix(a, w)
	case OpEndsWith:
		return strings.HasSuffix(a, w)
	case OpIn:
		for _, candidate := range splitList(w) {
			if a == candidate {
				return true
			}
		}
		return false
	case OpRegex:
		re, err := regexp.Compile(want)
		if err != nil {
			return false
		}
		return re.MatchString(actual)
	case OpGT, OpGTE, OpLT, OpLTE:
		// A numeric operator against a string field: compare numerically
		// when both sides parse, otherwise it simply doesn't match.
		af, err1 := strconv.ParseFloat(actual, 64)
		if err1 != nil {
			return false
		}
		return compareNumeric(af, op, want)
	default:
		return false
	}
}

func compareNumeric(actual float64, op, want string) bool {
	w, err := strconv.ParseFloat(strings.TrimSpace(want), 64)
	if err != nil {
		return false
	}
	switch op {
	case OpEquals:
		return actual == w
	case OpNotEquals:
		return actual != w
	case OpGT:
		return actual > w
	case OpGTE:
		return actual >= w
	case OpLT:
		return actual < w
	case OpLTE:
		return actual <= w
	default:
		return false
	}
}

// boolWord renders a boolean the way a rule's value is written, so
// `managed equals true` reads the way somebody would type it.
func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
