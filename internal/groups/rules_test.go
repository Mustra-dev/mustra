package groups

import (
	"encoding/json"
	"testing"
)

func device() Device {
	return Device{
		AgentID: "agt-1", Hostname: "prod-web-01", OS: "linux", Arch: "amd64",
		Site: "main-office", Platform: "debian", PlatformVersion: "12",
		AgentVersion: "0.2.0", IPs: []string{"192.0.2.20", "172.17.0.1"},
		CPUCount: 8, MemTotalMB: 16384, Online: true,
		Sensors: map[string][]map[string]any{
			"installed_apps": {
				{"name": "docker-ce", "version": "27.1.1"},
				{"name": "openssh-server", "version": "9.2p1"},
			},
			"patches": {
				{"name": "libssl3", "severity": "security"},
				{"name": "vim", "severity": ""},
			},
			"services": {{"name": "sshd", "status": "running"}},
		},
	}
}

func TestInventoryMatching(t *testing.T) {
	d := device()
	cases := []struct {
		name string
		rule Rule
		want bool
	}{
		{"hostname contains", Rule{"hostname", OpContains, "web"}, true},
		{"hostname is case-insensitive", Rule{"hostname", OpEquals, "PROD-WEB-01"}, true},
		{"hostname starts_with", Rule{"hostname", OpStartsWith, "prod"}, true},
		{"hostname wrong prefix", Rule{"hostname", OpStartsWith, "dev"}, false},
		{"os equals", Rule{"os", OpEquals, "linux"}, true},
		{"os not_equals", Rule{"os", OpNotEquals, "windows"}, true},
		{"regex", Rule{"hostname", OpRegex, `^prod-(web|db)-\d+$`}, true},
		{"regex non-match", Rule{"hostname", OpRegex, `^dev-`}, false},
		{"numeric gt", Rule{"cpu_count", OpGT, "4"}, true},
		{"numeric lt false", Rule{"cpu_count", OpLT, "4"}, false},
		{"memory gte boundary", Rule{"mem_total_mb", OpGTE, "16384"}, true},
		{"bool online", Rule{"online", OpEquals, "true"}, true},
		{"unset field never matches", Rule{"kernel_version", OpContains, "x"}, false},
		{"unset field not_exists", Rule{"kernel_version", OpNotExists, ""}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rule.matches(d); got != c.want {
				t.Errorf("rule %+v = %v, want %v", c.rule, got, c.want)
			}
		})
	}
}

// An IP rule should match if *any* of the device's addresses match — a
// device with several NICs is still "the 192.0.2.x box".
func TestIPMatchesAnyAddress(t *testing.T) {
	d := device()
	if !(Rule{"ip", OpStartsWith, "192.0.2."}).matches(d) {
		t.Error("expected the 192.0.2.x address to match")
	}
	if !(Rule{"ip", OpStartsWith, "172.17."}).matches(d) {
		t.Error("expected the secondary address to match")
	}
	if (Rule{"ip", OpStartsWith, "192.168."}).matches(d) {
		t.Error("did not expect a match on an address the device doesn't have")
	}
}

func TestSensorMatching(t *testing.T) {
	d := device()
	cases := []struct {
		name string
		rule Rule
		want bool
	}{
		{"installed app present", Rule{"installed_apps.name", OpContains, "docker"}, true},
		{"installed app absent", Rule{"installed_apps.name", OpContains, "nginx"}, false},
		{"service running", Rule{"services.status", OpEquals, "running"}, true},
		{"pending security patch", Rule{"patches.severity", OpEquals, "security"}, true},
		{"patch count gt", Rule{"patches.count", OpGT, "1"}, true},
		{"patch count lt", Rule{"patches.count", OpLT, "2"}, false},
		{"app count equals", Rule{"installed_apps.count", OpEquals, "2"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rule.matches(d); got != c.want {
				t.Errorf("rule %+v = %v, want %v", c.rule, got, c.want)
			}
		})
	}
}

// "Computers without Docker" is the whole point of a negative operator on a
// list: it must mean "no row matches", not "some row doesn't match".
func TestNegativeOperatorOnListMeansNoRowMatches(t *testing.T) {
	d := device()
	if (Rule{"installed_apps.name", OpNotContain, "docker"}).matches(d) {
		t.Error("device has docker-ce, so not_contains docker must be false")
	}
	if !(Rule{"installed_apps.name", OpNotContain, "nginx"}).matches(d) {
		t.Error("device has no nginx, so not_contains nginx must be true")
	}
}

// A device that never reported a sensor is unmeasured, not zero. Otherwise
// "fewer than 5 pending patches" would quietly include every machine that
// has never checked in.
func TestUnreportedSensorDoesNotCountAsZero(t *testing.T) {
	d := device()
	delete(d.Sensors, "patches")
	if (Rule{"patches.count", OpLT, "5"}).matches(d) {
		t.Error("a device with no patch data must not satisfy patches.count < 5")
	}
	if (Rule{"patches.name", OpNotContain, "libssl"}).matches(d) {
		t.Error("a device with no patch data must not satisfy a negative patch rule")
	}
}

func TestMatchAllVersusAny(t *testing.T) {
	d := device()
	linux := Rule{"os", OpEquals, "linux"}
	windows := Rule{"os", OpEquals, "windows"}

	if !Matches(d, []Rule{linux, {"cpu_count", OpGTE, "8"}}, true) {
		t.Error("both rules hold, so match-all should be true")
	}
	if Matches(d, []Rule{linux, windows}, true) {
		t.Error("one rule fails, so match-all should be false")
	}
	if !Matches(d, []Rule{windows, linux}, false) {
		t.Error("one rule holds, so match-any should be true")
	}
	if Matches(d, []Rule{windows, {"os", OpEquals, "darwin"}}, false) {
		t.Error("no rule holds, so match-any should be false")
	}
}

// An empty rule set is far more likely to be a half-built group than an
// intentional "everything" — matching the whole fleet would be a nasty
// surprise for whatever targets the group.
func TestEmptyRuleSetMatchesNothing(t *testing.T) {
	if Matches(device(), nil, true) || Matches(device(), nil, false) {
		t.Error("a group with no rules must match nothing")
	}
}

func TestValidate(t *testing.T) {
	bad := []Rule{
		{"", OpEquals, "x"},
		{"hostname", "sideways", "x"},
		{"nosuchsensor.name", OpEquals, "x"},
		{"installed_apps.", OpEquals, "x"},
		{"hostname", OpRegex, "([unclosed"},
		{"hostname", OpIn, " , "},
	}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("expected %+v to be rejected", r)
		}
	}
	for _, r := range []Rule{
		{"hostname", OpContains, "web"},
		{"hostname", OpIn, "web-01, web-02"},
		{"agent_id", OpNotIn, "(a1,a2)"},
		{"patches.count", OpGT, "0"},
		{"hostname", OpRegex, "^prod-"},
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("expected %+v to validate, got %v", r, err)
		}
	}
}

// "in" is how a question scopes to a handful of endpoints without a rule
// per endpoint: a comma-separated list, parentheses optional, matched
// case-insensitively like every other string operator. Its negative form
// follows the list rule: not_in on a multi-valued field means none of the
// values is in the list.
func TestInOperator(t *testing.T) {
	d := Device{AgentID: "agt-1", Hostname: "Web-01", IPs: []string{"10.0.0.5", "192.168.1.5"}}
	yes := []Rule{
		{"agent_id", OpIn, "agt-1, agt-2"},
		{"agent_id", OpIn, "(agt-2,agt-1)"},
		{"hostname", OpIn, "web-01,web-02"},
		{"ip", OpIn, "192.168.1.5"},
		{"agent_id", OpNotIn, "agt-2, agt-3"},
		{"ip", OpNotIn, "10.9.9.9"},
	}
	for _, r := range yes {
		if !r.matches(d) {
			t.Errorf("expected %+v to match", r)
		}
	}
	no := []Rule{
		{"agent_id", OpIn, "agt-2, agt-3"},
		{"agent_id", OpNotIn, "agt-1"},
		{"ip", OpNotIn, "10.0.0.5, 172.16.0.1"},
	}
	for _, r := range no {
		if r.matches(d) {
			t.Errorf("expected %+v not to match", r)
		}
	}
}

func TestAttributeRulesAndManaged(t *testing.T) {
	d := Device{
		AgentID: "a", Hostname: "box", Managed: true,
		Attributes: map[string]string{"owner": "platform", "seats": "12"},
	}
	yes := func(field, op, value string) bool {
		return Matches(d, []Rule{{Field: field, Op: op, Value: value}}, true)
	}
	if !yes("attr.owner", OpEquals, "platform") {
		t.Error("an attribute should match by equality")
	}
	if yes("attr.owner", OpEquals, "finance") {
		t.Error("a different value must not match")
	}
	if !yes("managed", OpEquals, "true") {
		t.Error("managed should read as a boolean")
	}
	// An attribute nobody set is absent, not empty: "is not set" and "is
	// set to nothing" must stay different questions.
	if yes("attr.location", OpEquals, "") {
		t.Error("an unset attribute must not match an empty value")
	}
	// A numeric attribute compares numerically, not as text: "9" < "12".
	if !Matches(d, []Rule{{Field: "attr.seats", Op: OpGT, Value: "9"}}, true) {
		t.Error("a numeric attribute should compare as a number")
	}
	retired := d
	retired.Managed = false
	if !Matches(retired, []Rule{{Field: "managed", Op: OpEquals, Value: "false"}}, true) {
		t.Error("a retired endpoint should be targetable as managed=false")
	}
}

// A rule that matches must also validate: the matcher understood
// "attr.owner" while Validate called it an unknown sensor, so a group
// using one could be evaluated but never saved.
func TestAttributeRulesValidate(t *testing.T) {
	if err := (Rule{Field: "attr.owner", Op: OpEquals, Value: "platform"}).Validate(); err != nil {
		t.Errorf("attr.owner should validate: %v", err)
	}
	if err := (Rule{Field: "attr.", Op: OpEquals, Value: "x"}).Validate(); err == nil {
		t.Error("attr. with no name should be rejected")
	}
	if err := (Rule{Field: "nonsense.thing", Op: OpEquals, Value: "x"}).Validate(); err == nil {
		t.Error("an unknown sensor should still be rejected")
	}
	if err := (Rule{Field: "managed", Op: OpEquals, Value: "false"}).Validate(); err != nil {
		t.Errorf("managed should validate: %v", err)
	}
}

func groupRule(t *testing.T, all bool, rules ...Rule) Rule {
	t.Helper()
	raw, err := json.Marshal(RuleGroup{All: all, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return Rule{GroupField, OpGroup, string(raw)}
}

// A group nests "any" inside "all": (os is windows or platform is debian)
// and online.
func TestGroupRulesNest(t *testing.T) {
	d := device()
	either := groupRule(t, false, Rule{"os", OpEquals, "windows"}, Rule{"platform", OpEquals, "debian"})
	if !Matches(d, []Rule{either, {"online", OpEquals, "true"}}, true) {
		t.Fatal("(windows or debian) and online should match a debian device")
	}
	neither := groupRule(t, false, Rule{"os", OpEquals, "windows"}, Rule{"platform", OpEquals, "ubuntu"})
	if Matches(d, []Rule{neither, {"online", OpEquals, "true"}}, true) {
		t.Fatal("(windows or ubuntu) and online should not match a debian device")
	}
	both := groupRule(t, true, Rule{"os", OpEquals, "linux"}, Rule{"hostname", OpContains, "web"})
	if !Matches(d, []Rule{{"os", OpEquals, "windows"}, both}, false) {
		t.Fatal("windows or (linux and web) should match")
	}
}

func TestExpandGroups(t *testing.T) {
	inner := groupRule(t, false, Rule{"os", OpEquals, "windows"}, Rule{"platform", OpEquals, "debian"})
	leaves, err := ExpandGroups([]Rule{{"online", OpEquals, "true"}, groupRule(t, true, inner, Rule{"site", OpEquals, "x"})})
	if err != nil || len(leaves) != 4 {
		t.Fatalf("got %v, %v; want 4 leaves", leaves, err)
	}
	for _, bad := range []Rule{
		{GroupField, OpGroup, "not json"},
		{GroupField, OpGroup, `{"all":true,"rules":[]}`},
		{"hostname", OpGroup, `{"all":true,"rules":[{"field":"os","op":"equals","value":"linux"}]}`},
	} {
		if _, err := ExpandGroups([]Rule{bad}); err == nil {
			t.Errorf("%v should be rejected", bad)
		}
	}
	deep := Rule{"os", OpEquals, "linux"}
	for i := 0; i < 5; i++ {
		deep = groupRule(t, true, deep)
	}
	if _, err := ExpandGroups([]Rule{deep}); err == nil {
		t.Error("five levels of nesting should be rejected")
	}
	// Everywhere else keeps flat rule lists.
	if err := groupRule(t, true, Rule{"os", OpEquals, "linux"}).Validate(); err == nil {
		t.Error("Validate should still reject a group rule")
	}
}
