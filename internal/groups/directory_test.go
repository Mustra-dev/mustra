package groups

import "testing"

// Directory targeting rows carry lists (a user's groups); a rule matches
// on the items, and negative operators mean "none of them".
func TestListValuedSensorFields(t *testing.T) {
	d := Device{Sensors: map[string][]map[string]any{"directory": {{
		"ou": "OU=Servers,DC=corp,DC=example", "user_groups": []any{"Finance", "Domain Users"}, "computer_groups": []any{},
	}}}}
	cases := []struct {
		rule Rule
		want bool
	}{
		{Rule{Field: "directory.user_groups", Op: OpEquals, Value: "Finance"}, true},
		{Rule{Field: "directory.user_groups", Op: OpEquals, Value: "Fin"}, false},
		{Rule{Field: "directory.user_groups", Op: OpNotEquals, Value: "Finance"}, false},
		{Rule{Field: "directory.user_groups", Op: OpNotEquals, Value: "HR"}, true},
		{Rule{Field: "directory.ou", Op: OpEndsWith, Value: "DC=corp,DC=example"}, true},
		{Rule{Field: "directory.computer_groups", Op: OpEquals, Value: "Servers"}, false},
	}
	for _, c := range cases {
		if err := c.rule.Validate(); err != nil {
			t.Fatalf("%+v: %v", c.rule, err)
		}
		if got := Matches(d, []Rule{c.rule}, true); got != c.want {
			t.Errorf("%s %s %q: got %v", c.rule.Field, c.rule.Op, c.rule.Value, got)
		}
	}
	if v := Values(d, "directory.user_groups"); len(v) != 2 || v[0] != "Finance" {
		t.Errorf("Values should list the items: %v", v)
	}
}
