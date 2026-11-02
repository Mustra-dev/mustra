package agent

import (
	"strings"
	"testing"
)

// Shadowing readiness: the Shadow value, the Remote Desktop service and,
// while the firewall is on, the shadow firewall rule.
func TestShadowState(t *testing.T) {
	for _, c := range []struct {
		name                 string
		value                int
		rule, service, fw    bool
		ready                bool
		mode, reasonContains string
	}{
		{"enforced policy", 1, true, true, true, true, "control_with_consent", ""},
		{"turned off", 0, true, true, true, false, "off", "turned off"},
		{"service stopped", 1, true, false, true, false, "control_with_consent", "TermService"},
		{"rule off, firewall on", 3, false, true, true, false, "view_with_consent", "firewall rule"},
		{"rule off, firewall off", 3, false, true, false, true, "view_with_consent", ""},
		{"unknown value", 9, true, true, true, false, "off", "turned off"},
	} {
		st := shadowState(c.value, "policy", c.rule, c.service, c.fw)
		if st.Ready != c.ready || st.Mode != c.mode || (c.reasonContains != "" && !strings.Contains(st.Reason, c.reasonContains)) {
			t.Errorf("%s: %+v", c.name, st)
		}
	}
}
