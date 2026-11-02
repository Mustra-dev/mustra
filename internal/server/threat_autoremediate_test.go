package server

import "testing"

func TestThreatAutoRemediationValidate(t *testing.T) {
	ok := []threatAutoRemediation{
		defaultThreatAutoRemediation(),
		{Enabled: true, AfterDays: 30},
		{Enabled: true, RestartMode: "if_required", RestartWarnMinutes: 15},
	}
	for _, c := range ok {
		if err := c.validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := []threatAutoRemediation{
		{AfterDays: -1},
		{AfterDays: 31},
		// "always" would restart servers whose updates did not need it,
		// with nobody having pressed anything.
		{RestartMode: "always", RestartWarnMinutes: 15},
		{RestartMode: "if_required"},
	}
	for _, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("%+v was accepted", c)
		}
	}
	if d := defaultThreatAutoRemediation(); d.Enabled || !d.OverdueAlerts {
		t.Errorf("defaults %+v: automatic patching must start off and past-due alerts on", d)
	}
}
