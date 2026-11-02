package enforcekinds

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDefaultsCompile(t *testing.T) {
	for _, k := range Kinds() {
		settings, err := Compile(k.Kind, mustJSON(t, k.Defaults))
		if err != nil {
			t.Fatalf("%s defaults do not compile: %v", k.Kind, err)
		}
		if len(settings) == 0 {
			t.Fatalf("%s defaults produce no settings", k.Kind)
		}
		ids := map[string]bool{}
		for _, s := range settings {
			if s.ID == "" || s.Name == "" || len(s.Rules) == 0 {
				t.Errorf("%s: incomplete setting %+v", k.Kind, s)
			}
			if ids[s.ID] {
				t.Errorf("%s: duplicate setting id %s", k.Kind, s.ID)
			}
			ids[s.ID] = true
			for _, r := range s.Rules {
				if !strings.HasPrefix(r, "c:") || !strings.Contains(r, " -> ") {
					t.Errorf("%s: rule is not a command rule with a matcher: %q", k.Kind, r)
				}
			}
		}
	}
}

func TestFirewallRuleCompiles(t *testing.T) {
	c := DefaultFirewall()
	c.Rules = []FirewallRule{{Name: "RDP from LAN", Direction: "in", Action: "allow", Protocol: "tcp", LocalPorts: "3389", RemoteAddresses: "192.0.2.0/24", Enabled: true}}
	settings, err := Compile(KindFirewall, mustJSON(t, c))
	if err != nil {
		t.Fatal(err)
	}
	var rule string
	var fix string
	for _, s := range settings {
		if strings.HasPrefix(s.Name, "Firewall rule:") {
			rule, fix = s.Rules[0], s.RemediateWindows
		}
	}
	if !strings.HasSuffix(rule, " -> Inbound/Allow/True/TCP/3389/192.0.2.0/24") {
		t.Errorf("rule check matcher wrong: %s", rule)
	}
	if !strings.Contains(fix, "New-NetFirewallRule -DisplayName 'mustra: RDP from LAN' -Direction Inbound -Action Allow -Protocol TCP -Enabled True -Profile Any -LocalPort 3389 -RemoteAddress 192.0.2.0/24") {
		t.Errorf("fix wrong: %s", fix)
	}
	// Deterministic ids survive a re-save.
	again, _ := Compile(KindFirewall, mustJSON(t, c))
	for i := range settings {
		if settings[i].ID != again[i].ID {
			t.Errorf("setting id changed between compiles: %s vs %s", settings[i].ID, again[i].ID)
		}
	}
	c.Rules[0].LocalPorts = "99999"
	if _, err := Compile(KindFirewall, mustJSON(t, c)); err == nil {
		t.Error("an impossible port should be refused")
	}
	c.Rules[0].LocalPorts = "22"
	c.Rules[0].RemoteAddresses = "not an address"
	if _, err := Compile(KindFirewall, mustJSON(t, c)); err == nil {
		t.Error("a bad address should be refused")
	}
}

func TestBitLockerChoices(t *testing.T) {
	c := DefaultBitLocker()
	c.RequireTPM, c.AllowWithoutTPM = true, true
	if _, err := Compile(KindBitLocker, mustJSON(t, c)); err == nil {
		t.Error("require TPM and allow without TPM together should be refused")
	}
	c = DefaultBitLocker()
	c.RequireTPM, c.AllowWithoutTPM = false, true
	settings, err := Compile(KindBitLocker, mustJSON(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(settings[0].RemediateWindows, "EnableBDEWithNoTPM") || !strings.Contains(settings[0].RemediateWindows, "-RecoveryPasswordProtector -SkipHardwareTest") || !strings.Contains(settings[0].RemediateWindows, "Install-WindowsFeature BitLocker") {
		t.Errorf("no-TPM path should set the FVE policy and use a recovery password: %s", settings[0].RemediateWindows)
	}
	// Completion is report-only so an encrypting machine is drift, not a
	// failure that burns attempts.
	if settings[1].RemediateWindows != "" {
		t.Error("the completion setting must not remediate")
	}
}

func TestAppLockerXML(t *testing.T) {
	c := DefaultAppLocker()
	c.Mode = "enforce"
	c.Rules = []AppLockerRule{
		{Type: "path", Action: "deny", Value: `%OSDRIVE%\Users\*\Downloads\*`, Description: "No running from Downloads"},
		{Type: "publisher", Action: "allow", Value: "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US", Collection: "exe"},
		{Type: "hash", Action: "allow", Value: strings.Repeat("ab", 32) + "|tool.exe|1234", Collection: "script"},
	}
	xml, err := AppLockerXML(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`<RuleCollection Type="Exe" EnforcementMode="Enabled">`, `Name="mustra: No running from Downloads"`, `Action="Deny"`, `PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*"`, `<FileHash Type="SHA256" Data="0x` + strings.ToUpper(strings.Repeat("ab", 32)) + `" SourceFileName="tool.exe" SourceFileLength="1234"/>`, `UserOrGroupSid="S-1-5-32-544"`} {
		if !strings.Contains(xml, want) {
			t.Errorf("xml lacks %s\n%s", want, xml)
		}
	}
	settings, err := Compile(KindAppLocker, mustJSON(t, c))
	if err != nil {
		t.Fatal(err)
	}
	// Exe collection: 3 defaults + 2 rules (path defaults to exe, publisher exe).
	found := false
	for _, s := range settings {
		if strings.Contains(s.Name, "Exe rules are enforced with 5 managed rule(s)") {
			found = true
		}
	}
	if !found {
		for _, s := range settings {
			t.Log(s.Name)
		}
		t.Error("expected the Exe collection to count 5 managed rules")
	}
	c.Rules[2].Value = "nothex"
	if _, err := Compile(KindAppLocker, mustJSON(t, c)); err == nil {
		t.Error("a bad hash should be refused")
	}
}
