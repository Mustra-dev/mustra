package server

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

const ingestAgent = "agt-0123456789abcdef0123456789abcdef"

func TestAttributeFromSubject(t *testing.T) {
	subj := bnats.AgentSensor(ingestAgent, "processes")
	if id, err := attributeFromSubject(subj, ""); err != nil || id != ingestAgent {
		t.Fatalf("empty claim: %q %v", id, err)
	}
	if _, err := attributeFromSubject(subj, ingestAgent); err != nil {
		t.Fatalf("matching claim refused: %v", err)
	}
	if _, err := attributeFromSubject(subj, "agt-ffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("a body claiming another agent was accepted")
	}
	if _, err := attributeFromSubject("beacon.agent.x.facts", ""); err == nil {
		t.Fatal("malformed agent id in subject accepted")
	}
}

// The stored-XSS shape from the web review: a string where the type says
// a number. It must not survive into storage.
func TestNormalizeRejectsAttackerShapedProcessRows(t *testing.T) {
	bad := json.RawMessage(`[{"pid":"1\"><img src=x onerror=alert(1)>","name":"init","ppid":0}]`)
	if _, err := normalizeSnapshotData(proto.SensorProcesses, bad); err == nil {
		t.Fatal("string pid accepted")
	}
	bad = json.RawMessage(`[{"pid":2,"ppid":"1\"><img src=x>","name":"child"}]`)
	if _, err := normalizeSnapshotData(proto.SensorProcesses, bad); err == nil {
		t.Fatal("string ppid accepted")
	}
	good := json.RawMessage(`[{"pid":2,"ppid":1,"name":"child","extra":"<script>"}]`)
	out, err := normalizeSnapshotData(proto.SensorProcesses, good)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "extra") {
		t.Errorf("unknown field survived normalization: %s", out)
	}
}

func TestNormalizeKinds(t *testing.T) {
	if _, err := normalizeSnapshotData("no_such_kind", json.RawMessage(`[]`)); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := normalizeSnapshotData("custom_a.b", json.RawMessage(`[]`)); err == nil {
		t.Error("malformed kind accepted")
	}
	// The kind every real custom sensor reports under (ID from idgen "csn-"),
	// with the result object an agent actually publishes.
	out, err := normalizeSnapshotData("custom_csn-3c187816c9b46e0167b648d3d340c5f6",
		json.RawMessage(`{"revision":"r1","lines":["no reboot pending"],"exit_code":0,"stray":{"x":1}}`))
	if err != nil {
		t.Fatalf("custom sensor result refused: %v", err)
	}
	var res proto.CustomSensorResult
	if err := json.Unmarshal(out, &res); err != nil || len(res.Lines) != 1 || res.Revision != "r1" {
		t.Errorf("custom sensor result not preserved: %s %v", out, err)
	}
	if strings.Contains(string(out), "stray") {
		t.Errorf("unknown custom result field kept: %s", out)
	}
	// A bare row list is not what agents send; it must not decode as a result.
	if _, err := normalizeSnapshotData("custom_abc", json.RawMessage(`[{"a":1}]`)); err == nil {
		t.Error("custom row list accepted as a result")
	}
	// The old single-object privileges shape is still accepted.
	if out, err := normalizeSnapshotData(proto.SensorPrivileges, json.RawMessage(`{}`)); err != nil || !strings.HasPrefix(string(out), "[") {
		t.Errorf("legacy privileges object: %s %v", out, err)
	}
}

func TestNormalizeFactsSettings(t *testing.T) {
	f := proto.Facts{Site: "a b<c>", Settings: &proto.AgentSettings{LogLevel: "<img src=x>", SensorIntervalSeconds: -5}}
	normalizeFacts(&f)
	if f.Settings.LogLevel != "" || f.Settings.SensorIntervalSeconds != 0 {
		t.Errorf("settings not bounded: %+v", f.Settings)
	}
	if !validSite(f.Site) {
		t.Errorf("site not sanitized: %q", f.Site)
	}
	f = proto.Facts{Settings: &proto.AgentSettings{LogLevel: "debug"}}
	normalizeFacts(&f)
	if f.Settings.LogLevel != "debug" || f.Site != "" {
		t.Errorf("valid facts changed: %+v", f)
	}
}

func TestValidatePublicURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://console.example.com":       "https://console.example.com",
		"https://console.example.com/":      "https://console.example.com",
		"https://198.51.100.7:8443":         "https://198.51.100.7:8443",
		" https://Console.Example.com:443 ": "https://Console.Example.com:443",
	} {
		got, err := validatePublicURL(in, false)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v", in, got, err)
		}
	}
	for _, in := range []string{
		"http://console.example.com", "ftp://x", "https://user:pw@x.example", "https://x.example/sub",
		"https://x.example?q=1", "https://x.example#f", "https://ev$(id).example", "https://x.example:8a",
		"https://'x.example", "javascript:alert(1)", "",
	} {
		if _, err := validatePublicURL(in, false); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := validatePublicURL("http://192.0.2.10:8080", true); err != nil {
		t.Errorf("explicit dev http refused: %v", err)
	}
}

func TestSiteValidation(t *testing.T) {
	for _, s := range []string{"default", "branch-1", "HQ_2"} {
		if !validSite(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "a.b", "$(id)", "a b", "x'y", strings.Repeat("a", 65), "a\"b", "a`b"} {
		if validSite(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// shQuote and psQuoteString must make the shell treat any value as data.
func TestQuotingIsInert(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, v := range []string{"plain", "it's", "$(touch /tmp/pwned)", "`id`", "a'; id; echo '", "\"$HOME\"", "x\ny"} {
		out, err := exec.Command("bash", "-c", "printf %s "+shQuote(v)).Output()
		if err != nil || string(out) != v {
			t.Errorf("shQuote(%q) ran as %q (%v)", v, out, err)
		}
	}
	if got := psQuoteString("a'b’c"); got != "'a''b’’c'" {
		t.Errorf("psQuoteString: %q", got)
	}
}

func TestAgentBuildPlatform(t *testing.T) {
	for name, want := range map[string][2]string{
		"mustra-agent-linux-amd64":       {"linux", "amd64"},
		"mustra-agent-windows-arm64.exe": {"windows", "arm64"},
		"mustra-tray-windows-amd64.exe":  {"windows", "amd64"},
	} {
		goos, goarch, ok := agentBuildPlatform(name)
		if !ok || goos != want[0] || goarch != want[1] {
			t.Errorf("%s: %s %s %v", name, goos, goarch, ok)
		}
	}
	for _, name := range []string{"mustra-agent-linux-amd64.exe", "mustra-agent-windows-amd64", "mustra-python-linux-amd64.tar.gz", "mustra-agent-plan9-amd64"} {
		if _, _, ok := agentBuildPlatform(name); ok {
			t.Errorf("%s accepted", name)
		}
	}
}
