package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func restrictedAgent() *Agent {
	return &Agent{noRemoteCode: true, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func commandOf(t *testing.T, cmd proto.AgentCommand) []byte {
	t.Helper()
	raw, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Every command in handleCommand, read from the source so a new one can't be
// missed. Each is refused unless someone put it on the list on purpose.
func TestNoRemoteCodeRefusesEverythingNotListed(t *testing.T) {
	src, err := os.ReadFile("sensor_loop.go")
	if err != nil {
		t.Fatal(err)
	}
	var cases []string
	for _, m := range regexp.MustCompile(`(?m)^\tcase "([a-z_]+)":`).FindAllSubmatch(src, -1) {
		cases = append(cases, string(m[1]))
	}
	if len(cases) < 20 {
		t.Fatalf("found only %d commands; has handleCommand moved?", len(cases))
	}
	a := restrictedAgent()
	refused := 0
	for _, name := range cases {
		if noRemoteCodeCommands[name] {
			continue
		}
		refused++
		res := a.handleCommand(context.Background(), commandOf(t, proto.AgentCommand{Cmd: name}), nil)
		if res.OK || res.Error != errNoRemoteCode.Error() {
			t.Errorf("%s: %+v", name, res)
		}
	}
	// Code, and things that amount to it, must stay off the list.
	for _, must := range []string{"run_deploy", "run_software", "run_enforce", "test_custom_sensor", "update_agent",
		"jit_create", "trust_root", "secret_write", "cert_install", "kill_process", "reveal_scan", "notify_user", "ask_user"} {
		if noRemoteCodeCommands[must] {
			t.Errorf("%s is allowed", must)
		}
		if !slices.Contains(cases, must) {
			t.Errorf("%s is no longer a command; update this test", must)
		}
	}
	if res := a.handleCommand(context.Background(), commandOf(t, proto.AgentCommand{Cmd: "brand_new_thing"}), nil); res.OK || res.Error != errNoRemoteCode.Error() {
		t.Errorf("an unknown command: %+v", res)
	}
}

func TestNoRemoteCodeIsNotTheDefault(t *testing.T) {
	a := &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	res := a.handleCommand(context.Background(), commandOf(t, proto.AgentCommand{Cmd: "brand_new_thing"}), nil)
	if res.Error == errNoRemoteCode.Error() {
		t.Errorf("an ordinary agent refused: %+v", res)
	}
}

func TestPatchNamesCannotBecomeArguments(t *testing.T) {
	for _, bad := range []string{"", "-oDPkg::Pre-Invoke::=id", "--allow-unauthenticated", "pkg;id", "pkg|id", "pkg&id", "$(id)", "`id`",
		"a'b", `a"b`, "a\nb", "a=b", "a*", "a\\b", "a>b", "a%b", strings.Repeat("a", 513)} {
		if checkPatchName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"openssl", "libstdc++6", "linux-image-6.1.0-13-amd64", "python3.11", "bash:amd64", "1:2.3~ubuntu1",
		"macOS Sequoia 15.1-24B83", "2026-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5044284)",
		"Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.419.1)", "Mise à jour"} {
		if err := checkPatchName(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	a := restrictedAgent()
	res := a.handleCommand(context.Background(), commandOf(t, proto.AgentCommand{Cmd: "apply_patches", Patches: []string{"-oDPkg::Pre-Invoke::=id"}}), nil)
	if res.OK || !strings.Contains(res.Error, "refusing package name") {
		t.Errorf("a hostile patch job: %+v", res)
	}
}

func TestNoRemoteCodeLeavesComplianceCommandsUnknown(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	rule := "c:touch " + marker
	if _, known := evaluateRule(withoutCheckCommands(context.Background()), rule); known {
		t.Error("a command rule was evaluated")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the command ran")
	}
	check := proto.ComplianceCheck{ID: "c1", Rules: []string{rule}}
	results := collectCompliance(withoutCheckCommands(context.Background()), []proto.ComplianceCheck{check})
	if len(results) != 1 || results[0].State != "unknown" {
		t.Errorf("results: %+v", results)
	}
}

func TestNoRemoteCodeRefusesUpdatesAndReportsItself(t *testing.T) {
	a := restrictedAgent()
	if _, err := a.startVerifiedUpdate(context.Background(), &proto.UpdateOffer{}); err == nil || err.Error() != errNoRemoteCode.Error() {
		t.Errorf("update: %v", err)
	}
	if !a.currentSettings().NoRemoteCode {
		t.Error("facts do not report the mode")
	}
	// Settings from a server cannot turn it off: they don't reach the field.
	a.settings.current = proto.AgentSettings{NoRemoteCode: false}
	if !a.currentSettings().NoRemoteCode {
		t.Error("stored settings changed the reported mode")
	}
}

// Only New sets the mode. Anything else assigning it would be a way to turn it
// off from outside.
func TestNothingElseSetsNoRemoteCode(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	assign := regexp.MustCompile(`\.noRemoteCode\s*=[^=]`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if assign.Match(src) {
			t.Errorf("%s assigns noRemoteCode", f)
		}
	}
}

func TestDetectNoRemoteCodeLooksBesideTheBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(exe), noRemoteCodeFile)
	if detectNoRemoteCode() {
		t.Fatal("on with no file")
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Skipf("cannot write beside the test binary: %v", err)
	}
	defer os.Remove(path)
	if !detectNoRemoteCode() {
		t.Error("off with the file there")
	}
}

// A patch list's repositories come from the server and go into apt's sources,
// so in this mode they must never be asked for.
func TestNoRemoteCodeIgnoresServerPatchSources(t *testing.T) {
	noRemoteCodeActive.Store(true)
	defer noRemoteCodeActive.Store(false)
	// A nil connection would panic if it were used.
	if got := fetchPatchListOverride(context.Background(), nil, "agt-1"); got.OSFamily != "" || len(got.Repos) != 0 {
		t.Errorf("override: %+v", got)
	}
}

// The second lock: where code runs, whatever path reached it.
func TestNoRemoteCodeStopsCodeWhereItRuns(t *testing.T) {
	noRemoteCodeActive.Store(true)
	defer noRemoteCodeActive.Store(false)
	if _, err := runSoftwareCommand(context.Background(), "true", 0); err == nil || err.Error() != errNoRemoteCode.Error() {
		t.Errorf("software: %v", err)
	}
	if res := executeCustomSensor(context.Background(), proto.CustomSensorDef{}); res.Error != errNoRemoteCode.Error() {
		t.Errorf("custom sensor: %+v", res)
	}
}
