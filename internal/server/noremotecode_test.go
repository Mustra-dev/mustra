package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func TestRefusedDeployEndsTheJobOnlyOnARefusal(t *testing.T) {
	refusal := proto.AgentCommandResult{Error: proto.NoRemoteCodeRefusal}
	if status, detail, refused := refusedDeploy(refusal, false); !refused || status != "failed" || detail != proto.NoRemoteCodeRefusal {
		t.Fatalf("refusal: %q %q %v", status, detail, refused)
	}
	if status, _, refused := refusedDeploy(refusal, true); !refused || status != "cancelled" {
		t.Fatalf("refused cancel: %q %v", status, refused)
	}
	for _, reply := range []proto.AgentCommandResult{{OK: true}, {Error: "invalid deployment target"}, {}} {
		if _, _, refused := refusedDeploy(reply, false); refused {
			t.Fatalf("%+v must keep being retried", reply)
		}
	}
}

func TestShellErrorIsNotRecordedAsSuccess(t *testing.T) {
	for _, c := range []struct {
		reply  proto.ShellReply
		code   int
		output string
	}{
		{proto.ShellReply{Error: proto.NoRemoteCodeRefusal}, -1, "error: " + proto.NoRemoteCodeRefusal},
		{proto.ShellReply{Output: "partial", Error: "timed out", ExitCode: 124}, 124, "partial\nerror: timed out"},
		{proto.ShellReply{Output: "ok"}, 0, "ok"},
		{proto.ShellReply{Output: "nope", ExitCode: 2}, 2, "nope"},
	} {
		if got := shellExitCode(c.reply); got != c.code {
			t.Errorf("%+v: exit %d", c.reply, got)
		}
		if got := shellLogOutput(c.reply); got != c.output {
			t.Errorf("%+v: output %q", c.reply, got)
		}
	}
}

func TestSettingsRefuseCode(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"no_remote_code":true}`: true,
		`{"log_level":"info"}`:    false,
		``:                        false,
		`not json`:                false,
	} {
		if got := settingsRefuseCode(json.RawMessage(raw)); got != want {
			t.Errorf("%q: %v", raw, got)
		}
	}
}

// TCC answers per binary, so the script can only ever test itself.
func TestInstallShDoesNotJudgeFullDiskAccess(t *testing.T) {
	var out bytes.Buffer
	if err := installShTemplate.Execute(&out, installScriptData{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"TCC.db", "is NOT granted"} {
		if strings.Contains(out.String(), bad) {
			t.Errorf("install.sh contains %q", bad)
		}
	}
}

func TestHuntCompletionIsNotFailedByFindings(t *testing.T) {
	_, outcome, severity, body := huntCompletion(3)
	if outcome != "succeeded" || severity != "info" || !strings.Contains(body, "3 new findings") {
		t.Fatalf("%q %q %q", outcome, severity, body)
	}
}

func TestRevealCompletion(t *testing.T) {
	now := time.Now()
	rows := []store.RevealScan{
		{FinishedAt: &now, FilesMatched: 2},
		{FinishedAt: &now, Error: "unknown command"},
		{},
	}
	title, outcome, severity, body, detail := revealCompletion(store.RevealRule{Name: "Card numbers", Kind: "rule"}, rows, 3)
	if title != "Sensitive-data scan finished: Card numbers" || outcome != "partial" || severity != "warning" {
		t.Errorf("%q %q %q", title, outcome, severity)
	}
	if body != "1 of 3 endpoints finished. 2 files matched." || detail["failed"] != 2 || detail["files_matched"] != 2 {
		t.Errorf("%q %v", body, detail)
	}
	// What a search looks for can be the sensitive part.
	title, _, _, _, detail = revealCompletion(store.RevealRule{Name: "my-secret-term", Kind: "quick"}, rows, 3)
	if strings.Contains(title, "my-secret-term") || detail["name"] != "Quick search" {
		t.Errorf("quick search leaked its terms: %q %v", title, detail)
	}
}

func TestCompletedActionsAcceptHuntAndReveal(t *testing.T) {
	if got, err := parseCompletedFilter("hunt,reveal"); err != nil || got != "hunt,reveal" {
		t.Fatalf("%q %v", got, err)
	}
}

func installScriptFor(t *testing.T, noRemoteCode bool) string {
	t.Helper()
	var out bytes.Buffer
	if err := installShTemplate.Execute(&out, installScriptData{NoRemoteCode: noRemoteCode, Pins: map[string]string{"mustra-haos-addon.tar.gz": "abc"}}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestHAOSInstallHoldsTheAddonToItsHash(t *testing.T) {
	script := installScriptFor(t, false)
	if !strings.Contains(script, "addon_expected=$(pinned_sha mustra-haos-addon.tar.gz)") {
		t.Error("the add-on is not checked")
	}
	if strings.Contains(script, "tar.gz\" | tar") {
		t.Error("the add-on is unpacked as it downloads, before any check")
	}
	// Called before the end of the script, so they must be defined before it.
	if strings.Index(script, "pinned_sha() {") > strings.Index(script, "install_haos_addon() {") {
		t.Error("pinned_sha is defined after the add-on installer that calls it")
	}
	if strings.Contains(script, "no_remote_code=true") {
		t.Error("a normal install turned the mode on")
	}
	if !strings.Contains(installScriptFor(t, true), "no_remote_code=true") {
		t.Error("the mode did not reach the add-on")
	}
}

func TestHAOSAddonRunsOnlyTheApprovedInstaller(t *testing.T) {
	run, err := haosAddonFiles.ReadFile("haosaddon/run.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(run)
	check := strings.Index(s, `!= "$install_sha256"`)
	install := strings.Index(s, "MUSTRA_NO_SERVICE=1 bash /tmp/install.sh")
	if check < 0 || install < 0 || check > install {
		t.Fatalf("the installer can run before its hash is checked (%d, %d)", check, install)
	}
	if !strings.Contains(s, `[ "$no_remote_code" != true ] && [ -f "$agent.verified" ]`) {
		t.Error("a restricted add-on can still install an agent update")
	}
}
