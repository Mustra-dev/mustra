package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
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
