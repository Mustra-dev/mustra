package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/proto"
)

// The events a real failed run logged (an action whose apt-get could not
// find the package), and an earlier step that succeeded: the result names
// the failing step, its exit code and the error, not "exit status 100".
func TestDeployFailureDetail(t *testing.T) {
	dir := t.TempDir()
	l, err := deploylog.Open(dir, proto.DeployLogSettings{ArchiveMB: 100, RotateMB: 1, CompressFiles: 5})
	if err != nil {
		t.Fatal(err)
	}
	code := func(n int) *int { return &n }
	at := time.Now()
	evs := []proto.DeployEvent{
		{JobID: "act-1", StepID: "s_prep", Stage: "stdout", Message: "preparing"},
		{JobID: "act-1", StepID: "s_prep", Stage: "stderr", Message: "warning: something harmless"},
		{JobID: "act-1", StepID: "s_prep", Stage: "execution_result", ExitCode: code(0), Message: "Command exited with code 0"},
		{JobID: "act-other", StepID: "s_x", Stage: "stderr", Message: "another job's error"},
		{JobID: "act-1", StepID: "s_run", Stage: "stdout", Message: "Reading package lists..."},
		{JobID: "act-1", StepID: "s_run", Stage: "stdout", Message: "Building dependency tree..."},
		{JobID: "act-1", StepID: "s_run", Stage: "stderr", Message: "E: Unable to locate package cloudflared"},
		{JobID: "act-1", StepID: "s_run", Stage: "execution_result", ExitCode: code(100), Message: "Command exited with code 100"},
		{JobID: "act-1", StepID: "s_run", Stage: "command", Message: "exit status 100"},
	}
	for i, ev := range evs {
		ev.Status, ev.Timestamp = "running", at.Add(time.Duration(i)*time.Millisecond)
		raw, _ := json.Marshal(ev)
		if _, err := l.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	job := proto.DeployJob{ID: "act-1", Packages: []proto.DeployPackagePlan{{Variant: proto.DeployVariant{Actions: map[string]proto.DeployAction{
		"run": {Steps: []proto.DeployStep{{ID: "s_prep", Name: "Prepare"}, {ID: "s_run", Name: "Upgrade cloudflared"}}},
	}}}}}
	final := proto.DeployEvent{JobID: "act-1", Stage: "complete", Status: "failed", Message: "exit status 100"}

	got := deployFailureDetail(context.Background(), dir, job, final)
	first, _, _ := strings.Cut(got, "\n")
	if first != `Step "Upgrade cloudflared" exited with code 100: E: Unable to locate package cloudflared` {
		t.Fatalf("first line %q\n%s", first, got)
	}
	for _, want := range []string{"Errors (last lines):\nE: Unable to locate package cloudflared", "Output (last lines):\nReading package lists...\nBuilding dependency tree...", "Agent: exit status 100"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, not := range []string{"something harmless", "another job"} {
		if strings.Contains(got, not) {
			t.Errorf("%q leaked into\n%s", not, got)
		}
	}

	// Nothing logged for the job: what the agent said.
	if got := deployFailureDetail(context.Background(), t.TempDir(), proto.DeployJob{ID: "act-none"}, final); got != "The run failed: exit status 100" {
		t.Errorf("no log: %q", got)
	}
	timedOut := proto.DeployEvent{JobID: "act-1", Status: "timed_out", Message: "step exceeded 900s"}
	if got := deployFailureDetail(context.Background(), dir, job, timedOut); !strings.HasPrefix(got, `Step "Upgrade cloudflared" timed out: E: Unable to locate`) || !strings.Contains(got, "Agent: step exceeded 900s") {
		t.Errorf("timed out: %q", got)
	}
}
