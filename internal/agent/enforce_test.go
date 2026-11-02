package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func linuxOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell commands as remediations")
	}
}

// posix gives the same shell remediation to both POSIX platforms, so the
// tests exercise the remediation path on a developer's Mac exactly as they
// do on the Linux box CI runs. Before this they set only the Linux command
// and failed on macOS with "no remediation defined for darwin", which reads
// like a product bug rather than a test assumption.
func posix(s proto.EnforceSetting, cmd string) proto.EnforceSetting {
	s.RemediateLinux = cmd
	s.RemediateDarwin = cmd
	return s
}

func TestEnforceCompliantDoesNothing(t *testing.T) {
	linuxOnly(t)
	path := filepath.Join(t.TempDir(), "present")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := enforceSetting(context.Background(), posix(proto.EnforceSetting{
		ID: "s1", Name: "file is present", Rules: []string{"f:" + path},
		Enforce: true,
	}, "echo SHOULD NOT RUN"))
	if res.State != "compliant" {
		t.Fatalf("state = %q, want compliant (%s)", res.State, res.Detail)
	}
	if res.Output != "" {
		t.Errorf("a compliant setting must not run its remediation; got output %q", res.Output)
	}
}

// Report mode is the default and the whole safety story: it must observe
// the drift and touch nothing.
func TestEnforceReportModeNeverRemediates(t *testing.T) {
	linuxOnly(t)
	path := filepath.Join(t.TempDir(), "missing")
	res := enforceSetting(context.Background(), posix(proto.EnforceSetting{
		ID: "s1", Name: "file is present", Rules: []string{"f:" + path},
		Enforce: false,
	}, "touch "+path))
	if res.State != "drifted" {
		t.Fatalf("state = %q, want drifted", res.State)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("report mode created the file; it must not change anything")
	}
}

func TestEnforceRemediatesAndReVerifies(t *testing.T) {
	linuxOnly(t)
	path := filepath.Join(t.TempDir(), "wanted")
	res := enforceSetting(context.Background(), posix(proto.EnforceSetting{
		ID: "s1", Name: "file is present", Rules: []string{"f:" + path},
		Enforce: true,
	}, "touch "+path))
	if res.State != "remediated" {
		t.Fatalf("state = %q, want remediated (%s)", res.State, res.Detail)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("claimed remediated but the file is still missing: %v", err)
	}
}

// The one that matters most. A remediation exiting zero is not evidence
// the setting took: `systemctl enable ufw` succeeds where ufw is not
// installed. Trusting the exit code produces a console that is green and a
// fleet that is wrong, which is worse than visible non-compliance because
// nobody goes looking.
func TestEnforceExitZeroIsNotEvidence(t *testing.T) {
	linuxOnly(t)
	path := filepath.Join(t.TempDir(), "never-created")
	res := enforceSetting(context.Background(), posix(proto.EnforceSetting{
		ID: "s1", Name: "file is present", Rules: []string{"f:" + path},
		Enforce: true,
	}, "true")) // succeeds, changes nothing
	if res.State != "failed" {
		t.Fatalf("state = %q, want failed", res.State)
	}
	if !strings.Contains(res.Detail, "still wrong") {
		t.Errorf("detail should say the command succeeded but the setting did not take, got: %q", res.Detail)
	}
}

func TestEnforceFailedCommandIsFailed(t *testing.T) {
	linuxOnly(t)
	path := filepath.Join(t.TempDir(), "never-created")
	res := enforceSetting(context.Background(), posix(proto.EnforceSetting{
		ID: "s1", Name: "file is present", Rules: []string{"f:" + path},
		Enforce: true,
	}, "exit 3"))
	if res.State != "failed" {
		t.Fatalf("state = %q, want failed", res.State)
	}
}

// A command that reports failure but does the job is worth flagging, not
// hiding: it is a remediation somebody should look at.
func TestEnforceNoisyButEffectiveRemediationIsRemediated(t *testing.T) {
	linuxOnly(t)
	path := filepath.Join(t.TempDir(), "wanted")
	res := enforceSetting(context.Background(), posix(proto.EnforceSetting{
		ID: "s1", Name: "file is present", Rules: []string{"f:" + path},
		Enforce: true,
	}, "touch "+path+"; exit 1"))
	if res.State != "remediated" {
		t.Fatalf("state = %q, want remediated", res.State)
	}
	if !strings.Contains(res.Detail, "reported an error") {
		t.Errorf("detail should mention the command reported an error, got: %q", res.Detail)
	}
}

// A setting with no fix for this platform reports drift. Pretending it was
// handled would be the same false assurance "unknown" exists to prevent.
func TestEnforceWithoutARemediationForThisPlatform(t *testing.T) {
	linuxOnly(t)
	path := filepath.Join(t.TempDir(), "missing")
	res := enforceSetting(context.Background(), proto.EnforceSetting{
		ID: "s1", Name: "file is present", Rules: []string{"f:" + path},
		RemediateWindows: "New-Item " + path, Enforce: true,
	})
	if res.State != "drifted" {
		t.Fatalf("state = %q, want drifted", res.State)
	}
	if !strings.Contains(res.Detail, "no remediation defined") {
		t.Errorf("detail should say why nothing was attempted, got: %q", res.Detail)
	}
}

// A rule nobody could evaluate is not a drift, and remediating on an answer
// we do not have is how enforcement breaks machines.
func TestEnforceUnknownIsNeverRemediated(t *testing.T) {
	linuxOnly(t)
	marker := filepath.Join(t.TempDir(), "ran")
	res := enforceSetting(context.Background(), posix(proto.EnforceSetting{
		ID: "s1", Name: "gibberish", Rules: []string{"this is not a rule"},
		Enforce: true,
	}, "touch "+marker))
	if res.State != "unknown" {
		t.Fatalf("state = %q, want unknown", res.State)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("remediated a setting whose state could not be determined")
	}
}
