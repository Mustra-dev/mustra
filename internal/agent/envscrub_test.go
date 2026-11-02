package agent

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestSecretEnvKeys(t *testing.T) {
	for _, k := range []string{"MUSTRA_NATS_PASSWORD", "BEACON_NATS_PASSWORD", "MUSTRA_NATS_USER", "MUSTRA_ENROLL_TOKEN",
		"MUSTRA_AGENT_SIGNING_KEY", "mustra_nats_password", "MUSTRA_NATS_CALLOUT_SEED_SECRET"} {
		if !isSecretEnvKey(k) {
			t.Errorf("%s is not treated as secret", k)
		}
	}
	for _, k := range []string{"PATH", "HOME", "MUSTRA_NATS_URL", "MUSTRA_SITE", "MUSTRA_PACKAGE_DIR", "TOKEN", "AWS_SECRET_KEY"} {
		if isSecretEnvKey(k) {
			t.Errorf("%s is treated as secret", k)
		}
	}
}

func TestRedactCmdline(t *testing.T) {
	in := "curl -fsSL -H Authorization: Bearer mte_wH6v4JqCvvNP4jL0pYkiL3PA95pt7uGoQTDJCLaTS1I https://c/install.sh"
	out := redactCmdline(in)
	if strings.Contains(out, "wH6v4") || !strings.Contains(out, "mte_[redacted]") {
		t.Fatalf("token not redacted: %s", out)
	}
	if redactCmdline("/usr/bin/sleep 30") != "/usr/bin/sleep 30" {
		t.Fatal("ordinary command line changed")
	}
}

// S4: a command the agent runs must not see the bus credential, whatever
// put it in the agent's environment.
func TestChildProcessesDoNotInheritCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses env(1)")
	}
	t.Setenv("MUSTRA_NATS_PASSWORD", "fleet-password-xyz")
	t.Setenv("BEACON_NATS_PASSWORD", "fleet-password-xyz")
	t.Setenv("MUSTRA_ENROLL_TOKEN", "mte_token-xyz")
	t.Setenv("MUSTRA_SITE", "visible")
	out, err := runSoftwareCommand(context.Background(), "env", 0)
	if err != nil {
		t.Fatalf("env: %v\n%s", err, out)
	}
	if strings.Contains(out, "fleet-password-xyz") || strings.Contains(out, "mte_token-xyz") {
		t.Fatal("a package command inherited the agent's credential")
	}
	if !strings.Contains(out, "MUSTRA_SITE=visible") {
		t.Fatal("ordinary environment was dropped too")
	}

	ScrubSecretEnv()
	for _, k := range []string{"MUSTRA_NATS_PASSWORD", "BEACON_NATS_PASSWORD", "MUSTRA_ENROLL_TOKEN"} {
		if _, ok := os.LookupEnv(k); ok {
			t.Errorf("%s survived ScrubSecretEnv", k)
		}
	}
	if os.Getenv("MUSTRA_SITE") != "visible" {
		t.Error("ScrubSecretEnv removed a non-secret variable")
	}
}
