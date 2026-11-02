package mustra

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runInitPreflight runs a copy of deploy/init.sh in a scratch directory,
// with an optional .env, on a PATH holding only what the script needs
// before its docker preflight. docker is deliberately absent, so a script
// that gets that far stops there, at a check that names itself, having
// touched nothing.
func runInitPreflight(t *testing.T, env string) (int, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	script, err := os.ReadFile("deploy/init.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "init.sh"), script, 0o755); err != nil {
		t.Fatal(err)
	}
	if env != "" {
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := t.TempDir()
	for _, tool := range []string{"dirname", "sed", "head"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not available", tool)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "openssl"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bash, filepath.Join(dir, "init.sh"), "--ip", "192.0.2.5")
	cmd.Env = []string{"PATH=" + bin, "HOME=" + dir}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

// A fresh checkout has no .env. Looking up a port it would have recorded
// must fall back to the default, not end the script: under set -e a failed
// lookup in the assignment exited 1 before printing anything, and the quick
// start failed at its first step without a word (#17).
func TestInitScriptRunsWithoutEnvFile(t *testing.T) {
	code, out := runInitPreflight(t, "")
	if code != 1 || !strings.Contains(out, "docker is required") {
		t.Fatalf("want the docker preflight to stop it (exit 1, \"docker is required\"); got exit %d, output %q", code, out)
	}
}

// An existing install's .env still decides the ports: the value is read,
// and a bad one is refused by name.
func TestInitScriptReadsPortsFromEnvFile(t *testing.T) {
	code, out := runInitPreflight(t, "MUSTRA_CONSOLE_PORT=80x0\n")
	if code != 2 || !strings.Contains(out, "port '80x0' is not a number") {
		t.Fatalf("want the .env port rejected (exit 2); got exit %d, output %q", code, out)
	}
}
