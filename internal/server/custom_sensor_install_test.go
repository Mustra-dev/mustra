package server

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCustomRuntimeInstallSyntax(t *testing.T) {
	data := installScriptData{DownloadBase: "https://example.test", NatsURL: "tls://example.test:4222", AgentVersion: "test"}
	var shell bytes.Buffer
	if err := installShTemplate.Execute(&shell, data); err != nil {
		t.Fatal(err)
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = &shell
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("installer syntax: %s %v", out, err)
		}
	}
	var ps bytes.Buffer
	if err := installPs1Template.Execute(&ps, data); err != nil {
		t.Fatal(err)
	}
	if pwsh, err := exec.LookPath("pwsh"); err == nil {
		path := filepath.Join(t.TempDir(), "install.ps1")
		if err = os.WriteFile(path, ps.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", `$tokens=$null;$errors=$null;$null=[System.Management.Automation.Language.Parser]::ParseFile($env:MUSTRA_TEST_SCRIPT_PATH,[ref]$tokens,[ref]$errors);if($errors.Count){$errors | ForEach-Object {$_.Message};exit 1}`)
		cmd.Env = append(os.Environ(), "MUSTRA_TEST_SCRIPT_PATH="+path)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Windows installer syntax: %s %v", out, err)
		}
	}
}
