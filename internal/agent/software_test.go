package agent

import (
	"strings"
	"testing"
)

// winget is an app execution alias in the *user's* WindowsApps directory,
// and the agent is a service running as LocalSystem — whose LOCALAPPDATA is
// C:\Windows\System32\config\systemprofile\AppData\Local and has no such
// alias. So a command that works in an admin's PowerShell reports "not
// recognized" from a package, which reads as mustra being broken.
func TestWingetPreambleOnlyWhenItCouldMatter(t *testing.T) {
	for _, c := range []struct {
		command string
		want    bool
	}{
		{"winget install --id Microsoft.VisualStudioCode", true},
		{"WINGET upgrade --all", true},          // operators do not type consistently
		{"& winget.exe list", true},             // and do not always type it bare
		{"choco install vscode", false},         // another package manager entirely
		{"Restart-Service mustra-agent", false}, // the common case pays nothing
	} {
		if got := needsWinget(c.command); got != c.want {
			t.Errorf("needsWinget(%q) = %v, want %v", c.command, got, c.want)
		}
	}
}

func TestWingetPreambleLeavesAnExistingWingetAlone(t *testing.T) {
	// The guard matters: on an endpoint where a working winget is on PATH — a
	// per-machine install, or a future Windows that ships it for services —
	// the preamble must not shadow it with an older copy it dug out of
	// WindowsApps.
	// It must also not trust a winget that resolves but cannot start, as
	// the SYSTEM profile's alias on Windows Server does.
	if !strings.HasPrefix(wingetPreamble, "$wingetWorks = $false") || !strings.Contains(wingetPreamble, "--version") || !strings.Contains(wingetPreamble, "if (-not $wingetWorks)") {
		t.Fatal("the preamble must no-op when winget already resolves and runs")
	}
	if !strings.Contains(wingetPreamble, "Sort-Object") {
		t.Error("with several App Installer versions present, the newest has to win")
	}
}
