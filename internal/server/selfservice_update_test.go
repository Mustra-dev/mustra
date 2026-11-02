package server

import (
	"strings"
	"testing"
)

// An agent from before signed updates updates by running the installer,
// which rewrites the service with the script's site. Without ?site= that
// was the default, and the console update moved the endpoint out of its
// site (found upgrading a 0.54.1 fleet: lab and homelab both became
// default).
func TestLegacyUpdateCommandKeepsTheEndpointsSite(t *testing.T) {
	base := "https://console.example"
	cases := []struct {
		os, site, want string
	}{
		{"linux", "lab", `curl -fsSL 'https://console.example/install.sh?site=lab' | bash`},
		{"darwin", "homelab", `curl -fsSL 'https://console.example/install.sh?site=homelab' | bash`},
		{"windows", "branch_2", `irm 'https://console.example/install.ps1?site=branch_2' -UseBasicParsing -OutFile $env:TEMP\mustra-install.ps1; & $env:TEMP\mustra-install.ps1`},
		// A site the installer would refuse is left out instead of failing the update.
		{"linux", "a b';id", `curl -fsSL 'https://console.example/install.sh' | bash`},
		{"linux", "", `curl -fsSL 'https://console.example/install.sh' | bash`},
		{"plan9", "lab", ""},
	}
	for _, c := range cases {
		if got := legacyUpdateCommand(base, c.os, c.site); got != c.want {
			t.Errorf("legacyUpdateCommand(%q, %q) = %q, want %q", c.os, c.site, got, c.want)
		}
	}
}

func TestUnversionedAgentBuildNamesTheRealProblem(t *testing.T) {
	if msg := unversionedAgentBuild("0.55.0", "0.54.1"); msg != "" {
		t.Errorf("versioned builds: %q", msg)
	}
	if msg := unversionedAgentBuild("dev", ""); msg != "" {
		t.Errorf("endpoint without a recorded version is left to the existing rule: %q", msg)
	}
	if msg := unversionedAgentBuild("dev", "0.54.1"); !strings.Contains(msg, "serves agent build \"dev\"") || !strings.Contains(msg, "AGENT_VERSION") {
		t.Errorf("dev server: %q", msg)
	}
	if msg := unversionedAgentBuild("d7ef441", "0.54.1"); !strings.Contains(msg, "d7ef441") {
		t.Errorf("untagged git describe: %q", msg)
	}
	if msg := unversionedAgentBuild("0.55.0", "dev"); !strings.Contains(msg, "endpoint runs agent build \"dev\"") || !strings.Contains(msg, "enrollment token") {
		t.Errorf("dev endpoint: %q", msg)
	}
}
