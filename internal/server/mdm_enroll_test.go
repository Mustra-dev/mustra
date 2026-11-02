package server

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// TestValidateMDMEnrollURL pins what may reach install.sh. The value lands
// inside single quotes in a script run as root on every Mac, so anything
// that could end the quoting is refused rather than escaped.
func TestValidateMDMEnrollURL(t *testing.T) {
	ok := []string{
		"",
		"https://fleet.example.com/enroll?enroll_secret=EXAMPLEexampleEXAMPLEexample0000",
		"https://mdm.example.com:8443/enroll",
	}
	for _, u := range ok {
		if err := validateMDMEnrollURL(u); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	bad := []string{
		"http://fleet.example.com/enroll",         // not https
		"fleet.example.com/enroll",                // no scheme or host
		"https:///enroll",                         // no host
		"https://x.example.com/a'; rm -rf / #",    // ends the quoting
		"https://x.example.com/a b",               // whitespace
		"https://x.example.com/a\nrm -rf /",       // newline
		"https://x.example.com/\\",                // backslash
		"https://x.example.com/café",              // non-ASCII
		"file:///etc/passwd",                      // open(1) would read it
		"x-apple.systempreferences:com.apple.foo", // a URL, but not a page
	}
	for _, u := range bad {
		if err := validateMDMEnrollURL(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

// TestInstallShWritesTheMDMEnrollURLOnMacs checks the enrollment page is
// written inside the macOS branch only, removed when the offer is off, and
// leaves the script valid shell either way.
func TestInstallShWritesTheMDMEnrollURLOnMacs(t *testing.T) {
	const enroll = "https://fleet.example.com/enroll?enroll_secret=abc123"
	render := func(u string) string {
		var buf bytes.Buffer
		if err := installShTemplate.Execute(&buf, installScriptData{
			DownloadBase: "https://console.example.com", NatsURL: "tls://192.0.2.5:4222",
			Site: "lab", AgentVersion: "0.54.0", MacMenuBar: macMenuBarScript,
			MacMDMEnrollURL: u, EnrollToken: "mte_test",
		}); err != nil {
			t.Fatalf("rendering install.sh: %v", err)
		}
		return buf.String()
	}

	on := render(enroll)
	line := "MDM_ENROLL_URL='" + enroll + "'"
	at := strings.Index(on, line)
	if at < 0 {
		t.Fatalf("install.sh does not carry %s", line)
	}
	darwin := strings.LastIndex(on[:at], `if [ "$goos" = "darwin" ]; then`)
	if darwin < 0 || strings.Contains(on[darwin:at], "\nfi\n") {
		t.Errorf("the enrollment page is written outside the macOS branch")
	}
	if !strings.Contains(on, `rm -f "$INSTALL_DIR/mdm-enroll.url"`) {
		t.Errorf("install.sh never removes a stale enrollment page")
	}

	off := render("")
	if !strings.Contains(off, "MDM_ENROLL_URL=''") {
		t.Errorf("with the offer off, install.sh should carry an empty value")
	}

	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for name, script := range map[string]string{"on": on, "off": off} {
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("install.sh with the offer %s is not valid shell: %v\n%s", name, err, out)
		}
	}
}
