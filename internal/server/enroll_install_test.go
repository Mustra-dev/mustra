package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testInstallServer is a Server with just enough wired to render install
// scripts without a database: the public URL comes from the environment
// override and no token is presented.
func testInstallServer() *Server {
	s := &Server{logger: slog.Default(), live: &liveConfig{},
		trust: &agentTrust{publicURLEnv: "https://console.example.com"}}
	s.live.setAgent(0, 0, "tls://192.0.2.5:4222")
	return s
}

func get(t *testing.T, h http.HandlerFunc, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// An unauthenticated install script carries no secret of any kind, and
// refuses to install a new endpoint.
func TestUnauthenticatedInstallScriptCarriesNoSecret(t *testing.T) {
	s := testInstallServer()
	for _, h := range []http.HandlerFunc{s.handleInstallSh, s.handleInstallPs1} {
		rec := get(t, h, "/install.sh", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		body := rec.Body.String()
		for _, bad := range []string{"MUSTRA_NATS_PASSWORD=$NATS", "mte_", "$NatsPassword", "UNINSTALL_HASH='$2"} {
			if strings.Contains(body, bad) {
				t.Errorf("unauthenticated script contains %q", bad)
			}
		}
		if !strings.Contains(body, "requires an enrollment token") {
			t.Error("unauthenticated script does not refuse a fresh install")
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Error("install script may be cached")
		}
	}
}

// A forged Host or X-Forwarded-* header changes nothing: every URL in the
// script is the configured one.
func TestForgedHostHeaderChangesNothing(t *testing.T) {
	s := testInstallServer()
	rec := get(t, s.handleInstallSh, "/install.sh", map[string]string{
		"Host": "evil.example", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.example",
	})
	body := rec.Body.String()
	if strings.Contains(body, "evil.example") {
		t.Fatal("a request header reached the install script")
	}
	if !strings.Contains(body, "DOWNLOAD_BASE='https://console.example.com'") {
		t.Fatal("the configured public URL is not what the script uses")
	}
}

func TestInstallScriptRefusesInjectedSite(t *testing.T) {
	s := testInstallServer()
	for _, site := range []string{"$(id)", "a'b", "a\"b", "x;y", "a.b", "`id`"} {
		rec := get(t, s.handleInstallSh, "/install.sh?site="+urlQueryEscape(site), nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("site %q: status %d", site, rec.Code)
		}
	}
	rec := get(t, s.handleInstallPs1, "/install.ps1?site=branch-1", nil)
	if !strings.Contains(rec.Body.String(), "$Site = 'branch-1'") {
		t.Error("a valid site is not rendered as a single-quoted literal")
	}
}

func urlQueryEscape(s string) string {
	r := strings.NewReplacer("%", "%25", " ", "%20", "'", "%27", "\"", "%22", ";", "%3B", "$", "%24", "(", "%28", ")", "%29", "`", "%60", "&", "%26")
	return r.Replace(s)
}

// B7: the agent checksum is mandatory and the previous binary survives
// until the new one passes its health check.
func TestInstallShNeverFallsBackFromTheChecksum(t *testing.T) {
	script := renderInstallSh(t)
	if strings.Contains(script, "Size alone") || strings.Contains(script, "the agent download was empty") {
		t.Fatal("the size-only fallback is back")
	}
	if !strings.Contains(script, "could not fetch the agent checksum; nothing was changed") {
		t.Fatal("a failed checksum fetch does not abort")
	}
	health := strings.Index(script, "NRestarts")
	firstRm := strings.Index(script, `rm -f "$INSTALL_DIR/mustra-agent.previous"`+"\n  echo \"mustra-agent installed and started via systemd.")
	if health < 0 || firstRm < 0 || firstRm < health {
		t.Fatal("the previous binary is not kept until the systemd health check passes")
	}
	if !strings.Contains(script, "restore_previous_agent") {
		t.Fatal("no rollback on a failed health check")
	}
	// The previous binary is not removed right after the move any more.
	move := strings.Index(script, `mv "$python_stage/mustra-agent" "$INSTALL_DIR/mustra-agent"`)
	next := script[move : move+700]
	if strings.Contains(next, `rm -f "$INSTALL_DIR/mustra-agent.previous"`) {
		t.Fatal("the previous binary is deleted before the health check")
	}
}

// B1: modes do not depend on the caller's umask.
func TestInstallShSetsExplicitModes(t *testing.T) {
	script := renderInstallSh(t)
	for _, want := range []string{"umask 022", `chmod 755 "$INSTALL_DIR"`, `chmod 700 "$DATA_DIR"`,
		`chmod 755 "$INSTALL_DIR/mustra-agent"`, `chmod -R go-w "$INSTALL_DIR/python"`, `chmod 600 "$DATA_DIR/enroll.token"`} {
		if !strings.Contains(script, want) {
			t.Errorf("install.sh is missing %q", want)
		}
	}
	if strings.Contains(script, "EnvironmentFile=") || strings.Contains(script, "<key>EnvironmentVariables</key>") {
		t.Error("credentials are put in the service environment, which every child process inherits")
	}
}

// The quoting holds when the script actually runs: a hostile value in any
// templated field stays data. The fields are validated server-side too;
// this checks the second line of defence.
func TestInstallShQuotingHoldsInBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	var buf bytes.Buffer
	evil := "$(touch /tmp/mustra-pwned)'\"`id`"
	if err := installShTemplate.Execute(&buf, installScriptData{
		DownloadBase: evil, NatsURL: evil, Site: evil, AgentVersion: evil, EnrollToken: evil, MacMenuBar: macMenuBarScript,
	}); err != nil {
		t.Fatal(err)
	}
	script := buf.String()
	head := script[:strings.Index(script, "INSTALL_DIR=")]
	out, err := exec.Command("bash", "-c", head+`printf '%s|%s|%s|%s' "$NATS_URL" "$SITE" "$DOWNLOAD_BASE" "$ENROLL_TOKEN"`).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if string(out) != strings.Repeat(evil+"|", 3)+evil {
		t.Fatalf("templated values were interpreted: %q", out)
	}
}

// Windows: no credential in Machine environment variables, the service is
// updated in place, recovery fires on error exits, and the uninstaller
// checks for elevation.
func TestInstallPs1Hardening(t *testing.T) {
	var buf bytes.Buffer
	if err := installPs1Template.Execute(&buf, installScriptData{
		DownloadBase: "https://console.example.com", NatsURL: "tls://192.0.2.5:4222",
		Site: "lab", AgentVersion: "0.80.0", EnrollToken: "mte_x",
	}); err != nil {
		t.Fatal(err)
	}
	script := buf.String()
	if strings.Contains(script, `SetEnvironmentVariable("MUSTRA_NATS_PASSWORD", $`) {
		t.Error("install.ps1 still writes the password to a Machine environment variable")
	}
	install := script[:strings.Index(script, "$UninstallScript =")]
	if strings.Contains(install, "sc.exe delete mustra-agent") {
		t.Error("install.ps1 deletes and recreates the service")
	}
	for _, want := range []string{"sc.exe failureflag mustra-agent 1", "Set-AgentAcl $DataDir $false",
		"IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)", "$EnrollToken = 'mte_x'",
		`Write-Ascii "$DataDir\enroll.token" $EnrollToken`, "restored the previous agent binary"} {
		if !strings.Contains(script, want) {
			t.Errorf("install.ps1 is missing %q", want)
		}
	}
	if strings.Count(script, "\"{{") > 0 || strings.Contains(script, "?v=${AGENT_VERSION}") {
		t.Error("an unquoted template value or a bash-only reference is left in install.ps1")
	}
}

func TestInstallCommandsQuoteTheToken(t *testing.T) {
	c := installCommands("https://console.example.com", "mte_abc", "branch-1")
	if c["unix"] != "curl -fsSL -H 'Authorization: Bearer mte_abc' 'https://console.example.com/install.sh?site=branch-1' | sudo bash" {
		t.Errorf("unix one-liner: %s", c["unix"])
	}
	if !strings.Contains(c["windows"], "@{Authorization='Bearer mte_abc'}") {
		t.Errorf("windows one-liner: %s", c["windows"])
	}
	// Alpine: no sudo, and bash and curl added first.
	if c["alpine"] != "apk add --no-cache bash curl && curl -fsSL -H 'Authorization: Bearer mte_abc' 'https://console.example.com/install.sh?site=branch-1' | bash" {
		t.Errorf("alpine one-liner: %s", c["alpine"])
	}
}

// On Home Assistant OS the script runs in the SSH add-on, where none of the
// agent's files are visible: they are in the agent's own add-on. An update
// fetched without a token must still go through when the Supervisor already
// has that add-on installed, and a new install without one must not.
func TestInstallShHAOSAddonCountsAsEnrolled(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the HAOS branch is Linux-only")
	}
	var buf bytes.Buffer
	if err := installShTemplate.Execute(&buf, installScriptData{
		DownloadBase: "https://example.test", NatsURL: "tls://example.test:4222", AgentVersion: "test", MacMenuBar: macMenuBarScript,
	}); err != nil {
		t.Fatal(err)
	}
	script := buf.String()
	end := strings.Index(script, "# The Linux install is a systemd unit.")
	if end < 0 {
		t.Fatal("marker after the enrollment check not found")
	}
	root := t.TempDir()
	for _, d := range []string{"addons", "s6", "bin", "data", "install"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "s6", "SUPERVISOR_TOKEN"), []byte("tok"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The Supervisor's answer is whatever FAKE_VERSION says. id answers
	// root because the SSH add-on is root and the script refuses anyone
	// else before it reaches the enrollment check; without it the test
	// passed only when go test itself ran as root.
	fakes := map[string]string{
		"curl": "#!/bin/sh\necho '{}'\n",
		"jq":   "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$FAKE_VERSION\"\n",
		"id":   "#!/bin/sh\necho 0\n",
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	head := script[:end]
	head = strings.ReplaceAll(head, "/run/s6/container_environment", filepath.Join(root, "s6"))
	head = strings.ReplaceAll(head, "/run/systemd/system", filepath.Join(root, "no-systemd"))
	head = strings.ReplaceAll(head, "[ -d /addons ]", "[ -d "+filepath.Join(root, "addons")+" ]")
	head = strings.Replace(head, "DATA_DIR=", "DATA_DIR="+filepath.Join(root, "data")+" #", 1)
	head = strings.Replace(head, "INSTALL_DIR=", "INSTALL_DIR="+filepath.Join(root, "install")+" #", 1)
	for _, tc := range []struct {
		version string
		ok      bool
	}{{"0.1.0", true}, {"", false}} {
		cmd := exec.Command("bash", "-c", head+"echo enrolled-check-passed")
		cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+":"+os.Getenv("PATH"), "FAKE_VERSION="+tc.version)
		out, _ := cmd.CombinedOutput()
		passed := strings.Contains(string(out), "enrolled-check-passed")
		if passed != tc.ok {
			t.Errorf("add-on version %q: passed=%v, want %v: %s", tc.version, passed, tc.ok, out)
		}
		// A refusal must be the enrollment check's, not an earlier exit.
		if !tc.ok && !strings.Contains(string(out), "requires an enrollment token") {
			t.Errorf("add-on version %q: stopped before the enrollment check: %s", tc.version, out)
		}
	}
}
