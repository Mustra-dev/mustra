package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// renderInstallSh renders the install script with plausible values. The
// template is the only form the script ever exists in, so anything checking
// it has to render it first.
func renderInstallSh(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := installShTemplate.Execute(&buf, installScriptData{
		DownloadBase:  "https://console.example.com",
		NatsURL:       "tls://192.0.2.5:4222",
		Site:          "lab",
		AgentVersion:  "0.51.0",
		EnrollToken:   "mte_test",
		UninstallHash: "",
		// The real thing, not a stub: this is what the template has to
		// carry, and an empty one renders a script whose heredoc is blank.
		MacMenuBar: macMenuBarScript,
	}); err != nil {
		t.Fatalf("rendering install.sh: %v", err)
	}
	return buf.String()
}

// TestInstallShIsValidShell parses the rendered script. It runs with
// "set -euo pipefail" on endpoints, where a syntax error is not a failed
// install but a half-finished one, and the script is assembled from a Go
// raw string where an editing slip is easy and invisible until an endpoint
// runs it.
func TestInstallShIsValidShell(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	cmd := exec.Command(bash, "-n")
	cmd.Stdin = strings.NewReader(renderInstallSh(t))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh is not valid shell: %v\n%s", err, out)
	}
}

// TestInstallShStagesTheAgentBinary pins the ordering that keeps a failed
// download from bricking an endpoint. The agent binary must be fetched and
// checked while the old agent is still running; it used to be downloaded
// straight over the live binary after the service had been stopped, so one
// reset connection left a truncated agent and nothing to roll back to.
func TestInstallShStagesTheAgentBinary(t *testing.T) {
	script := renderInstallSh(t)

	fetchAgent := strings.Index(script, `fetch "$BIN_URL" "$python_stage/mustra-agent"`)
	if fetchAgent < 0 {
		t.Fatal("the agent binary is not staged before install")
	}
	stop := strings.Index(script, "launchctl unload")
	if stop < 0 {
		t.Fatal("could not find where the script stops a running agent")
	}
	if fetchAgent > stop {
		t.Error("the agent binary is downloaded after the running agent is stopped; " +
			"a failed download then leaves the endpoint with no agent")
	}
	if strings.Contains(script, `-o "$INSTALL_DIR/mustra-agent"`) {
		t.Error(`the agent binary is downloaded directly over the installed one; ` +
			`a partial transfer truncates a working agent`)
	}
	if !strings.Contains(script, `mustra-agent.previous`) {
		t.Error("no rollback copy is kept while the new agent binary is moved into place")
	}
}

// TestInstallShCarriesTheMacMenuBar pins the helper into the script. It is
// embedded from its own file rather than written inline, because the
// install script is a Go raw string and one backtick in the JavaScript
// would end it — so the failure mode if the wiring breaks is an empty
// heredoc and a menu bar item that never appears, with nothing to see in a
// diff.
func TestInstallShCarriesTheMacMenuBar(t *testing.T) {
	script := renderInstallSh(t)

	// Both halves: the template asks for the field, and the embedded file
	// has the thing worth asking for. Either alone passes while the feature
	// is broken.
	if !strings.Contains(installShScript, "{{.MacMenuBar}}") {
		t.Fatal("the install script template never interpolates the menu bar helper")
	}
	if !strings.Contains(script, "NSStatusBar") {
		t.Fatal("the menu bar helper is not in the rendered install script")
	}
	if strings.Contains(macMenuBarScript, "`") {
		t.Error("the menu bar script contains a backtick; it is interpolated into a Go raw string")
	}
	// A line equal to the heredoc delimiter would end the heredoc early and
	// leave the rest of the JavaScript being run as shell.
	for _, line := range strings.Split(macMenuBarScript, "\n") {
		if strings.TrimSpace(line) == "MENUBAR_EOF" {
			t.Error("the menu bar script contains its own heredoc delimiter")
		}
	}
	// It has to start in the user's session, not as another root daemon.
	if !strings.Contains(script, "/Library/LaunchAgents/dev.mustra.menubar.plist") {
		t.Error("the helper is not installed as a LaunchAgent; a LaunchDaemon has no session to draw in")
	}
	if strings.Contains(script, "/Library/LaunchDaemons/dev.mustra.menubar.plist") {
		t.Error("the helper is installed as a LaunchDaemon, which cannot draw a menu bar item")
	}
}

// The checksum the installer compares against has to be the digest and
// nothing else. Serving sha256sum's "<digest>  <name>" form instead made
// every macOS install refuse its own binary: the script computes a bare
// digest and compared it to a line that still had the filename on it, so it
// could never match. Both ends are fixed; this pins the wire format, which
// is the half a shell script cannot assert for itself.
func TestAgentChecksumIsABareDigest(t *testing.T) {
	dir := t.TempDir()
	build := filepath.Join(dir, "mustra-agent-darwin-arm64")
	if err := os.WriteFile(build, []byte("not really a binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MUSTRA_AGENT_BUILDS_DIR", dir)

	s := &Server{logger: slog.Default(), cfg: Config{AgentBuildsDir: dir}}
	rec := httptest.NewRecorder()
	s.serveAgentChecksum(rec, httptest.NewRequest(http.MethodGet, "/downloads/x.sha256", nil),
		build, "mustra-agent-darwin-arm64")

	body := strings.TrimSpace(rec.Body.String())
	if strings.ContainsAny(body, " \t") {
		t.Fatalf("the checksum body is %q; it must be the digest alone, or the installer's comparison never matches", body)
	}
	want := sha256.Sum256([]byte("not really a binary"))
	if body != hex.EncodeToString(want[:]) {
		t.Fatalf("checksum = %q, want %q", body, hex.EncodeToString(want[:]))
	}
}

// And the script has to tolerate either form, so an installer from this
// release still works against a server that has not been updated.
func TestInstallShTakesTheFirstFieldOfAChecksum(t *testing.T) {
	script := renderInstallSh(t)
	if !strings.Contains(script, `awk '{print $1; exit}' "$python_stage/agent-expected"`) {
		t.Error("the installer does not reduce the expected checksum to its first field")
	}
}

// launchctl bootout returns before the job is gone, so a bootstrap issued
// immediately after it fails and the installer reports that the icon will
// appear at the next login — on a machine whose owner is watching it not
// appear. The wait between them is the whole fix, and it is one line that
// is easy to lose.
func TestInstallShWaitsForTheMenuBarHelperToStop(t *testing.T) {
	script := renderInstallSh(t)

	bootout := strings.Index(script, `launchctl bootout "gui/$CONSOLE_UID/dev.mustra.menubar"`)
	bootstrap := strings.Index(script, `launchctl bootstrap "gui/$CONSOLE_UID" "$MENUBAR_PLIST"`)
	if bootout < 0 || bootstrap < 0 {
		t.Fatal("the installer no longer restarts the menu bar helper")
	}
	if bootout > bootstrap {
		t.Fatal("bootstrap comes before bootout; the old helper would keep running")
	}
	between := script[bootout:bootstrap]
	if !strings.Contains(between, `launchctl print "gui/$CONSOLE_UID/dev.mustra.menubar"`) {
		t.Error("nothing waits for the old helper to actually stop between bootout and bootstrap")
	}
}

// TestInstallShRefusesHostsWithoutSystemd pins the check that runs before
// anything is downloaded. Home Assistant OS's SSH add-on is Alpine under
// s6; an install there got most of the way through and then exited 1 with
// nothing on stderr, leaving files in a container that is thrown away when
// the add-on restarts.
func TestInstallShRefusesHostsWithoutSystemd(t *testing.T) {
	script := renderInstallSh(t)
	guard := strings.Index(script, `[ ! -d /run/systemd/system ]`)
	if guard < 0 {
		t.Fatal("install.sh does not check for systemd on Linux")
	}
	if first := strings.Index(script, `fetch "`); first >= 0 && first < guard {
		t.Error("install.sh downloads before checking for systemd; a refused host is left with a partial install")
	}
}

// TestInstallShChecksTheAgentStayedUp pins the post-start check. An agent
// that cannot trust the bus exits at once and systemd restarts it forever;
// the install used to report success regardless, which is how a push to
// your-spotify "succeeded" while the endpoint never appeared.
func TestInstallShChecksTheAgentStayedUp(t *testing.T) {
	script := renderInstallSh(t)
	start := strings.Index(script, "systemctl enable --now mustra-agent")
	check := strings.Index(script, "NRestarts")
	if start < 0 || check < 0 || check < start {
		t.Fatal("install.sh does not check the agent's restart count after starting it")
	}
}

// TestInstallPs1StagesAndSerialises pins the fixes for dc01 going dark on
// 2026-09-28: three concurrent installers wrote one exe over each other
// after stopping the service, leaving a truncated binary. The download and
// its checksum now come before the service is stopped, and a machine-wide
// mutex keeps a second installer out until the first is done.
func TestInstallPs1StagesAndSerialises(t *testing.T) {
	var buf bytes.Buffer
	if err := installPs1Template.Execute(&buf, installScriptData{
		DownloadBase: "https://console.example.com", NatsURL: "tls://192.0.2.5:4222",
		Site: "lab", AgentVersion: "0.53.3",
	}); err != nil {
		t.Fatalf("rendering install.ps1: %v", err)
	}
	script := buf.String()
	lock := strings.Index(script, `Global\MustraAgentInstall`)
	download := strings.Index(script, `-Uri $BinUrl -OutFile $AgentStage`)
	checksum := strings.Index(script, `agent checksum mismatch`)
	stop := strings.Index(script, "Stop-Service mustra-agent")
	if lock < 0 || download < 0 || checksum < 0 || stop < 0 {
		t.Fatalf("missing a step: lock=%d download=%d checksum=%d stop=%d", lock, download, checksum, stop)
	}
	if !(lock < download && download < checksum && checksum < stop) {
		t.Errorf("want lock < download < checksum < stop, got %d %d %d %d", lock, download, checksum, stop)
	}
	if strings.Contains(script, `-OutFile "$InstallDir\mustra-agent.exe"`) {
		t.Error("install.ps1 still downloads straight over the live agent binary")
	}
}

// TestInstallersFetchTheCAForANatsURL pins the fix for the DCs that went
// dark on their first reboot after an install: with a nats:// URL neither
// installer fetched ca.crt or passed --nats-ca, though the broker requires
// TLS regardless, so the agent was left verifying it against the system
// trust store, which has never held the mustra CA.
func TestInstallersFetchTheCAForANatsURL(t *testing.T) {
	data := installScriptData{
		DownloadBase: "https://console.example.com", NatsURL: "nats://192.0.2.5:4222",
		HasCA: true, Site: "lab", AgentVersion: "0.55.8", MacMenuBar: macMenuBarScript,
	}
	var sh, ps1 bytes.Buffer
	if err := installShTemplate.Execute(&sh, data); err != nil {
		t.Fatalf("rendering install.sh: %v", err)
	}
	if err := installPs1Template.Execute(&ps1, data); err != nil {
		t.Fatalf("rendering install.ps1: %v", err)
	}
	if !strings.Contains(sh.String(), "\nHAS_CA=1\n") {
		t.Error("install.sh does not know the control plane has a CA")
	}
	if !strings.Contains(ps1.String(), "$HasCa = $true") {
		t.Error("install.ps1 does not know the control plane has a CA")
	}

	data.HasCA = false
	sh.Reset()
	if err := installShTemplate.Execute(&sh, data); err != nil {
		t.Fatalf("rendering install.sh: %v", err)
	}
	if !strings.Contains(sh.String(), "\nHAS_CA=\n") {
		t.Error("install.sh claims a CA the control plane does not have")
	}
}
