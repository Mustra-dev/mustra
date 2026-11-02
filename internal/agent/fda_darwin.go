//go:build darwin

package agent

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Full Disk Access on macOS.
//
// TCC guards Desktop, Documents, Downloads, Mail, Photos and its own
// database, and it does not care that this process is root. Without Full
// Disk Access the agent holds every Unix privilege there is and still cannot
// list a user's Documents -- so a sensor over those paths returns nothing
// and reads as a pass rather than as a refusal. That is the failure worth
// preventing: not a loud error, a quiet wrong answer.
//
// It cannot be granted from here. The TCC database is itself TCC-protected
// precisely so a root process cannot grant itself access, which is the
// design working. All the agent can do is ask the person at the machine.

const fdaStampFile = "fda-prompted"

// hasFullDiskAccess reports whether this process can read the TCC database,
// which is the standard probe: nothing else distinguishes "root" from "root
// with Full Disk Access".
func hasFullDiskAccess() bool {
	f, err := os.Open("/Library/Application Support/com.apple.TCC/TCC.db")
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 1)
	_, err = f.Read(buf)
	return err == nil
}

// promptFullDiskAccess asks the console user for the grant, at most once a
// day, and never blocks.
//
// The installer used to do this with `display dialog`, which waits for a
// button. An installer runs unattended -- from a console update, from a
// launchd job -- so it waited for somebody who was not necessarily there,
// and every relaunch of that job produced another. `display notification`
// posts and returns, which is the difference that matters.
//
// Called at startup, so it lands right after an install or update: the
// installer restarts the agent as its last act.
func (a *Agent) promptFullDiskAccess() {
	// Stated either way, at startup.
	//
	// This has to be reported by the agent itself and cannot be probed from
	// outside it: TCC is evaluated per-binary, so running `head` or `ls`
	// against the TCC database through a shell tests the access of *that*
	// binary, not this one. Every external check of this that looked
	// authoritative was measuring the wrong process.
	granted := hasFullDiskAccess()
	a.logger.Info("full disk access", "granted", granted)
	if granted {
		return
	}
	// DataDir is the bbolt file, not the directory that holds it -- see the
	// field's declaration. Everything else in the agent already takes
	// filepath.Dir of it; this did not, and wrote into a path under the
	// database file, which is not a directory.
	stamp := filepath.Join(filepath.Dir(a.cfg.DataDir), fdaStampFile)
	if fi, err := os.Stat(stamp); err == nil && time.Since(fi.ModTime()) < 24*time.Hour {
		// Asked recently. An agent that restarts -- a crash loop, a reboot,
		// a run of updates -- must not turn a reminder into a pestering.
		return
	}
	// Not ignored. Without this stamp the rate limit does not exist, so
	// every restart asks again -- which is the exact annoyance the prompt
	// was rewritten to stop. A silent failure here reads as "the prompt is
	// broken" rather than "the prompt cannot remember it asked".
	if err := os.WriteFile(stamp, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		a.logger.Warn("could not record that Full Disk Access was requested",
			"path", stamp, "error", err,
			"effect", "the request will be repeated at the next agent start")
	}

	uid := consoleUserID()
	if uid == "" {
		// Nobody signed in. Nothing to ask, and the stamp is deliberately
		// still written: the next start after somebody logs in will be
		// within the day, and the installer's own output already says it.
		return
	}

	exe, err := os.Executable()
	if err != nil {
		return
	}

	a.logger.Warn("Full Disk Access is not granted",
		"effect", "Desktop, Documents, Downloads, Mail and Photos are invisible to sensors",
		"grant", "System Settings > Privacy & Security > Full Disk Access, add "+exe)

	// When the console offers an MDM enrollment page and this Mac is not
	// enrolled, send the person there instead. Enrolling is the one step
	// that lets the MDM grant Full Disk Access -- and keep it granted across
	// agent updates, which a hand grant to this ad-hoc-signed binary does
	// not survive. An enrolled Mac that still lacks access falls through to
	// the hand grant: its MDM is not pushing the profile, and sending the
	// person to enroll again would be advice they cannot act on.
	if enrollURL := mdmEnrollURL(exe); enrollURL != "" && !mdmEnrolled(context.Background()) {
		a.logger.Info("offering MDM enrollment for Full Disk Access")
		body := "Enroll this Mac in device management and mustra gets the access it needs " +
			"automatically. Install the profile from the page that just opened, then approve it in " +
			"System Settings > General > Device Management."
		a.asConsoleUser(uid, "/usr/bin/osascript", "-e",
			`display notification `+appleScriptString(body)+
				` with title "mustra" subtitle "Enroll this Mac"`)
		a.asConsoleUser(uid, "/usr/bin/open", enrollURL)
		return
	}

	// Three things, all non-blocking, all best effort. The person gets the
	// message, the right settings pane, and a Finder window with the binary
	// already selected -- because the file picker hides /opt, so "add
	// /opt/mustra-agent/mustra-agent" is advice you cannot follow by
	// clicking. Dragging the revealed file into the list works; so does
	// Cmd-Shift-G, which the notification says.
	body := "Open Privacy & Security > Full Disk Access and add the agent. " +
		"In the picker press Cmd-Shift-G and paste " + exe
	a.asConsoleUser(uid, "/usr/bin/osascript", "-e",
		`display notification `+appleScriptString(body)+
			` with title "mustra" subtitle "Full Disk Access needed"`)
	a.asConsoleUser(uid, "/usr/bin/open",
		"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
	a.asConsoleUser(uid, "/usr/bin/open", "-R", exe)
}

// asConsoleUser runs a command in the logged-in user's session. A daemon
// running it directly draws into a session nobody is looking at.
func (a *Agent) asConsoleUser(uid string, name string, args ...string) {
	full := append([]string{"asuser", uid, name}, args...)
	cmd := exec.Command("/bin/launchctl", full...)
	if err := cmd.Start(); err != nil {
		a.logger.Debug("could not run as the console user", "command", name, "error", err)
		return
	}
	// Reaped in the background so a hung open(1) cannot hold a goroutine.
	go func() { _ = cmd.Wait() }()
}

// consoleUserID is the uid owning the display, or empty when nobody is
// signed in.
func consoleUserID() string {
	out, err := exec.Command("/usr/bin/stat", "-f", "%u", "/dev/console").Output()
	if err != nil {
		return ""
	}
	uid := strings.TrimSpace(string(out))
	if uid == "" || uid == "0" {
		return ""
	}
	return uid
}

// appleScriptString quotes a Go string as an AppleScript literal. The text
// includes a filesystem path, and a stray quote would turn a notification
// into a syntax error nobody would ever see.
func appleScriptString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// mdmEnrollFile holds the MDM enrollment page the console offers, written by
// install.sh beside the agent; absent when the offer is off.
const mdmEnrollFile = "mdm-enroll.url"

// mdmEnrollURL returns the enrollment page, or empty when there is none or
// the file does not hold an https URL. The server validates it before it is
// ever written, so a bad value here means the file was edited by hand, and
// open(1) is not handed something it might treat as a local path.
func mdmEnrollURL(exe string) string {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), mdmEnrollFile))
	if err != nil {
		return ""
	}
	raw := strings.TrimSpace(string(b))
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return raw
}
