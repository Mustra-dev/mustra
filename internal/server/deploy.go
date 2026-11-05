package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/updatesig"
	"github.com/mustra-dev/mustra/internal/version"
)

//go:embed macmenubar.js
var macMenuBarScript string

// defaultAgentBuildsDir is where the container image places the agent
// binaries. See Config.AgentBuildsDir for running outside the container.
const defaultAgentBuildsDir = "/usr/local/share/mustra-agent-builds"

func (s *Server) agentBuildsDir() string {
	if s.cfg.AgentBuildsDir != "" {
		return s.cfg.AgentBuildsDir
	}
	return defaultAgentBuildsDir
}

// handleDownloadAgent serves a pre-built agent binary. Deliberately
// unauthenticated (unlike the rest of the console): a copy-pasted `curl`
// one-liner from the install scripts below has no browser session cookie
// to send, and the binaries themselves carry no secrets — the NATS URL and
// site are passed as runtime flags, not baked in.
func (s *Server) handleDownloadAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// PathValue can't contain "/" from the route pattern itself, but guard
	// against ".." defensively before it ever reaches the filesystem.
	if strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.agentBuildsDir(), name)
	// The Python runtimes ship a .sha256 beside them; the agent binaries do
	// not, so the installer had nothing to check a download against and a
	// truncated transfer was indistinguishable from a good one. Synthesize
	// it rather than requiring a build-time change, so existing deployments
	// gain the guard on upgrade.
	// "<build>.sig" is the signed update manifest (enroll_signing.go): the
	// release's own when it shipped one, otherwise signed by this
	// deployment's key. Published for transparency and for tooling; agents
	// receive the same manifest over their authenticated channel.
	if base, ok := strings.CutSuffix(name, ".sig"); ok {
		m, err := s.buildManifest(base)
		if err != nil {
			http.Error(w, "no signed manifest for "+base, http.StatusNotFound)
			return
		}
		raw, _ := m.Marshal()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		_, _ = w.Write(raw)
		return
	}
	if base, ok := strings.CutSuffix(name, ".sha256"); ok {
		if _, err := os.Stat(path); err != nil {
			s.serveAgentChecksum(w, r, filepath.Join(s.agentBuildsDir(), base), base)
			return
		}
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "no such build: "+name, http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	// These filenames are stable across releases -- mustra-agent-windows-amd64.exe
	// is a different binary after every deploy. Any intermediary that caches
	// by URL (Cloudflare sits in front of this one) will happily serve a
	// months-old agent to a fresh install, which looks like a broken build
	// rather than a stale cache. no-cache still permits revalidation, and
	// ServeContent supplies Last-Modified/ETag, so an unchanged binary is
	// still a cheap 304.
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	http.ServeContent(w, r, name, statModTime(f), f)
}

// agentChecksums caches a build's digest against its modification time, so
// hashing 13 MB is something that happens once per deploy rather than once
// per endpoint installing.
var agentChecksums sync.Map // path -> agentChecksum

type agentChecksum struct {
	modTime time.Time
	sum     string
}

// fileDigest is a file's SHA-256, remembered against its modification time.
func fileDigest(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if hit, ok := agentChecksums.Load(path); ok {
		if c := hit.(agentChecksum); c.modTime.Equal(fi.ModTime()) {
			return c.sum, nil
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	agentChecksums.Store(path, agentChecksum{modTime: fi.ModTime(), sum: sum})
	return sum, nil
}

// serveAgentChecksum answers "<build>.sha256" by hashing the build itself,
// in the format sha256sum writes: the digest, two spaces, the filename.
func (s *Server) serveAgentChecksum(w http.ResponseWriter, r *http.Request, path, base string) {
	if _, err := os.Stat(path); err != nil {
		http.Error(w, "no such build: "+base, http.StatusNotFound)
		return
	}
	sum, err := fileDigest(path)
	if err != nil {
		s.logger.Error("hashing an agent build failed", "path", path, "error", err)
		http.Error(w, "could not checksum "+base, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	// The digest alone, which is what the Python runtimes' .sha256 files
	// beside these contain and what the installer compares against. Writing
	// sha256sum's "<digest>  <name>" form instead meant the installer was
	// comparing a digest to a digest-plus-a-filename, so every macOS
	// install refused its own binary as a checksum mismatch.
	_, _ = io.WriteString(w, sum+"\n")
}

func statModTime(f *os.File) (t time.Time) {
	if fi, err := f.Stat(); err == nil {
		t = fi.ModTime()
	}
	return t
}

// The console URL used to be learned here: publicBaseURL built it from the
// request's Host and X-Forwarded-Proto headers and rememberConsoleURL
// stored it as the URL every agent later fetched its updater from. Both
// headers are the client's to choose, and /install.sh is unauthenticated,
// so one forged request pointed the fleet's next update at any host. The
// URL is configuration now (enroll_publicurl.go). A value this code
// remembered in the past is offered in Settings as a suggestion only.

type installScriptData struct {
	NatsURL string
	// HasCA says the control plane has a CA to hand out at /ca.crt. The
	// installers fetch it and pass --nats-ca whenever it does, whatever
	// the URL's scheme: the broker requires TLS either way, and a nats://
	// URL used to mean an agent with no CA of its own, which worked only
	// while a MUSTRA_NATS_CA it had inherited was still in its environment.
	// The installer deletes that variable, so the first reboot afterwards
	// left the agent rejecting the broker (dc01 and dc02, 2026-10-11).
	HasCA        bool
	Site         string
	DownloadBase string
	AgentVersion string
	// EnrollToken is the token this request was authorized with. Empty
	// means an unauthenticated request: the script then carries no
	// enrollment material at all, updates an endpoint that is already
	// enrolled, and refuses to install a new one. It never carries a bus
	// password — there is no shared one to hand out any more.
	EnrollToken string
	// UpdateSigningKey is the public key agent updates are signed with,
	// pinned by the agent when it enrolls.
	UpdateSigningKey string

	// UninstallHash is the bcrypt hash of the password the endpoint's own
	// uninstaller asks for, or empty when no password is configured. Only
	// in token-authorized scripts: a hash served to anyone is a hash anyone
	// can try to crack offline.
	UninstallHash string
	// MacMDMEnrollURL is the MDM enrollment page the macOS agent offers when
	// it lacks Full Disk Access and the Mac is not enrolled; empty when the
	// console has not turned the offer on, and always empty in an
	// unauthenticated script. Validated on save (see validateMDMEnrollURL).
	MacMDMEnrollURL string
	// MacMenuBar is the JXA menu bar helper, written into the Self Service
	// bundle by the macOS branch of the install script.
	MacMenuBar string
	// NoRemoteCode installs in inventory-and-patching mode: the script leaves
	// the file the agent looks for beside its binary. It only ever adds that
	// file, so a later install without it does not turn the mode off.
	NoRemoteCode bool
	// Pins are the SHA-256 of everything this script downloads, by file name.
	// The install command pins this script's own hash (installCommands), so the
	// chain holds whatever carries the downloads. Only in token-authorized
	// scripts: the unauthenticated update path checks what it fetches as before.
	Pins map[string]string
}

// installError is a refusal the install handlers turn into a plain-text
// HTTP error. curl -f and Invoke-WebRequest both fail on it, so a piped
// "| bash" runs nothing.
type installError struct {
	status int
	msg    string
}

func (e *installError) Error() string { return e.msg }

// requestEnrollToken reads the enrollment token from the Authorization
// header (what the console's one-liners use, keeping it out of access
// logs) or, for tools that cannot set a header, the token query parameter.
func requestEnrollToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if tok, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(tok)
		}
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

// installScriptData renders the data for one install script request.
func (s *Server) installScriptData(r *http.Request) (installScriptData, error) {
	ctx := r.Context()
	site := r.URL.Query().Get("site")
	if site != "" && !validSite(site) {
		return installScriptData{}, &installError{http.StatusBadRequest,
			"site may contain only letters, digits, '-' and '_' (at most 64 characters)"}
	}
	noRemoteCode := r.URL.Query().Get("no_remote_code") == "1"
	token := requestEnrollToken(r)
	tokenSite := ""
	if token != "" {
		t, err := s.store.LookupEnrollmentToken(ctx, hashToken(token))
		if err != nil {
			if !errors.Is(err, store.ErrTokenUnusable) {
				s.logger.Error("enrollment token lookup failed", "error", err)
				return installScriptData{}, &installError{http.StatusInternalServerError, "could not check the enrollment token"}
			}
			return installScriptData{}, &installError{http.StatusUnauthorized,
				"this enrollment token is not valid: it may have expired, been revoked or been used up. Create a new one in the console."}
		}
		tokenSite = t.Site
	}
	if site == "" {
		site = firstNonEmptyString(tokenSite, defaultSite)
	}
	data, err := s.renderInstallData(ctx, site, token)
	data.NoRemoteCode = noRemoteCode
	return data, err
}

// renderInstallData is the part shared with the SSH push, which mints its
// own single-use token rather than having one in a request.
func (s *Server) renderInstallData(ctx context.Context, site, token string) (installScriptData, error) {
	base, err := s.agentPublicURL(ctx)
	if err != nil {
		return installScriptData{}, &installError{http.StatusServiceUnavailable, err.Error()}
	}
	natsURL := s.agentNATSURL()
	if !natsURLPattern.MatchString(natsURL) {
		return installScriptData{}, &installError{http.StatusServiceUnavailable,
			"the agent NATS URL (MUSTRA_AGENT_NATS_URL, or Settings) is not set to a valid nats:// or tls:// address"}
	}
	data := installScriptData{
		NatsURL: natsURL, HasCA: s.cfg.NATSCreds.CAFile != "", Site: site, DownloadBase: base,
		AgentVersion: version.AgentVersion, MacMenuBar: macMenuBarScript,
	}
	if token == "" {
		return data, nil
	}
	data.EnrollToken = token
	if s.trust != nil && s.trust.signPub != nil {
		data.UpdateSigningKey = updatesig.EncodePublicKey(s.trust.signPub)
	}
	// Read per request rather than cached, so changing the password in the
	// console reaches the next install instead of the next restart.
	if h, err := s.store.GetSetting(ctx, settingUninstallPasswordHash); err == nil {
		data.UninstallHash = h
	} else {
		s.logger.Warn("could not read the uninstall password setting", "error", err)
	}
	// A failed read serves the script without the offer rather than failing
	// the install: enrollment is a convenience, the agent is not.
	mdmEnrollURL, err := s.store.GetSetting(ctx, settingMacMDMEnrollURL)
	if err != nil || validateMDMEnrollURL(mdmEnrollURL) != nil {
		if err != nil {
			s.logger.Warn("could not read the macOS MDM enrollment setting", "error", err)
		}
		mdmEnrollURL = ""
	}
	data.MacMDMEnrollURL = mdmEnrollURL
	data.Pins = s.installPins()
	return data, nil
}

// installPins is the digest of every build an installer can fetch, and of the
// control plane's CA. A file that can't be read is left out, and its download
// falls back to the checksum beside it.
func (s *Server) installPins() map[string]string {
	pins := map[string]string{}
	if entries, err := os.ReadDir(s.agentBuildsDir()); err == nil {
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !(strings.HasPrefix(name, "mustra-agent-") || strings.HasPrefix(name, "mustra-python-") || strings.HasPrefix(name, "mustra-tray-")) ||
				strings.HasSuffix(name, ".sha256") || strings.HasSuffix(name, ".sig") || strings.HasSuffix(name, ".source") {
				continue
			}
			if sum, err := fileDigest(filepath.Join(s.agentBuildsDir(), name)); err == nil {
				pins[name] = sum
			} else {
				s.logger.Warn("could not hash a build for the installer", "name", name, "error", err)
			}
		}
	}
	if path := s.cfg.NATSCreds.CAFile; path != "" {
		if data, err := os.ReadFile(path); err == nil {
			sum := sha256.Sum256(data)
			pins["ca.crt"] = hex.EncodeToString(sum[:])
		}
	}
	if data, err := haosAddonTarball(); err == nil {
		sum := sha256.Sum256(data)
		pins["mustra-haos-addon.tar.gz"] = hex.EncodeToString(sum[:])
	}
	return pins
}

// installScriptHashes renders both installers exactly as a request with this
// token would get them, for the install command to pin.
func (s *Server) installScriptHashes(ctx context.Context, site, token string, noRemoteCode bool) (sh, ps1 string, err error) {
	if site == "" {
		site = defaultSite
	}
	data, err := s.renderInstallData(ctx, site, token)
	if err != nil {
		return "", "", err
	}
	data.NoRemoteCode = noRemoteCode
	hash := func(t *template.Template) (string, error) {
		var buf bytes.Buffer
		if err := t.Execute(&buf, data); err != nil {
			return "", err
		}
		sum := sha256.Sum256(buf.Bytes())
		return hex.EncodeToString(sum[:]), nil
	}
	if sh, err = hash(installShTemplate); err != nil {
		return "", "", err
	}
	if ps1, err = hash(installPs1Template); err != nil {
		return "", "", err
	}
	return sh, ps1, nil
}

// installScriptDataForPush is what an SSH push installs with: a fresh
// single-use token, short-lived, attributed to whoever started the push.
func (s *Server) installScriptDataForPush(ctx context.Context, site, actor, target string, noRemoteCode bool) (installScriptData, error) {
	if site == "" {
		site = defaultSite
	}
	if !validSite(site) {
		return installScriptData{}, errors.New("site may contain only letters, digits, '-' and '_'")
	}
	token, _, err := s.mintEnrollToken(ctx, "ssh push to "+target, site, actor, 1, pushTokenTTL)
	if err != nil {
		return installScriptData{}, err
	}
	data, err := s.renderInstallData(ctx, site, token)
	data.NoRemoteCode = noRemoteCode
	return data, err
}

var installTemplateFuncs = template.FuncMap{"sq": shQuote, "psq": psQuoteString}

var installShTemplate = template.Must(template.New("install.sh").Funcs(installTemplateFuncs).Parse(installShScript))
var installPs1Template = template.Must(template.New("install.ps1").Funcs(installTemplateFuncs).Parse(installPs1Script))

func (s *Server) serveInstallScript(w http.ResponseWriter, r *http.Request, tmpl *template.Template, contentType string) {
	data, err := s.installScriptData(r)
	if err != nil {
		var ie *installError
		if errors.As(err, &ie) {
			http.Error(w, ie.msg, ie.status)
			return
		}
		http.Error(w, "could not render the installer", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		s.logger.Error("render install script failed", "error", err)
		http.Error(w, "could not render the installer", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	// A token-bearing script must not be kept by anything in between.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// handleInstallSh serves the Linux/macOS installer:
//
//	curl -fsSL -H 'Authorization: Bearer <token>' https://<console>/install.sh | sudo bash
func (s *Server) handleInstallSh(w http.ResponseWriter, r *http.Request) {
	s.serveInstallScript(w, r, installShTemplate, "text/x-shellscript; charset=utf-8")
}

// handleCACert serves the control plane's CA certificate. Deliberately
// unauthenticated: a CA certificate is a public key, and an agent needs it
// before it can authenticate to anything. Publishing it lets endpoints
// verify the bus rather than trust it blindly.
func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	path := s.cfg.NATSCreds.CAFile
	if path == "" {
		http.Error(w, "this deployment has no control-plane CA configured", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		s.logger.Error("reading the CA certificate failed", "path", path, "error", err)
		http.Error(w, "CA certificate unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Write(data)
}

// handleInstallPs1 serves the Windows installer (elevated PowerShell):
//
//	irm -Headers @{Authorization='Bearer <token>'} https://<console>/install.ps1 | iex
func (s *Server) handleInstallPs1(w http.ResponseWriter, r *http.Request) {
	s.serveInstallScript(w, r, installPs1Template, "text/plain; charset=utf-8")
}

// handleFullDiskAccessProfile serves a PPPC configuration profile granting
// the agent Full Disk Access on macOS.
//
// This is the only way to grant it without a human clicking through System
// Settings on every Mac: TCC ignores root, and Apple deliberately allows
// only an MDM-delivered profile to pre-authorize it. The profile must be
// pushed by an MDM the Mac is enrolled in — dropping this file on a machine
// and double-clicking it will not work, by design.
func (s *Server) handleFullDiskAccessProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="mustra-full-disk-access.mobileconfig"`)
	if err := pppcProfileTemplate.Execute(w, map[string]string{
		"UUID1": idgen.New(""), "UUID2": idgen.New(""),
	}); err != nil {
		s.logger.Error("render PPPC profile failed", "error", err)
	}
}

var pppcProfileTemplate = template.Must(template.New("pppc").Parse(pppcProfile))

// The identifier is the binary's path with a code-requirement of "identifier
// absent" — an ad-hoc-signed binary has no Team ID to match on, so the
// profile authorizes it by path. Signing the agent with a Developer ID
// would let this be tightened to a real code requirement.
const pppcProfile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>dev.mustra.pppc</string>
  <key>PayloadUUID</key><string>{{.UUID1}}</string>
  <key>PayloadDisplayName</key><string>mustra — endpoint management access</string>
  <key>PayloadDescription</key><string>Grants the mustra agent the access it needs to inventory and manage this Mac. Without it, parts of the filesystem stay unreadable even to root.</string>
  <key>PayloadOrganization</key><string>mustra</string>
  <key>PayloadScope</key><string>System</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.TCC.configuration-profile-policy</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>dev.mustra.pppc.tcc</string>
      <key>PayloadUUID</key><string>{{.UUID2}}</string>
      <key>PayloadDisplayName</key><string>mustra Privacy Preferences</string>
      <key>Services</key>
      <dict>
        <key>SystemPolicyAllFiles</key>
        <array>
          <dict>
            <key>Identifier</key><string>/opt/mustra-agent/mustra-agent</string>
            <key>IdentifierType</key><string>path</string>
            <key>CodeRequirement</key><string>identifier "dev.mustra.agent"</string>
            <key>Authorization</key><string>Allow</string>
            <key>Comment</key><string>Read the whole filesystem, so inventory is complete</string>
          </dict>
        </array>
        <key>SystemPolicySysAdminFiles</key>
        <array>
          <dict>
            <key>Identifier</key><string>/opt/mustra-agent/mustra-agent</string>
            <key>IdentifierType</key><string>path</string>
            <key>CodeRequirement</key><string>identifier "dev.mustra.agent"</string>
            <key>Authorization</key><string>Allow</string>
            <key>Comment</key><string>Administer system settings such as the active directory binding</string>
          </dict>
        </array>
        <key>AppleEvents</key>
        <array>
          <dict>
            <key>Identifier</key><string>/opt/mustra-agent/mustra-agent</string>
            <key>IdentifierType</key><string>path</string>
            <key>CodeRequirement</key><string>identifier "dev.mustra.agent"</string>
            <key>AEReceiverIdentifier</key><string>com.apple.systemevents</string>
            <key>AEReceiverIdentifierType</key><string>bundleID</string>
            <key>AEReceiverCodeRequirement</key><string>identifier "com.apple.systemevents" and anchor apple</string>
            <key>Authorization</key><string>Allow</string>
            <key>Comment</key><string>Drive System Events for actions that have no command-line equivalent</string>
          </dict>
        </array>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`

const installShScript = `#!/usr/bin/env bash
# mustra agent installer (Linux/macOS). Run as root.
set -euo pipefail
# Every file below is created with an explicit mode, but a permissive umask
# in the calling shell (0000 under some docker exec and sudo setups) used to
# leave the root-run binary and its directory world-writable.
umask 022

# Every value the server fills in is single-quoted: data, never shell.
NATS_URL={{sq .NatsURL}}
HAS_CA={{if .HasCA}}1{{end}}
SITE={{sq .Site}}
DOWNLOAD_BASE={{sq .DownloadBase}}
AGENT_VERSION={{sq .AgentVersion}}
# The enrollment token this script was fetched with, which the agent
# exchanges once for a credential of its own. Empty when the script was
# fetched without one: such a script can update an endpoint that is
# already enrolled and refuses to install a new one. There is no shared
# bus password in it either way.
ENROLL_TOKEN={{sq .EnrollToken}}
UPDATE_SIGNING_KEY={{sq .UpdateSigningKey}}
INSTALL_DIR="/opt/mustra-agent"
DATA_DIR="/var/lib/mustra-agent"

# The agent needs full administrative rights on the endpoint: it installs
# and removes packages, reads every process and service, and writes a
# system service unit. Nothing here degrades gracefully to a user install,
# so refuse up front rather than failing halfway with a confusing
# permission error. systemd units live in /etc and launchd's system domain
# is /Library/LaunchDaemons — both are root-only by design, and running
# there is what gives the agent its privileges.
if [ "$(id -u)" -ne 0 ]; then
  echo "the mustra agent must be installed as root -- re-run with sudo:" >&2
  echo "  curl -fsSL ${DOWNLOAD_BASE}/install.sh | sudo bash" >&2
  exit 1
fi

os_name=$(uname -s)
arch_name=$(uname -m)

case "$os_name" in
  Linux) goos=linux ;;
  Darwin) goos=darwin ;;
  *) echo "unsupported OS: $os_name" >&2; exit 1 ;;
esac

case "$arch_name" in
  x86_64|amd64) goarch=amd64 ;;
  arm64|aarch64) goarch=arm64 ;;
  *) echo "unsupported arch: $arch_name" >&2; exit 1 ;;
esac

# A new endpoint needs a token; an enrolled one (or one still holding the
# old shared credential, which the agent trades for its own on start) does
# not. Checked before anything is downloaded or changed.
#
# On Home Assistant OS this runs in the SSH add-on, but the agent lives in
# its own add-on, whose files this container cannot see. There, an agent
# add-on the Supervisor already has installed counts as enrolled: it holds
# its credential in its own /data, and updating it changes nothing else.
haos_addon_installed() {
  local t v
  [ -d /addons ] && command -v jq >/dev/null 2>&1 || return 1
  t=$(cat /run/s6/container_environment/SUPERVISOR_TOKEN 2>/dev/null || printf '%s' "${SUPERVISOR_TOKEN:-}")
  [ -n "$t" ] || return 1
  v=$(curl -fsS -H "Authorization: Bearer $t" http://supervisor/addons/local_mustra_agent/info 2>/dev/null | jq -r '.data.version // empty')
  [ -n "$v" ]
}
already_enrolled() {
  [ -s "$DATA_DIR/agent-credential.json" ] && return 0
  [ -s "$DATA_DIR/enroll.token" ] && return 0
  grep -qs '^MUSTRA_NATS_PASSWORD=.' "$INSTALL_DIR/agent.env" && return 0
  grep -qs 'MUSTRA_NATS_PASSWORD' /Library/LaunchDaemons/com.mustra.agent.plist && return 0
  [ "$goos" = "linux" ] && [ ! -d /run/systemd/system ] && haos_addon_installed && return 0
  return 1
}
if [ -z "$ENROLL_TOKEN" ] && ! already_enrolled; then
  echo "this console requires an enrollment token to install a new agent." >&2
  echo "Create one under Administration -> Client Management -> Enrollment tokens and use the command shown there." >&2
  exit 1
fi

pinned_sha() {
  case "$1" in
{{- range $name, $sum := .Pins}}
    '{{$name}}') echo '{{$sum}}' ;;
{{- end}}
    *) ;;
  esac
}
file_sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f1; else shasum -a 256 "$1" | cut -d ' ' -f1; fi
}

# The Linux install is a systemd unit. Check before downloading or touching
# anything: without systemd the install used to get as far as the unit file
# and die with nothing on stderr. The common case is an SSH session that
# lands in a container rather than on the host, like Home Assistant OS's
# SSH add-on (Alpine under s6), where an agent would report the add-on
# container and vanish when the add-on restarts.
#
# Home Assistant OS is the exception with a way through: its SSH add-on can
# ask the Supervisor to install another add-on, and the agent has one. So
# there, install that instead of refusing.
install_haos_addon() {
  local token="$1" slug=local_mustra_agent dir=/addons/mustra_agent info state
  local no_remote_code=false install_sha256=""
{{- if .NoRemoteCode}}
  # The add-on runs this installer again once it starts, so it is told this
  # script's hash and runs nothing else. A script piped into bash has no file to
  # hash, and that promise can't be made for it.
  no_remote_code=true
  if [ ! -f "$0" ]; then
    echo "Inventory and patching only needs the verified install command on Home Assistant, not the plain one. Nothing was changed." >&2
    return 1
  fi
  install_sha256=$(file_sha "$0")
{{- end}}
  sup() { curl -fsS -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$@"; }
  echo "Installing the mustra agent as a Home Assistant add-on."
  rm -rf "$dir.new" && mkdir -p "$dir.new"
  local tarball addon_expected
  tarball=$(mktemp)
  if ! curl -fsSL --retry 3 --retry-all-errors "${DOWNLOAD_BASE}/downloads/mustra-haos-addon.tar.gz" -o "$tarball"; then
    rm -rf "$dir.new" "$tarball"
    echo "could not download the add-on from ${DOWNLOAD_BASE}" >&2
    return 1
  fi
  # This becomes a script that runs as root on every start, so it is held to
  # the same hash as everything else this installer downloads.
  addon_expected=$(pinned_sha mustra-haos-addon.tar.gz)
  if [ -n "$addon_expected" ] && [ "$(file_sha "$tarball")" != "$addon_expected" ]; then
    rm -rf "$dir.new" "$tarball"
    echo "the add-on from ${DOWNLOAD_BASE} does not match this installer's checksum; nothing was changed" >&2
    return 1
  fi
  if ! tar -xz -C "$dir.new" -f "$tarball"; then
    rm -rf "$dir.new" "$tarball"
    echo "could not unpack the add-on from ${DOWNLOAD_BASE}" >&2
    return 1
  fi
  rm -f "$tarball"
  rm -rf "$dir" && mv "$dir.new" "$dir"
  sup -X POST http://supervisor/store/reload >/dev/null || { echo "the Supervisor would not reload its add-on store" >&2; return 1; }
  info=$(sup "http://supervisor/addons/$slug/info") || { echo "the Supervisor does not list $slug after a reload" >&2; return 1; }
  if [ "$(printf '%s' "$info" | jq -r '.data.version // "none"')" = none ]; then
    echo "Building the add-on image on this host (usually a minute or two)..."
    sup -X POST --max-time 900 "http://supervisor/store/addons/$slug/install" >/dev/null || { echo "the Supervisor could not build or install the add-on" >&2; return 1; }
  elif [ "$(printf '%s' "$info" | jq -r '.data.update_available')" = true ]; then
    echo "Updating the add-on..."
    sup -X POST --max-time 900 "http://supervisor/store/addons/$slug/update" >/dev/null || { echo "the Supervisor could not update the add-on" >&2; return 1; }
  else
    echo "Rebuilding the add-on image..."
    sup -X POST --max-time 900 "http://supervisor/addons/$slug/rebuild" >/dev/null || { echo "the Supervisor could not rebuild the add-on" >&2; return 1; }
  fi
  sup -X POST "http://supervisor/addons/$slug/options" \
    -d "$(jq -n --arg u "$DOWNLOAD_BASE" --arg s "$SITE" --arg t "$ENROLL_TOKEN" --argjson nrc "$no_remote_code" --arg sum "$install_sha256" '{options: {server_url: $u, site: $s, log_level: "info", enroll_token: $t, no_remote_code: $nrc, install_sha256: $sum}, boot: "auto"}')" >/dev/null \
    || { echo "the Supervisor rejected the add-on's options" >&2; return 1; }
  state=$(sup "http://supervisor/addons/$slug/info" | jq -r '.data.state')
  if [ "$state" = started ]; then
    sup -X POST "http://supervisor/addons/$slug/restart" >/dev/null
  else
    sup -X POST "http://supervisor/addons/$slug/start" >/dev/null
  fi || { echo "the add-on would not start" >&2; return 1; }
  # Started is not running: run.sh installs the agent from this server
  # first, so give it time and look, as the systemd path does.
  sleep 30
  if [ "$(sup "http://supervisor/addons/$slug/info" | jq -r '.data.state')" != started ]; then
    echo "the add-on stopped after starting. Its last log lines:" >&2
    sup "http://supervisor/addons/$slug/logs" 2>/dev/null | tail -n 15 >&2 || true
    return 1
  fi
  echo "mustra agent add-on installed and running. It is under Settings > Add-ons as \"mustra agent\"."
}

# OpenRC (Alpine, Gentoo) is the other Linux service manager the agent
# installs under: a supervise-daemon service that restarts it when it exits.
has_openrc() { command -v openrc-run >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1 && [ -d /run/openrc ]; }

if [ "$goos" = "linux" ] && [ "${MUSTRA_NO_SERVICE:-}" != 1 ] && [ ! -d /run/systemd/system ] && ! has_openrc; then
  sup_token=$(cat /run/s6/container_environment/SUPERVISOR_TOKEN 2>/dev/null || printf '%s' "${SUPERVISOR_TOKEN:-}")
  if [ -n "$sup_token" ] && [ -d /addons ] && command -v jq >/dev/null 2>&1; then
    install_haos_addon "$sup_token"
    exit $?
  fi
  init_name=$(cat /proc/1/comm 2>/dev/null || echo unknown)
  echo "this host runs neither systemd nor OpenRC (PID 1 is $init_name), which the Linux agent installs as a service under." >&2
  if [ -e /run/s6 ] || [ -f /.dockerenv ] || [ -n "${SUPERVISOR_TOKEN:-}" ]; then
    echo "It looks like a container, such as the Home Assistant SSH add-on, not the host itself. Nothing was changed." >&2
  fi
  exit 1
fi

# The ?v= is a cache-buster, not a server-side selector: the filename is
# stable across releases, so any CDN in front of this (Cloudflare, here)
# would otherwise keep serving the previous build long after a deploy.
BIN_URL="${DOWNLOAD_BASE}/downloads/mustra-agent-${goos}-${goarch}?v=${AGENT_VERSION}"

echo "Installing mustra agent (${goos}/${goarch}) from ${BIN_URL}"
mkdir -p "$INSTALL_DIR" "$DATA_DIR"
# Explicit ownership and modes, whatever existed before: systemd and
# launchd run what is in here as root, so nothing in it may be writable by
# anyone else, and the data directory holds the agent's credential.
chown 0:0 "$INSTALL_DIR" "$DATA_DIR"
chmod 755 "$INSTALL_DIR"
chmod 700 "$DATA_DIR"

# Every download goes through here. Retries first, then one attempt forced
# to HTTP/1.1: a 13 MB Mach-O pulled through Cloudflare was reset mid-stream
# on every HTTP/2 attempt from one Mac -- "Recv failure: Connection reset by
# peer" -- while a 25 MB tarball over the same connection went through, and
# forcing 1.1 fetched it first try. Whatever inspects that path objects to
# the payload, not the size, so a size-based guess would have missed it.
# What each download must hash to, from the script the install command pinned.

fetch() {
  # The first attempt is speculative, so its noise is suppressed: curl
  # reporting "Recv failure" on a transfer that the next line retries and
  # completes reads like a broken install rather than a working fallback.
  if curl -fsSL --retry 3 --retry-all-errors "$1" -o "$2" 2>/dev/null; then return 0; fi
  echo "download reset, retrying over HTTP/1.1: $1" >&2
  curl -fsSL --http1.1 --retry 3 --retry-all-errors "$1" -o "$2"
}

# Stage and verify the application-owned interpreter before replacing it.
python_target="${goos}-${goarch}"
if [ "$goos" = linux ] && ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then python_target="${python_target}-musl"; fi
PYTHON_URL="${DOWNLOAD_BASE}/downloads/mustra-python-${python_target}.tar.gz?v=${AGENT_VERSION}"
python_stage=$(mktemp -d "$INSTALL_DIR/.python-XXXXXX")
trap 'rm -rf "$python_stage"' EXIT
fetch "$PYTHON_URL" "$python_stage/runtime.tar.gz"
fetch "${DOWNLOAD_BASE}/downloads/mustra-python-${python_target}.tar.gz.sha256?v=${AGENT_VERSION}" "$python_stage/expected"
if command -v sha256sum >/dev/null 2>&1; then
  python_sha=$(sha256sum "$python_stage/runtime.tar.gz" | cut -d ' ' -f1)
else
  python_sha=$(shasum -a 256 "$python_stage/runtime.tar.gz" | cut -d ' ' -f1)
fi
python_expected=$(pinned_sha "mustra-python-${python_target}.tar.gz")
[ -n "$python_expected" ] || python_expected=$(tr -d '\r\n' < "$python_stage/expected")
[ "$python_sha" = "$python_expected" ] || { echo "Python checksum mismatch" >&2; exit 1; }
tar -xzf "$python_stage/runtime.tar.gz" -C "$python_stage"
"$python_stage/python/bin/python3" -I -S -c 'import json,ssl,sqlite3; print("Python runtime ready")'

# The agent binary is staged and verified here, while the old agent is still
# running. It used to be downloaded straight over the live binary *after*
# the service had been stopped, so one reset connection in that single line
# truncated the running agent and left the endpoint with nothing to restart
# -- KeepAlive respawning a zero-length file forever. That is how a Mac went
# dark on 2026-09-21. Nothing below this point can fail on the network.
fetch "$BIN_URL" "$python_stage/mustra-agent"
# The checksum is mandatory. This used to fall back to "the file is not
# empty" whenever the .sha256 could not be fetched -- a fallback for a
# server older than this script, which cannot exist since the same server
# serves both -- and a reset connection on that one request installed a
# truncated binary that segfaulted forever.
fetch "${DOWNLOAD_BASE}/downloads/mustra-agent-${goos}-${goarch}.sha256?v=${AGENT_VERSION}" "$python_stage/agent-expected" ||
  { echo "could not fetch the agent checksum; nothing was changed" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  agent_sha=$(sha256sum "$python_stage/mustra-agent" | cut -d ' ' -f1)
else
  agent_sha=$(shasum -a 256 "$python_stage/mustra-agent" | cut -d ' ' -f1)
fi
# First field only: a .sha256 may hold the bare digest or sha256sum's
# "<digest>  <name>", and a comparison that keeps the filename never
# matches a computed digest.
agent_expected=$(pinned_sha "mustra-agent-${goos}-${goarch}")
[ -n "$agent_expected" ] || agent_expected=$(awk '{print $1; exit}' "$python_stage/agent-expected" | tr -d '\r')
if [ -z "$agent_expected" ] || [ "$agent_sha" != "$agent_expected" ]; then
  echo "agent checksum mismatch: downloaded $agent_sha, expected ${agent_expected:-nothing}; nothing was changed" >&2
  exit 1
fi
chmod 755 "$python_stage/mustra-agent"

# Stop any already-running agent first: overwriting a binary that's
# currently executing fails (ETXTBSY) on a re-install/update, since the
# kernel won't let you truncate+write a file a running process is mapped
# from. Downloading to a temp file and renaming over the target would also
# work without stopping the service, but stopping first is simpler and this
# script is already about to restart it anyway.
# The project was renamed from beacon to mustra. If this host still runs the
# old service, retire it first — otherwise the box ends up with two agents
# registering as two separate endpoints.
# A plain file test, not "list-unit-files | grep -q": under pipefail,
# grep -q exits on the first match, systemctl dies of SIGPIPE, and the
# pipeline's non-zero status makes this branch silently skip -- which
# left both agents running side by side sharing one identity.
if [ -f /etc/systemd/system/beacon-agent.service ]; then
  systemctl disable --now beacon-agent 2>/dev/null || true
  rm -f /etc/systemd/system/beacon-agent.service
  systemctl daemon-reload 2>/dev/null || true
  echo "retired the old beacon-agent service"
fi
# Carry the old identity database across the rename. Without this the
# upgraded agent finds no stored ID, registers fresh, and the host shows up
# as a second endpoint while the original ages out of inventory.
if [ -f /var/lib/beacon-agent/beacon-agent.db ] && [ ! -f "$DATA_DIR/mustra-agent.db" ]; then
  mkdir -p "$DATA_DIR"
  cp /var/lib/beacon-agent/beacon-agent.db "$DATA_DIR/mustra-agent.db"
  echo "migrated the existing agent identity from beacon-agent"
fi
rm -rf /opt/beacon-agent 2>/dev/null || true
systemctl stop mustra-agent 2>/dev/null || true
if has_openrc && [ -f /etc/init.d/mustra-agent ]; then rc-service mustra-agent stop >/dev/null 2>&1 || true; fi
# No -w. That flag writes a *disabled* override into launchd's database, so
# an install that dies between here and the load below leaves the agent not
# merely stopped but permanently off — surviving a reboot, with launchctl
# reporting the service as simply not found. That is exactly the state one
# Mac ended up in. Without -w, the worst case is an agent that is down until
# something reloads it, which a reboot does.
launchctl unload /Library/LaunchDaemons/com.mustra.agent.plist 2>/dev/null || true

rm -rf "$INSTALL_DIR/python.previous"
if [ -d "$INSTALL_DIR/python" ]; then mv "$INSTALL_DIR/python" "$INSTALL_DIR/python.previous"; fi
if ! mv "$python_stage/python" "$INSTALL_DIR/python"; then
  [ ! -d "$INSTALL_DIR/python.previous" ] || mv "$INSTALL_DIR/python.previous" "$INSTALL_DIR/python"
  exit 1
fi
rm -rf "$INSTALL_DIR/python.previous"
chown -R 0:0 "$INSTALL_DIR/python"
chmod -R go-w "$INSTALL_DIR/python"

rm -f "$INSTALL_DIR/mustra-agent.previous"
if [ -f "$INSTALL_DIR/mustra-agent" ]; then mv "$INSTALL_DIR/mustra-agent" "$INSTALL_DIR/mustra-agent.previous"; fi
if ! mv "$python_stage/mustra-agent" "$INSTALL_DIR/mustra-agent"; then
  [ ! -f "$INSTALL_DIR/mustra-agent.previous" ] || mv "$INSTALL_DIR/mustra-agent.previous" "$INSTALL_DIR/mustra-agent"
  echo "could not install the new agent binary; kept the one that was working" >&2
  exit 1
fi
chown 0:0 "$INSTALL_DIR/mustra-agent"
chmod 755 "$INSTALL_DIR/mustra-agent"
# The previous binary is kept until the new one has passed its health check
# below. Deleting it here, as this used to, left nothing to roll back to
# when the new one would not start.
restore_previous_agent() {
  if [ -f "$INSTALL_DIR/mustra-agent.previous" ]; then
    mv -f "$INSTALL_DIR/mustra-agent.previous" "$INSTALL_DIR/mustra-agent"
    echo "restored the previous agent binary" >&2
    return 0
  fi
  return 1
}

# The uninstaller's password, as a bcrypt hash. Rewritten on every install
# and update, so changing it in the console reaches endpoints with the next
# update rather than needing anything else. Empty means no password, and the
# file is removed rather than left holding a stale one.
# Only a token-authorized script carries it, so an update fetched without
# one leaves the existing file as it is.
UNINSTALL_HASH={{sq .UninstallHash}}
if [ -n "$ENROLL_TOKEN" ]; then
  if [ -n "$UNINSTALL_HASH" ]; then
    umask 077
    printf '%s\n' "$UNINSTALL_HASH" > "$INSTALL_DIR/uninstall.hash"
    chmod 600 "$INSTALL_DIR/uninstall.hash"
    umask 022
  else
    rm -f "$INSTALL_DIR/uninstall.hash"
  fi
fi

# The CA that signed the control plane's certificate. Fetched over the
# console's HTTPS, which is already trusted, so the agent can verify the
# bus rather than merely encrypt to it — encryption without verification
# stops eavesdropping but not an impostor, and an impostor on this bus
# owns every endpoint.
NATS_CA_ARGS=""
case "$NATS_URL" in tls://*) HAS_CA=1 ;; esac
if [ -n "$HAS_CA" ]; then
  fetch "${DOWNLOAD_BASE}/ca.crt?v=${AGENT_VERSION}" "$INSTALL_DIR/ca.crt.new"
  ca_expected=$(pinned_sha ca.crt)
  if [ -n "$ca_expected" ] && [ "$(file_sha "$INSTALL_DIR/ca.crt.new")" != "$ca_expected" ]; then
    rm -f "$INSTALL_DIR/ca.crt.new"
    echo "the control plane's CA does not match this install command; stopping" >&2
    exit 1
  fi
  mv -f "$INSTALL_DIR/ca.crt.new" "$INSTALL_DIR/ca.crt"
  chmod 644 "$INSTALL_DIR/ca.crt"
  NATS_CA_ARGS="--nats-ca $INSTALL_DIR/ca.crt"
fi

if [ "$goos" = "darwin" ]; then
  # Re-sign with a stable identifier. The Go linker already ad-hoc-signs
  # darwin binaries (Apple Silicon won't execute one otherwise), but the
  # designated requirement it produces is a cdhash, which changes with
  # every build. A PPPC profile has to name a code requirement that keeps
  # matching across upgrades, so pin the identifier here and let the
  # profile match on that instead of on a hash that won't survive the next
  # release. curl doesn't set the quarantine bit, but a browser download
  # would, so clear it either way.
  /usr/bin/xattr -dr com.apple.quarantine "$INSTALL_DIR/mustra-agent" 2>/dev/null || true
  /usr/bin/codesign --force --sign - --identifier dev.mustra.agent \
    "$INSTALL_DIR/mustra-agent" 2>/dev/null || true

  # The MDM enrollment page, when the console offers one. The agent opens it
  # for the person at the Mac if it starts without Full Disk Access on a Mac
  # that is not enrolled -- enrolling is what lets the MDM grant that access,
  # since Apple ignores a hand-installed grant. Nothing here enrolls the Mac;
  # it cannot, by Apple's design. Rewritten on every install and update, and
  # removed when the console turns the offer off.
  MDM_ENROLL_URL={{sq .MacMDMEnrollURL}}
  if [ -z "$ENROLL_TOKEN" ]; then
    : # an unauthenticated script carries no MDM setting; leave the file as it is
  elif [ -n "$MDM_ENROLL_URL" ]; then
    umask 077
    printf '%s\n' "$MDM_ENROLL_URL" > "$INSTALL_DIR/mdm-enroll.url"
    chmod 600 "$INSTALL_DIR/mdm-enroll.url"
    umask 022
  else
    rm -f "$INSTALL_DIR/mdm-enroll.url"
  fi
fi

# Enrollment. The token goes in a root-only file the agent reads once,
# trades for a credential of its own (kept in $DATA_DIR, 0600) and then
# deletes. It is never put on the command line, where argv is readable by
# every local user, nor in the service's environment, which every command
# the agent runs would inherit.
if [ -n "$ENROLL_TOKEN" ]; then
  umask 077
  printf '%s\n' "$ENROLL_TOKEN" > "$DATA_DIR/enroll.token"
  chmod 600 "$DATA_DIR/enroll.token"
  umask 022
  if [ -n "$UPDATE_SIGNING_KEY" ]; then
    printf '%s\n' "$UPDATE_SIGNING_KEY" > "$DATA_DIR/update-signing.pub"
    chmod 644 "$DATA_DIR/update-signing.pub"
  fi
  # A shared bus password left by an older install is no longer needed.
  rm -f "$INSTALL_DIR/agent.env"
elif [ "$goos" = "darwin" ] && [ ! -s "$DATA_DIR/agent-credential.json" ] && [ ! -f "$INSTALL_DIR/agent.env" ] &&
     grep -qs MUSTRA_NATS_PASSWORD /Library/LaunchDaemons/com.mustra.agent.plist; then
  # An older macOS install kept the shared password in the LaunchDaemon's
  # environment, which the plist written below no longer has. Carry it to
  # the root-only file the agent reads, so it can still trade it for a
  # credential of its own.
  legacy_user=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:MUSTRA_NATS_USER' /Library/LaunchDaemons/com.mustra.agent.plist 2>/dev/null || true)
  legacy_pass=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:MUSTRA_NATS_PASSWORD' /Library/LaunchDaemons/com.mustra.agent.plist 2>/dev/null || true)
  if [ -n "$legacy_pass" ]; then
    umask 077
    printf 'MUSTRA_NATS_USER=%s\nMUSTRA_NATS_PASSWORD=%s\n' "$legacy_user" "$legacy_pass" > "$INSTALL_DIR/agent.env"
    chmod 600 "$INSTALL_DIR/agent.env"
    umask 022
  fi
fi

# Something else supervises the agent (the Home Assistant add-on's run.sh):
# leave the files in place and tell it how to start them.
{{- if .NoRemoteCode}}
# Inventory-and-patching mode: this agent refuses code from the server. Only an
# administrator on this machine can remove this file.
touch "$INSTALL_DIR/no-remote-code"
chmod 644 "$INSTALL_DIR/no-remote-code"
echo "inventory-and-patching mode: this endpoint will refuse code from the server"
{{- end}}
if [ "${MUSTRA_NO_SERVICE:-}" = 1 ]; then
  # Sourced by the supervisor, so quoted; the values are validated
  # server-side and contain no quotes.
  cat > "$INSTALL_DIR/service.env" <<SVCEOF
MUSTRA_NATS_URL='$NATS_URL'
MUSTRA_SITE='$SITE'
MUSTRA_DATA_DIR='$DATA_DIR'
MUSTRA_NATS_CA='$( [ -f "$INSTALL_DIR/ca.crt" ] && echo "$INSTALL_DIR/ca.crt" )'
SVCEOF
  rm -f "$INSTALL_DIR/mustra-agent.previous"
  echo "mustra agent installed in $INSTALL_DIR; not registering a service (MUSTRA_NO_SERVICE=1)."
  exit 0
fi

if [ "$goos" = "linux" ] && [ ! -d /run/systemd/system ] && has_openrc; then
  # supervise-daemon restarts the agent whenever it exits. That is also how
  # a self-update takes effect here: without systemd the updater asks the
  # running agent to exit and leaves starting the new binary to whatever
  # supervises it.
  cat > /etc/init.d/mustra-agent <<RCEOF
#!/sbin/openrc-run
description="mustra endpoint agent"
supervisor=supervise-daemon
command="$INSTALL_DIR/mustra-agent"
command_args="--nats-url $NATS_URL --site $SITE --data-dir $DATA_DIR $NATS_CA_ARGS"
respawn_delay=5
respawn_max=0
output_log=/var/log/mustra-agent.log
error_log=/var/log/mustra-agent.log

depend() {
	need net
	after firewall
}

start_pre() {
	# The identity and credential live here.
	checkpath -d -m 0700 -o root:root "$DATA_DIR"
}
RCEOF
  chmod 755 /etc/init.d/mustra-agent
  rc-update add mustra-agent default >/dev/null
  rc-service mustra-agent start >/dev/null
  # As with systemd: "started" only means it was launched. An agent that
  # cannot reach or trust the bus exits at once and supervise-daemon starts
  # it again every five seconds, so a changing PID means a crash loop.
  sleep 3
  first_pid=$(pidof mustra-agent 2>/dev/null || true)
  sleep 8
  if [ -z "$first_pid" ] || [ "$(pidof mustra-agent 2>/dev/null || true)" != "$first_pid" ]; then
    echo "mustra-agent was installed but keeps exiting. Its last log lines:" >&2
    tail -n 15 /var/log/mustra-agent.log >&2 2>/dev/null || true
    if restore_previous_agent; then
      rc-service mustra-agent restart >/dev/null 2>&1 || true
    fi
    exit 1
  fi
  rm -f "$INSTALL_DIR/mustra-agent.previous"
  echo "mustra-agent installed and started via OpenRC."
elif [ "$goos" = "linux" ]; then
  cat > /etc/systemd/system/mustra-agent.service <<UNIT
[Unit]
Description=mustra endpoint agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/mustra-agent --nats-url $NATS_URL --site $SITE --data-dir $DATA_DIR $NATS_CA_ARGS
Restart=always
RestartSec=5s
StateDirectory=mustra-agent
# The identity and credential live here; systemd resets the mode on every
# start, so it has to be stated rather than set once by the installer.
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now mustra-agent
  # "Started" only means the process was launched. An agent that cannot
  # reach or trust the bus exits within a second and systemd restarts it
  # every five, so give it one restart interval and look: a restart count
  # above zero means it is crash-looping, and the install should say so
  # instead of reporting success for an endpoint that never appears.
  sleep 8
  if [ "$(systemctl show -p NRestarts --value mustra-agent 2>/dev/null || echo 0)" != "0" ] || ! systemctl is-active --quiet mustra-agent; then
    echo "mustra-agent was installed but keeps exiting. Its last log lines:" >&2
    journalctl -u mustra-agent -n 15 --no-pager >&2 2>/dev/null || true
    if restore_previous_agent; then
      systemctl reset-failed mustra-agent 2>/dev/null || true
      systemctl restart mustra-agent || true
    fi
    exit 1
  fi
  rm -f "$INSTALL_DIR/mustra-agent.previous"
  echo "mustra-agent installed and started via systemd."
elif [ "$goos" = "darwin" ]; then
  PLIST=/Library/LaunchDaemons/com.mustra.agent.plist
  # No EnvironmentVariables: nothing secret belongs in a job's environment,
  # which every command the agent runs inherits.
  PLIST_CA_ARGS=""
  if [ -f "$INSTALL_DIR/ca.crt" ]; then
    PLIST_CA_ARGS="    <string>--nats-ca</string><string>$INSTALL_DIR/ca.crt</string>
"
  fi
  cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.mustra.agent</string>
  <key>ProgramArguments</key><array>
    <string>$INSTALL_DIR/mustra-agent</string>
    <string>--nats-url</string><string>$NATS_URL</string>
    <string>--site</string><string>$SITE</string>
    <string>--data-dir</string><string>$DATA_DIR</string>
$PLIST_CA_ARGS  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <!-- A launchd job gets 256 descriptors by default, and the file watcher
       needs one per watched file on macOS (kqueue has no directory watch).
       The agent that ran out went quiet ninety seconds after starting, with
       nowhere to look: launchd discards a job's output unless it is told
       where to put it, so there was no log to read either. Both fixed
       here. -->
  <key>SoftResourceLimits</key><dict>
    <key>NumberOfFiles</key><integer>4096</integer>
  </dict>
  <key>HardResourceLimits</key><dict>
    <key>NumberOfFiles</key><integer>8192</integer>
  </dict>
  <key>StandardOutPath</key><string>/var/log/mustra-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/mustra-agent.log</string>
</dict></plist>
PLIST_EOF
  chmod 600 "$PLIST"
  # "load -w" clears the plist's own Disabled key, but launchd keeps a
  # separate per-service disabled flag that "launchctl disable" sets and
  # "load -w" does not touch. A daemon disabled once -- by hand, or by
  # somebody turning it off under Login Items -- stayed disabled through
  # every later reinstall, and came back looking installed while never
  # starting at boot. Clearing it is what makes the install idempotent.
  launchctl enable system/com.mustra.agent 2>/dev/null || true
  launchctl load -w "$PLIST"
  # Verified, not assumed. An install that writes a plist and fails to load
  # it leaves a machine that looks installed and reports nothing, which is
  # the hardest kind of endpoint to notice.
  # Loaded is not running: give KeepAlive one cycle and check the job has a
  # live process that has not been restarted, as the systemd branch does.
  sleep 8
  if launchctl print system/com.mustra.agent 2>/dev/null | grep -q 'state = running' &&
     [ "$(launchctl print system/com.mustra.agent 2>/dev/null | awk -F'= ' '/runs =/{print $2; exit}')" = "1" ]; then
    rm -f "$INSTALL_DIR/mustra-agent.previous"
    echo "mustra-agent installed and started via launchd."
  else
    echo "mustra-agent was installed but is not staying up under launchd. Its last log lines:" >&2
    tail -n 15 /var/log/mustra-agent.log >&2 2>/dev/null || true
    if restore_previous_agent; then
      launchctl kickstart -k system/com.mustra.agent 2>/dev/null || true
    fi
    exit 1
  fi

  # Menu bar helper. A LaunchAgent, not a daemon: the agent above runs as
  # root with no GUI session, and nothing without a session can draw in the
  # menu bar. This is the same split as the Windows tray helper.
  #
  # Written as a script the way Self Service is, because a compiled status
  # item would need AppKit, which needs cgo, which the agent build does not
  # have -- every binary here is CGO_ENABLED=0 so it can cross-compile from
  # Linux. It would also be unsigned, and Gatekeeper is friendlier to a
  # script an installer wrote as root than to an unsigned Mach-O.
  MENUBAR_DIR="/Library/Application Support/mustra"
  MENUBAR_JS="$MENUBAR_DIR/menubar.js"
  mkdir -p "$MENUBAR_DIR"
  cat > "$MENUBAR_JS" <<'MENUBAR_EOF'
{{.MacMenuBar}}
MENUBAR_EOF
  chmod 644 "$MENUBAR_JS"

  MENUBAR_PLIST=/Library/LaunchAgents/dev.mustra.menubar.plist
  cat > "$MENUBAR_PLIST" <<MENUBAR_PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.mustra.menubar</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/osascript</string>
    <string>-l</string><string>JavaScript</string>
    <string>$MENUBAR_JS</string>
  </array>
  <key>RunAtLoad</key><true/>
  <!-- No KeepAlive on purpose. The menu has a "Quit menu bar icon" item,
       and launchd would put it straight back, which is not a quit. It
       returns at the next login. -->
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>/tmp/mustra-menubar.log</string>
  <key>StandardErrorPath</key><string>/tmp/mustra-menubar.log</string>
</dict></plist>
MENUBAR_PLIST_EOF
  chmod 644 "$MENUBAR_PLIST"

  # Start it in the session that is logged in right now, so it appears
  # without making somebody log out. There may not be one -- a Mac
  # installed over SSH, or sitting at the login window -- and that is fine:
  # RunAtLoad brings it up when somebody next logs in.
  CONSOLE_UID="$(/usr/bin/stat -f %u /dev/console 2>/dev/null || echo 0)"
  if [ "$CONSOLE_UID" != "0" ]; then
    launchctl bootout "gui/$CONSOLE_UID/dev.mustra.menubar" 2>/dev/null || true
    # bootout returns before the job is actually gone, and bootstrap fails
    # while the old one is still there. Re-running the installer therefore
    # left the previous helper running and reported "at the next login",
    # which is the one case where somebody is standing in front of the
    # machine wondering why nothing changed.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      launchctl print "gui/$CONSOLE_UID/dev.mustra.menubar" >/dev/null 2>&1 || break
      sleep 0.3
    done
    if launchctl bootstrap "gui/$CONSOLE_UID" "$MENUBAR_PLIST" 2>/dev/null; then
      echo "menu bar icon started for the logged-in user."
    else
      echo "menu bar icon installed; it will appear at the next login." >&2
    fi
  else
    echo "no user is logged in; the menu bar icon will appear at the next login."
  fi

  # Self Service as a real application in /Applications, so it is findable
  # in Spotlight and the Launchpad rather than being a URL people have to
  # remember. The daemon above is what manages the machine; this bundle is
  # only a launcher for the window the daemon already serves on loopback,
  # which is why it is a script rather than a compiled binary and why it
  # needs no privileges of its own.
  APP="/Applications/Mustra Self Service.app"
  rm -rf "$APP"
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
  cat > "$APP/Contents/Info.plist" <<APP_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Mustra Self Service</string>
  <key>CFBundleDisplayName</key><string>Mustra Self Service</string>
  <key>CFBundleIdentifier</key><string>dev.mustra.selfservice</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>mustra-selfservice</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
APP_EOF
  cat > "$APP/Contents/MacOS/mustra-selfservice" <<'LAUNCH_EOF'
#!/bin/bash
# Opens the Self Service window the local agent serves. Waits briefly for
# the daemon, since clicking the icon right after a reboot can beat launchd
# to the port.
URL="http://127.0.0.1:8137/"
for _ in $(seq 1 20); do
  if /usr/bin/curl -fsS --max-time 1 "$URL" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
if ! /usr/bin/curl -fsS --max-time 1 "$URL" >/dev/null 2>&1; then
  /usr/bin/osascript -e 'display alert "Mustra Self Service" message "The mustra agent is not running on this Mac. It starts automatically at boot; if this keeps happening, contact whoever manages this machine." as critical'
  exit 1
fi
# A dedicated window rather than a tab in whatever is already open: Chrome
# and Edge support app mode, Safari does not, so fall back to the default
# browser.
for browser in "/Applications/Google Chrome.app" "/Applications/Microsoft Edge.app" "/Applications/Brave Browser.app"; do
  if [ -d "$browser" ]; then
    open -na "$browser" --args --app="$URL" --window-size=1000,780
    exit 0
  fi
done
open "$URL"
LAUNCH_EOF
  chmod +x "$APP/Contents/MacOS/mustra-selfservice"
  curl -fsSL "${DOWNLOAD_BASE}/static/brand/mustra.icns" -o "$APP/Contents/Resources/AppIcon.icns" 2>/dev/null || true
  # Ad-hoc sign so Gatekeeper treats it as a stable identity rather than
  # re-prompting on every launch, and clear the quarantine bit curl never
  # sets but a manual download would.
  /usr/bin/xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true
  /usr/bin/codesign --force --deep --sign - "$APP" 2>/dev/null || true
  # Make Finder and the Dock pick up the new icon immediately.
  /usr/bin/touch "$APP"
  echo "Mustra Self Service installed in /Applications."
fi

# A local uninstaller, so removing the agent from the machine itself is a
# documented act rather than guesswork about which files to delete. Windows
# has had one through Add/Remove Programs; this is the same thing for the
# platforms that do not have an equivalent.
cat > "$INSTALL_DIR/uninstall.sh" <<'UNINSTALL_EOF'
#!/usr/bin/env bash
# Removes the mustra agent from this machine.
set -u
if [ "$(id -u)" -ne 0 ]; then
  echo "run this with sudo" >&2
  exit 1
fi
INSTALL_DIR=/opt/mustra-agent
DATA_DIR=/var/lib/mustra-agent

# The password, when the console set one.
#
# What this stops is the person using the machine removing the agent
# because it is in their way. It is not a defence against an administrator
# of this machine and could not be: whoever can run this can also stop the
# service and delete the directory by hand. Better to say so than to imply
# a guarantee nobody can keep.
if [ -s "$INSTALL_DIR/uninstall.hash" ]; then
  attempts=0
  while :; do
    attempts=$((attempts + 1))
    printf "Uninstall password: " >&2
    stty -echo 2>/dev/null || true
    IFS= read -r password
    stty echo 2>/dev/null || true
    printf "\n" >&2
    if printf '%s\n' "$password" | "$INSTALL_DIR/mustra-agent" \
         -verify-uninstall-password "$INSTALL_DIR/uninstall.hash" 2>/dev/null; then
      break
    fi
    if [ "$attempts" -ge 3 ]; then
      echo "Uninstall cancelled." >&2
      exit 1
    fi
    echo "That password is not correct." >&2
  done
fi

# The recovery job first (internal/agent/recovery.go): left behind, it
# would find nothing to run, but it should not outlive the agent.
if [ "$(uname -s)" = "Darwin" ]; then
  launchctl bootout system/com.mustra.agent.recover 2>/dev/null || true
  rm -f /Library/LaunchDaemons/com.mustra.agent.recover.plist
elif command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/mustra-agent-recover.timer ]; then
  systemctl disable --now mustra-agent-recover.timer 2>/dev/null || true
  rm -f /etc/systemd/system/mustra-agent-recover.timer /etc/systemd/system/mustra-agent-recover.service
fi
rm -f /etc/cron.d/mustra-agent-recover

if [ "$(uname -s)" = "Darwin" ]; then
  launchctl unload /Library/LaunchDaemons/com.mustra.agent.plist 2>/dev/null || true
  rm -f /Library/LaunchDaemons/com.mustra.agent.plist
  # The menu bar helper runs in the logged-in user's session, so stopping it
  # means reaching into that session. Removing the plist alone would leave
  # the icon sitting there until the user logged out, on a Mac that no
  # longer has an agent behind it.
  MENUBAR_UID="$(/usr/bin/stat -f %u /dev/console 2>/dev/null || echo 0)"
  if [ "$MENUBAR_UID" != "0" ]; then
    launchctl bootout "gui/$MENUBAR_UID/dev.mustra.menubar" 2>/dev/null || true
  fi
  rm -f /Library/LaunchAgents/dev.mustra.menubar.plist
  rm -rf "/Library/Application Support/mustra"
  rm -rf "/Applications/Mustra Self Service.app"
elif [ -f /etc/init.d/mustra-agent ] && command -v rc-service >/dev/null 2>&1; then
  rc-service mustra-agent stop 2>/dev/null || true
  rc-update del mustra-agent default 2>/dev/null || true
  rm -f /etc/init.d/mustra-agent /var/log/mustra-agent.log
else
  systemctl disable --now mustra-agent 2>/dev/null || true
  rm -f /etc/systemd/system/mustra-agent.service
  systemctl daemon-reload 2>/dev/null || true
fi
rm -rf "$INSTALL_DIR" "$DATA_DIR"
echo "mustra removed. This endpoint will stop reporting to the console."
UNINSTALL_EOF
chmod 700 "$INSTALL_DIR/uninstall.sh"
echo "To remove mustra from this machine: sudo $INSTALL_DIR/uninstall.sh"

# Full Disk Access, which root does not confer.
#
# macOS guards Desktop, Documents, Downloads, Mail, Photos and the TCC
# database behind TCC, and TCC does not care that a process is root. Without
# Full Disk Access the agent has every Unix privilege there is and still
# cannot list a user's Documents, so a sensor over those paths reports
# nothing and looks like it passed.
#
# Explained here, never checked or prompted here. TCC answers per binary, so
# reading its database from this script tests this script's access, and said
# "NOT granted" about an agent that had it. An installer also runs unattended
# -- from a console update, from a launchd job -- and the first version of this
# put up a blocking osascript dialog: it waited for a button nobody was
# necessarily there to press, and every relaunch of the job put up another. The
# agent checks and raises it once at startup instead, which is right after any
# install or update, because the installer restarts the agent.
if [ "$goos" = "darwin" ]; then
  echo ""
  echo "  The agent needs Full Disk Access to see Desktop, Documents, Downloads,"
  echo "  Mail or Photos on this Mac, even though it runs as root. If it doesn't"
  echo "  have it, it posts a notification when it starts."
  echo ""
  echo "    System Settings > Privacy & Security > Full Disk Access, then +"
  echo "    The picker hides /opt, so press Cmd-Shift-G and paste:"
  echo "        $INSTALL_DIR/mustra-agent"
  echo ""
fi
`

const installPs1Script = `# mustra agent installer (Windows). Run from an elevated PowerShell.
$ErrorActionPreference = "Stop"

# The agent runs as a Windows service under LocalSystem, which is what
# gives it the rights to install software and read every process. Creating
# that service needs an elevated shell, so check before downloading
# anything rather than failing at New-Service.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "the mustra agent must be installed from an elevated PowerShell (Run as Administrator)"
  exit 1
}

# One install at a time on this machine. Update in the console launches a
# detached installer per click, and on 2026-09-28 three clicks in a minute
# ran three at once: they stopped and deleted each other's service and
# wrote the same exe concurrently, leaving dc01 with a 2.4 MB fragment of a
# 15 MB binary that Windows refused as "not a valid Win32 application".
# A later install waits for the earlier one rather than racing it. The
# mutex is released when this process exits, however it exits.
$InstallLock = New-Object System.Threading.Mutex($false, "Global\MustraAgentInstall")
try { $LockHeld = $InstallLock.WaitOne([TimeSpan]::FromMinutes(10)) }
catch [System.Threading.AbandonedMutexException] { $LockHeld = $true }
if (-not $LockHeld) {
  Write-Error "another mustra install on this machine has been running for 10 minutes; not starting a second one"
  exit 1
}

# Every value the server fills in is a single-quoted literal: data, never
# code. A site spliced inside double quotes used to run $(...) from the URL.
$NatsUrl = {{psq .NatsURL}}
$HasCa = {{if .HasCA}}$true{{else}}$false{{end}}
# What each download must hash to, from the script the install command pinned.
$Pins = @{ {{- range $name, $sum := .Pins}} '{{$name}}' = '{{$sum}}'; {{- end}} }
$Site = {{psq .Site}}
$DownloadBase = {{psq .DownloadBase}}
$AgentVersion = {{psq .AgentVersion}}
# The enrollment token this script was fetched with; empty when it was
# fetched without one, in which case it only updates an endpoint that is
# already enrolled. There is no shared bus password in it either way.
$EnrollToken = {{psq .EnrollToken}}
$UpdateSigningKey = {{psq .UpdateSigningKey}}
$InstallDir = "C:\Program Files\mustra-agent"
$DataDir = "C:\ProgramData\mustra-agent"

function Test-Enrolled {
  if (Test-Path "$DataDir\agent-credential.json") { return $true }
  if (Test-Path "$DataDir\enroll.token") { return $true }
  if (Test-Path "$InstallDir\agent.env") { return $true }
  if ([Environment]::GetEnvironmentVariable("MUSTRA_NATS_PASSWORD", "Machine")) { return $true }
  return $false
}
if (-not $EnrollToken -and -not (Test-Enrolled)) {
  Write-Error "this console requires an enrollment token to install a new agent. Create one under Administration -> Client Management -> Enrollment tokens and use the command shown there."
  exit 1
}

# Restricts a path to SYSTEM and Administrators (plus read/execute for
# Users when asked), replacing whatever it inherited: ProgramData and
# Program Files both grant Users read by default, and the data directory
# holds the agent's credential.
function Set-AgentAcl([string]$Path, [bool]$UsersRead) {
  $grants = @("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
  if ($UsersRead) { $grants += "*S-1-5-32-545:(OI)(CI)RX" }
  $out = & icacls.exe $Path /inheritance:r /grant:r @grants 2>&1
  if ($LASTEXITCODE -ne 0) { throw "could not restrict access to $Path : $out" }
}
function Set-FileAcl([string]$Path) {
  $out = & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" 2>&1
  if ($LASTEXITCODE -ne 0) { throw "could not restrict access to $Path : $out" }
}
function Write-Ascii([string]$Path, [string]$Text) {
  [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false))
}

$arch = "amd64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $arch = "arm64" }

# ?v= busts any CDN cache in front of the console -- the filename is the
# same after every release, so without it a fresh install can be handed a
# months-old binary.
$BinUrl = "$DownloadBase/downloads/mustra-agent-windows-$arch.exe?v=$AgentVersion"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
{{- if .NoRemoteCode}}
# Inventory-and-patching mode: this agent refuses code from the server. Only an
# administrator on this machine can remove this file.
New-Item -ItemType File -Force -Path "$InstallDir\no-remote-code" | Out-Null
Write-Host "inventory-and-patching mode: this endpoint will refuse code from the server"
{{- end}}
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
# The service runs what is in the install directory as LocalSystem, so no
# one else may write there; the data directory is the agent's alone.
Set-AgentAcl $InstallDir $true
Set-AgentAcl $DataDir $false

$PythonStage = Join-Path $InstallDir (".python-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $PythonStage | Out-Null
try {
  $PythonUrl = "$DownloadBase/downloads/mustra-python-windows-$arch.zip?v=$AgentVersion"
  Invoke-WebRequest -UseBasicParsing -Uri $PythonUrl -OutFile "$PythonStage\runtime.zip"
  # -UseBasicParsing hands back .Content as a byte array on Windows
  # PowerShell 5.1 and as a string on PowerShell 7, and only one of those
  # has .Trim().
  $ExpectedRaw = (Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/downloads/mustra-python-windows-$arch.zip.sha256?v=$AgentVersion").Content
  if ($ExpectedRaw -is [byte[]]) { $ExpectedRaw = [System.Text.Encoding]::UTF8.GetString($ExpectedRaw) }
  $Expected = $ExpectedRaw.Trim()
  if ($Pins["mustra-python-windows-$arch.zip"]) { $Expected = $Pins["mustra-python-windows-$arch.zip"] }
  if ((Get-FileHash "$PythonStage\runtime.zip" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) { throw "Python checksum mismatch" }
  Expand-Archive -Path "$PythonStage\runtime.zip" -DestinationPath $PythonStage
  # No quotes inside the -c argument. Windows PowerShell 5.1 rewrites the
  # arguments it hands a native executable and strips embedded double
  # quotes, so python received print(Python runtime ready) and died of a
  # SyntaxError -- reported as a failed runtime, which it was not. The
  # imports are the check; the exit code is how it reports.
  & "$PythonStage\python\python.exe" -I -S -c 'import json, ssl, sqlite3'
  if ($LASTEXITCODE -ne 0) { throw "Bundled Python validation failed" }
  Write-Host "Python runtime ready"
} catch {
  Remove-Item $PythonStage -Recurse -Force -ErrorAction SilentlyContinue
  throw
}

# The agent binary is staged and verified while the old agent still runs,
# as the shell installer does since a reset download truncated a live Mac
# agent on 2026-09-21. This script used to stop the service and then
# download straight over the exe, so any failed or interrupted transfer
# left the endpoint with a broken binary and no service.
$AgentStage = "$InstallDir\mustra-agent.exe.new"
Remove-Item -Force $AgentStage -ErrorAction SilentlyContinue
Write-Host "Downloading $BinUrl"
Invoke-WebRequest -UseBasicParsing -Uri $BinUrl -OutFile $AgentStage
$ExpectedRaw = (Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/downloads/mustra-agent-windows-$arch.exe.sha256?v=$AgentVersion").Content
if ($ExpectedRaw -is [byte[]]) { $ExpectedRaw = [System.Text.Encoding]::UTF8.GetString($ExpectedRaw) }
# First field only: a .sha256 may be the bare digest or "<digest>  <name>".
$Expected = ($ExpectedRaw.Trim() -split '\s+')[0].ToLowerInvariant()
if ($Pins["mustra-agent-windows-$arch.exe"]) { $Expected = $Pins["mustra-agent-windows-$arch.exe"] }
$Actual = (Get-FileHash $AgentStage -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) {
  Remove-Item -Force $AgentStage -ErrorAction SilentlyContinue
  throw "agent checksum mismatch: downloaded $Actual, expected $Expected. Nothing was changed."
}

# Stop (and remove) any existing service first: Windows locks a running
# executable's file, so overwriting mustra-agent.exe while the service is
# still using it fails on a re-install/update.
# Retire the pre-rename service if this host still has it, so the machine
# doesn't end up running two agents.
if (Get-Service beacon-agent -ErrorAction SilentlyContinue) {
  Stop-Service beacon-agent -ErrorAction SilentlyContinue
  sc.exe delete beacon-agent | Out-Null
  Write-Host "retired the old beacon-agent service"
}
$OldData = "C:\ProgramData\beacon-agent\beacon-agent.db"
if ((Test-Path $OldData) -and -not (Test-Path "$DataDir\mustra-agent.db")) {
  New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
  Copy-Item $OldData "$DataDir\mustra-agent.db"
  Write-Host "migrated the existing agent identity from beacon-agent"
}
# Updated in place rather than deleted and recreated. sc.exe delete only
# marks a service for deletion while anything holds a handle to it (the
# Services console, a monitoring agent), and New-Service then failed after
# the binary had already been replaced, leaving no service at all.
$ExistingService = Get-Service mustra-agent -ErrorAction SilentlyContinue
if ($ExistingService) {
  if ($ExistingService.Status -ne 'Stopped') {
    Stop-Service mustra-agent -Force
    $ExistingService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
  }
}

try {
  Remove-Item "$InstallDir\python.previous" -Recurse -Force -ErrorAction SilentlyContinue
  if (Test-Path "$InstallDir\python") { Move-Item "$InstallDir\python" "$InstallDir\python.previous" }
  try { Move-Item "$PythonStage\python" "$InstallDir\python" } catch {
    if (Test-Path "$InstallDir\python.previous") { Move-Item "$InstallDir\python.previous" "$InstallDir\python" }
    throw
  }
  Remove-Item "$InstallDir\python.previous" -Recurse -Force -ErrorAction SilentlyContinue
} finally { Remove-Item $PythonStage -Recurse -Force -ErrorAction SilentlyContinue }

# Nothing below can fail on the network. Keep the old binary until the new
# one is in place, so a failed move puts back something that runs.
Remove-Item -Force "$InstallDir\mustra-agent.exe.previous" -ErrorAction SilentlyContinue
if (Test-Path "$InstallDir\mustra-agent.exe") { Move-Item -Force "$InstallDir\mustra-agent.exe" "$InstallDir\mustra-agent.exe.previous" }
try { Move-Item -Force $AgentStage "$InstallDir\mustra-agent.exe" } catch {
  if (Test-Path "$InstallDir\mustra-agent.exe.previous") { Move-Item -Force "$InstallDir\mustra-agent.exe.previous" "$InstallDir\mustra-agent.exe" }
  throw
}
# The previous binary stays until the new one has been seen running below.

# The uninstaller's password, as a bcrypt hash -- see the same block in the
# shell installer. ASCII with no BOM, because the agent reads this file as
# bytes and a BOM would be part of the hash.
# Only a token-authorized script carries it, so an update fetched without
# one leaves the existing file alone.
$UninstallHash = {{psq .UninstallHash}}
$HashPath = "$InstallDir\uninstall.hash"
if ($EnrollToken) {
  if ($UninstallHash) {
    # No trailing newline and no backtick escape: a backtick would end the Go
    # raw string this script lives inside, and the reader trims whitespace.
    Write-Ascii $HashPath $UninstallHash
  } elseif (Test-Path $HashPath) {
    Remove-Item -Force $HashPath
  }
}

$CaArgs = ""
if ($HasCa -or $NatsUrl -like "tls://*") {
  Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/ca.crt?v=$AgentVersion" -OutFile "$InstallDir\ca.crt"
  if ($Pins["ca.crt"] -and (Get-FileHash "$InstallDir\ca.crt" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Pins["ca.crt"]) {
    Remove-Item -Force "$InstallDir\ca.crt" -ErrorAction SilentlyContinue
    throw "The control plane's CA does not match this install command. Stopping."
  }
  $CaArgs = ' --nats-ca "' + $InstallDir + '\ca.crt"'
}

# Credentials never go in Machine environment variables any more. Those are
# readable by every local user (HKLM\...\Session Manager\Environment), are
# inherited by every command the agent runs, and a running service does not
# even see a new one until a reboot.
$LegacyUser = [Environment]::GetEnvironmentVariable("MUSTRA_NATS_USER", "Machine")
$LegacyPass = [Environment]::GetEnvironmentVariable("MUSTRA_NATS_PASSWORD", "Machine")
if ($EnrollToken) {
  # The agent trades this once for a credential of its own and deletes it.
  Write-Ascii "$DataDir\enroll.token" $EnrollToken
  if ($UpdateSigningKey) { Write-Ascii "$DataDir\update-signing.pub" $UpdateSigningKey }
  Remove-Item -Force "$InstallDir\agent.env" -ErrorAction SilentlyContinue
} elseif ($LegacyPass -and -not (Test-Path "$DataDir\agent-credential.json")) {
  # An older install's shared password moves from the world-readable
  # Machine environment into a file only SYSTEM and Administrators can
  # read, which the agent reads itself and then trades for its own
  # credential.
  $nl = [Environment]::NewLine
  Write-Ascii "$InstallDir\agent.env" ("MUSTRA_NATS_USER=" + $LegacyUser + $nl + "MUSTRA_NATS_PASSWORD=" + $LegacyPass + $nl)
  Set-FileAcl "$InstallDir\agent.env"
}
foreach ($name in @("MUSTRA_NATS_USER", "MUSTRA_NATS_PASSWORD", "MUSTRA_NATS_CA")) {
  [Environment]::SetEnvironmentVariable($name, $null, "Machine")
}

$binPath = '"' + $InstallDir + '\mustra-agent.exe" --nats-url ' + $NatsUrl + ' --site ' + $Site + ' --data-dir "' + $DataDir + '"' + $CaArgs
if ($ExistingService) {
  # The registry value rather than sc.exe config binPath=, because Windows
  # PowerShell 5.1 strips the embedded quotes a path with spaces needs when
  # it hands arguments to a native executable.
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mustra-agent" -Name ImagePath -Value $binPath
  Set-Service -Name mustra-agent -StartupType Automatic
} else {
  New-Service -Name mustra-agent -BinaryPathName $binPath -DisplayName "mustra endpoint agent" -StartupType Automatic | Out-Null
}

# LocalSystem is New-Service's default, but say it explicitly: the account
# is what gives the agent the rights to install software, read every
# process, and manage services. Recovery settings so a crash doesn't leave
# an endpoint unmanaged until someone notices.
sc.exe config mustra-agent obj= LocalSystem | Out-Null
sc.exe failure mustra-agent reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
# Without the flag, the actions above run only when the process crashes, not
# when the agent exits cleanly with an error -- which is how it reports a
# failure it could not recover from.
sc.exe failureflag mustra-agent 1 | Out-Null
sc.exe description mustra-agent "Keeps this endpoint inventoried, patched, and manageable by mustra." | Out-Null

Start-Service mustra-agent
# Started is not staying up: give it a few seconds, and if it has stopped,
# put the previous binary back rather than leaving the endpoint without an
# agent that can be told anything.
Start-Sleep -Seconds 8
if ((Get-Service mustra-agent).Status -ne 'Running') {
  Write-Host "mustra-agent was installed but is not staying up. The end of its log:"
  Get-Content "$DataDir\agent.log" -Tail 15 -ErrorAction SilentlyContinue | Write-Host
  if (Test-Path "$InstallDir\mustra-agent.exe.previous") {
    Stop-Service mustra-agent -Force -ErrorAction SilentlyContinue
    Move-Item -Force "$InstallDir\mustra-agent.exe.previous" "$InstallDir\mustra-agent.exe"
    Start-Service mustra-agent -ErrorAction SilentlyContinue
    Write-Host "restored the previous agent binary"
  }
  throw "the new mustra agent did not stay running"
}
Remove-Item -Force "$InstallDir\mustra-agent.exe.previous" -ErrorAction SilentlyContinue
Write-Host "mustra-agent installed and started as a Windows service (LocalSystem)."

# Self Service as a findable application: a Start Menu entry, a Desktop
# shortcut, and an Add/Remove Programs record. The service above is what
# manages the machine; this shortcut only opens the window that service
# already serves on loopback, so it needs no privileges of its own and
# deliberately runs in the signed-in user's session rather than SYSTEM's.
$IconPath = "$InstallDir\mustra.ico"
try { Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/static/brand/favicon.ico" -OutFile $IconPath } catch {}
# The toast's logo. A toast renders PNG reliably and an .ico not at all on
# some builds, so the tray carries both rather than reusing one.
try { Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/static/brand/app-icon-256.png" -OutFile "$InstallDir\mustra.png" } catch {}

# The tray helper, which is what makes a real toast possible at all: the
# agent is a LocalSystem service and session 0 isolation forbids a service
# from drawing in somebody's desktop, so the notification it can raise on
# its own is msg.exe and nothing better. This runs in the user's session.
#
# Stop the running helper so its binary can be replaced -- Windows locks a
# running image -- and let the agent start it again.
#
# The agent supervises the helper and restarts on every update, so it brings
# one back into the signed-in session within half a minute. That is the only
# mechanism that actually crosses session 0; the two this replaced did not.
# Letting the helper swap its own binary looked neater and cannot work: it
# runs unelevated as the user, and this directory is not user-writable.
Get-Process mustra-tray -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
$TrayPath = "$InstallDir\mustra-tray.exe"
try {
  Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/downloads/mustra-tray-windows-$arch.exe?v=$AgentVersion" -OutFile $TrayPath
  if ($Pins["mustra-tray-windows-$arch.exe"] -and (Get-FileHash $TrayPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Pins["mustra-tray-windows-$arch.exe"]) {
    Remove-Item -Force $TrayPath -ErrorAction SilentlyContinue
    throw "the tray helper does not match this install command"
  }
  Remove-Item -Force "$TrayPath.new","$TrayPath.old" -ErrorAction SilentlyContinue
} catch {
  Write-Host "tray helper unavailable; notifications will use the plain fallback"
  if (-not (Test-Path $TrayPath)) { $TrayPath = $null }
}

$LauncherPath = "$InstallDir\Open Self Service.cmd"
Set-Content -Path $LauncherPath -Encoding ASCII -Value @'
@echo off
rem Opens the Self Service window the local mustra agent serves. A
rem dedicated app window when Edge or Chrome is present, otherwise the
rem default browser.
set URL=http://127.0.0.1:8137/
set EDGE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe
set CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe
if exist "%EDGE%" ( start "" "%EDGE%" --app=%URL% --window-size=1000,780 & exit /b )
if exist "%CHROME%" ( start "" "%CHROME%" --app=%URL% --window-size=1000,780 & exit /b )
start "" %URL%
'@

$StartMenu = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Mustra"
New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null
$shell = New-Object -ComObject WScript.Shell
# One app: with the tray present, "Mustra Self Service" starts it with
# --open, which shows the window and keeps the tray in the notification
# area. The .cmd launcher is only the fallback for a machine without it.
foreach ($linkPath in @("$StartMenu\Mustra Self Service.lnk", "$env:PUBLIC\Desktop\Mustra Self Service.lnk")) {
  $lnk = $shell.CreateShortcut($linkPath)
  if ($TrayPath) { $lnk.TargetPath = $TrayPath; $lnk.Arguments = "--open" } else { $lnk.TargetPath = $LauncherPath }
  $lnk.WorkingDirectory = $InstallDir
  $lnk.Description = "Check in, see what mustra has done to this machine, and install approved software"
  if (Test-Path $IconPath) { $lnk.IconLocation = $IconPath }
  $lnk.Save()
}

# Start the tray at sign-in for every account on this machine. The common
# Startup folder rather than a Run key, because the helper registers its own
# per-user pieces (its application identity and the mustra: protocol) on
# first run, and those have to be written by the user who will see them --
# SYSTEM cannot write another account's HKCU.
if ($TrayPath) {
  $Startup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
  New-Item -ItemType Directory -Force -Path $Startup | Out-Null
  $lnk = $shell.CreateShortcut("$Startup\Mustra Tray.lnk")
  $lnk.TargetPath = $TrayPath
  $lnk.WorkingDirectory = $InstallDir
  $lnk.Description = "Shows mustra notifications and gives quick access to Self Service"
  if (Test-Path $IconPath) { $lnk.IconLocation = $IconPath }
  $lnk.Save()

  # Deliberately not started from here.
  #
  # This installer is SYSTEM, and getting a process from SYSTEM into a
  # specific desktop session means schtasks with an interactive token --
  # which twice aborted the whole install, because schtasks writes warnings
  # to stderr and this script runs with $ErrorActionPreference = "Stop".
  # The helper is a convenience that starts at the next sign-in; risking the
  # agent install to save one sign-in was the wrong trade.
  #
  # No separate "Mustra Tray" Start Menu entry: "Mustra Self Service"
  # starts the tray. Remove the one older installers made.
  Remove-Item -Force "$StartMenu\Mustra Tray.lnk" -ErrorAction SilentlyContinue

  Write-Host "Mustra tray helper installed; the agent starts it in the signed-in session."
}

# An Add/Remove Programs entry, so this is uninstallable the way people
# expect rather than something that can only be removed by hand.
$Uninstall = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MustraAgent"
New-Item -Path $Uninstall -Force | Out-Null
Set-ItemProperty -Path $Uninstall -Name DisplayName -Value "Mustra Agent & Self Service"
Set-ItemProperty -Path $Uninstall -Name DisplayVersion -Value $AgentVersion
Set-ItemProperty -Path $Uninstall -Name Publisher -Value "mustra"
Set-ItemProperty -Path $Uninstall -Name InstallLocation -Value $InstallDir
Set-ItemProperty -Path $Uninstall -Name NoModify -Value 1 -Type DWord
Set-ItemProperty -Path $Uninstall -Name NoRepair -Value 1 -Type DWord
if (Test-Path $IconPath) { Set-ItemProperty -Path $Uninstall -Name DisplayIcon -Value $IconPath }

$UninstallScript = "$InstallDir\uninstall.ps1"
Set-Content -Path $UninstallScript -Encoding UTF8 -Value @'
# Removing a LocalSystem service and a Program Files directory needs an
# elevated shell. This used to run anyway, fail at every step silently and
# then announce that mustra had been removed.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
  exit
}
$ErrorActionPreference = "Continue"
$failures = @()

# The password, when the console set one.
#
# What this stops is the person using the machine removing the agent
# because it is in their way. It is not a defence against an administrator
# of this machine and could not be: whoever can run this can also stop the
# service and delete the directory. Saying so plainly is better than
# implying a guarantee nobody can keep.
$HashFile = "C:\Program Files\mustra-agent\uninstall.hash"
if (Test-Path $HashFile) {
  $attempts = 0
  while ($true) {
    $attempts++
    $secure = Read-Host -AsSecureString "Uninstall password"
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    $plain | & "C:\Program Files\mustra-agent\mustra-agent.exe" -verify-uninstall-password $HashFile
    if ($LASTEXITCODE -eq 0) { break }
    if ($attempts -ge 3) {
      Write-Host "Uninstall cancelled."
      exit 1
    }
    Write-Host "That password is not correct."
  }
}

# The tray first: it holds its own executable open, and it owns per-user
# registry entries that only it can remove from the session that has them.
& "C:\Program Files\mustra-agent\mustra-tray.exe" --uninstall
Get-Process mustra-tray -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Force "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Mustra Tray.lnk"
# The recovery job (internal/agent/recovery.go), before the service it
# would otherwise try to start again.
schtasks.exe /Delete /F /TN "\mustra\agent recovery" 2>$null | Out-Null
Stop-Service mustra-agent -Force -ErrorAction SilentlyContinue
if (Get-Service mustra-agent -ErrorAction SilentlyContinue) {
  sc.exe delete mustra-agent | Out-Null
  if ($LASTEXITCODE -ne 0) { $failures += "the mustra-agent service" }
}
foreach ($name in @("MUSTRA_NATS_USER", "MUSTRA_NATS_PASSWORD", "MUSTRA_NATS_CA")) {
  [Environment]::SetEnvironmentVariable($name, $null, "Machine")
}
foreach ($path in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Mustra", "$env:PUBLIC\Desktop\Mustra Self Service.lnk",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MustraAgent", "C:\Program Files\mustra-agent",
                    "C:\ProgramData\mustra-agent")) {
  if (Test-Path $path) {
    Remove-Item -Recurse -Force $path -ErrorAction SilentlyContinue
    if (Test-Path $path) { $failures += $path }
  }
}
if ($failures.Count -gt 0) {
  Write-Host "mustra was only partly removed. Still present:"
  $failures | ForEach-Object { Write-Host "  $_" }
  exit 1
}
Write-Host "mustra removed. The endpoint will stop reporting to the console."
'@
Set-ItemProperty -Path $Uninstall -Name UninstallString -Value ('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $UninstallScript + '"')

Write-Host "Mustra Self Service added to the Start Menu and Desktop."
`
