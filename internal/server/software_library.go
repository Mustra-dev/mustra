package server

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The package library: ready-made definitions for widely used applications,
// installed through each platform's own package manager (winget, Homebrew,
// apt) so they always fetch the vendor's current, signed release and no
// binary passes through mustra.
//
// Adding one to the catalog creates an unpublished draft. Nothing in the
// library is ever deployed by itself: an operator opens the draft, tests it
// on one endpoint and publishes it, like any package they wrote. That
// review is the ownership model: the library is maintained here, in code
// review, and each deployment of it is the operator's decision.
//
// The rules every entry follows, which TestLibraryEntriesArePublishable
// checks:
//   - applicable only where its package manager exists (a requirement
//     check), so a server without winget is "not applicable", not a
//     failure;
//   - detected and validated by a pattern over the installed-apps
//     inventory, because display names carry versions and editions
//     ("Mozilla Firefox (x64 en-US)", "7-Zip 24.08 (x64)");
//   - "already installed" and "no newer version" count as success.

// libraryEntry is one application in the library.
type libraryEntry struct {
	ID          string
	Name        string
	Vendor      string
	Category    string
	Description string
	// Windows is the winget package ID; Mac the Homebrew cask (one that
	// installs an app bundle into /Applications, which the macOS inventory
	// reads); Linux the apt package. Empty where there is no good source.
	Windows, Mac, Linux string
	// Detect is the installed-apps name pattern per platform.
	Detect map[string]string
}

var softwareLibrary = []libraryEntry{
	{ID: "google-chrome", Name: "Google Chrome", Vendor: "Google", Category: "Browsers", Description: "Web browser.",
		Windows: "Google.Chrome", Mac: "google-chrome",
		Detect: map[string]string{"windows": `^Google Chrome$`, "darwin": `^Google Chrome$`}},
	{ID: "mozilla-firefox", Name: "Mozilla Firefox", Vendor: "Mozilla", Category: "Browsers", Description: "Web browser.",
		Windows: "Mozilla.Firefox", Mac: "firefox",
		Detect: map[string]string{"windows": `^Mozilla Firefox`, "darwin": `^Firefox$`}},
	{ID: "7zip", Name: "7-Zip", Vendor: "Igor Pavlov", Category: "Utilities", Description: "File archiver.",
		Windows: "7zip.7zip", Linux: "p7zip-full",
		Detect: map[string]string{"windows": `^7-Zip`, "linux": `^p7zip-full$`}},
	{ID: "vscode", Name: "Visual Studio Code", Vendor: "Microsoft", Category: "Development", Description: "Code editor.",
		Windows: "Microsoft.VisualStudioCode", Mac: "visual-studio-code",
		Detect: map[string]string{"windows": `^Microsoft Visual Studio Code`, "darwin": `^Visual Studio Code$`}},
	{ID: "notepad-plus-plus", Name: "Notepad++", Vendor: "Notepad++ team", Category: "Utilities", Description: "Text editor.",
		Windows: "Notepad++.Notepad++",
		Detect:  map[string]string{"windows": `^Notepad\+\+`}},
	{ID: "vlc", Name: "VLC media player", Vendor: "VideoLAN", Category: "Media", Description: "Media player.",
		Windows: "VideoLAN.VLC", Mac: "vlc", Linux: "vlc",
		Detect: map[string]string{"windows": `^VLC media player`, "darwin": `^VLC$`, "linux": `^vlc$`}},
	{ID: "git", Name: "Git", Vendor: "Git project", Category: "Development", Description: "Version control.",
		Windows: "Git.Git", Linux: "git",
		Detect: map[string]string{"windows": `^Git( version|$)`, "linux": `^git$`}},
	{ID: "powershell", Name: "PowerShell 7", Vendor: "Microsoft", Category: "Development", Description: "Cross-platform shell.",
		Windows: "Microsoft.PowerShell",
		Detect:  map[string]string{"windows": `^PowerShell 7`}},
	{ID: "keepassxc", Name: "KeePassXC", Vendor: "KeePassXC team", Category: "Security", Description: "Password manager.",
		Windows: "KeePassXCTeam.KeePassXC", Mac: "keepassxc", Linux: "keepassxc",
		Detect: map[string]string{"windows": `^KeePassXC`, "darwin": `^KeePassXC$`, "linux": `^keepassxc$`}},
	{ID: "wireshark", Name: "Wireshark", Vendor: "Wireshark Foundation", Category: "Network", Description: "Network protocol analyzer.",
		Windows: "WiresharkFoundation.Wireshark", Linux: "wireshark",
		Detect: map[string]string{"windows": `^Wireshark`, "linux": `^wireshark$`}},
	{ID: "putty", Name: "PuTTY", Vendor: "Simon Tatham", Category: "Network", Description: "SSH and telnet client.",
		Windows: "PuTTY.PuTTY", Linux: "putty",
		Detect: map[string]string{"windows": `^PuTTY`, "linux": `^putty$`}},
	{ID: "slack", Name: "Slack", Vendor: "Slack Technologies", Category: "Communication", Description: "Team chat.",
		Windows: "SlackTechnologies.Slack", Mac: "slack",
		Detect: map[string]string{"windows": `^Slack`, "darwin": `^Slack$`}},
	{ID: "zoom", Name: "Zoom Workplace", Vendor: "Zoom", Category: "Communication", Description: "Video meetings.",
		Windows: "Zoom.Zoom",
		Detect:  map[string]string{"windows": `^Zoom`}},
	{ID: "acrobat-reader", Name: "Adobe Acrobat Reader", Vendor: "Adobe", Category: "Documents", Description: "PDF reader.",
		Windows: "Adobe.Acrobat.Reader.64-bit",
		Detect:  map[string]string{"windows": `^Adobe Acrobat`}},
	{ID: "cloudflared", Name: "cloudflared", Vendor: "Cloudflare", Category: "Network", Description: "Cloudflare Tunnel client.",
		Windows: "Cloudflare.cloudflared",
		Detect:  map[string]string{"windows": `^cloudflared`}},
	{ID: "python3", Name: "Python 3", Vendor: "Python Software Foundation", Category: "Development", Description: "Python runtime.",
		Windows: "Python.Python.3.13", Linux: "python3",
		Detect: map[string]string{"windows": `^Python 3\.13`, "linux": `^python3$`}},
	{ID: "nodejs-lts", Name: "Node.js LTS", Vendor: "OpenJS Foundation", Category: "Development", Description: "JavaScript runtime, long-term support line.",
		Windows: "OpenJS.NodeJS.LTS",
		Detect:  map[string]string{"windows": `^Node\.js`}},
	{ID: "htop", Name: "htop", Vendor: "htop developers", Category: "Utilities", Description: "Interactive process viewer.",
		Linux:  "htop",
		Detect: map[string]string{"linux": `^htop$`}},
}

// winget, as SYSTEM: usually not on the service's PATH, and where the
// SYSTEM profile has an app-execution alias it can fail to start (below),
// so one that resolves is used only if it runs; otherwise it is found
// where App Installer puts it. Exit codes 0x8A15002B (no applicable update) and
// 0x8A150061 (already installed) are outcomes, not failures.
//
// The executable alone is not enough on Windows Server: winget.exe links
// against the framework packages its manifest names (VCLibs and the
// Windows App Runtime), which a packaged app finds through its package
// graph and a process started by path does not, so as SYSTEM it exits
// 0xC0000135 (a DLL not found). Those packages' folders, read from
// winget's own AppxManifest.xml so they follow whatever version is
// installed, go on PATH with it. Only those: putting every runtime on
// PATH loads the wrong one first. Measured on Windows Server 2025.
const wingetPrelude = `$ErrorActionPreference = "Stop"
$winget = $null
$c = Get-Command winget.exe -ErrorAction SilentlyContinue
if ($c) { try { & $c.Source --version *> $null; if ($LASTEXITCODE -eq 0) { $winget = $c.Source } } catch {} }
if (-not $winget) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
  $apps = "$env:ProgramFiles\WindowsApps"
  function Get-NewestAppDir($name) {
    Get-ChildItem $apps -Directory -Filter "${name}_*_${arch}__8wekyb3d8bbwe" -ErrorAction SilentlyContinue |
      Sort-Object { try { [version](($_.Name -split '_')[1]) } catch { [version]'0.0' } } -Descending | Select-Object -First 1
  }
  $d = Get-NewestAppDir 'Microsoft.DesktopAppInstaller'
  if ($d -and (Test-Path (Join-Path $d.FullName 'winget.exe'))) {
    $deps = @()
    try {
      $m = [xml](Get-Content -LiteralPath (Join-Path $d.FullName 'AppxManifest.xml'))
      $deps = foreach ($dep in $m.Package.Dependencies.PackageDependency) { (Get-NewestAppDir $dep.Name).FullName }
    } catch {}
    $env:PATH = ((@($d.FullName) + $deps | Where-Object { $_ }) -join ';') + ';' + $env:PATH
    $winget = Join-Path $d.FullName 'winget.exe'
  }
}
if (-not $winget) { Write-Error "winget (App Installer) is not installed on this endpoint"; exit 1 }
`

const wingetEpilogue = `
if ($LASTEXITCODE -in @(-1978335189, -1978335135)) { exit 0 }
exit $LASTEXITCODE
`

// Homebrew refuses to run as root; run it as whoever owns its prefix, as
// the agent's own brew helper does.
const brewPrelude = `BREW=$(command -v brew || ls /opt/homebrew/bin/brew /usr/local/bin/brew 2>/dev/null | head -1)
[ -n "$BREW" ] || { echo "Homebrew is not installed on this Mac" >&2; exit 1; }
OWNER=$(stat -f %Su "$(dirname "$(dirname "$BREW")")")
`

const aptPrelude = `export DEBIAN_FRONTEND=noninteractive
`

func libraryScript(os, op, pkg string) (lang, src string) {
	switch os {
	case "windows":
		args := map[string]string{
			"install": "install --id " + pkg + " --exact --silent --scope machine --accept-package-agreements --accept-source-agreements --disable-interactivity",
			"update":  "upgrade --id " + pkg + " --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity",
			"remove":  "uninstall --id " + pkg + " --exact --silent --disable-interactivity",
		}[op]
		return "powershell", wingetPrelude + "& $winget " + args + wingetEpilogue
	case "darwin":
		verb := map[string]string{"install": "install --cask", "update": "upgrade --cask", "remove": "uninstall --cask"}[op]
		return "shell", brewPrelude + `sudo -u "$OWNER" -H "$BREW" ` + verb + " " + pkg + "\n"
	default:
		cmd := map[string]string{
			"install": "apt-get update -q && apt-get install -y -q " + pkg,
			"update":  "apt-get update -q && apt-get install -y -q --only-upgrade " + pkg,
			"remove":  "apt-get remove -y -q " + pkg,
		}[op]
		return "shell", aptPrelude + cmd + "\n"
	}
}

// libraryRequirement is applicability: the platform's package manager
// exists. Exit 0 is "applies", exit 1 "does not".
func libraryRequirement(os string) *proto.DeployCheck {
	src := map[string]string{
		"windows": `if (Get-Command winget.exe -ErrorAction SilentlyContinue) { exit 0 }
if (Resolve-Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue) { exit 0 }
exit 1`,
		"darwin": `command -v brew >/dev/null 2>&1 || [ -x /opt/homebrew/bin/brew ] || [ -x /usr/local/bin/brew ]`,
		"linux":  `command -v apt-get >/dev/null 2>&1`,
	}[os]
	lang := "shell"
	if os == "windows" {
		lang = "powershell"
	}
	return &proto.DeployCheck{Kind: "script", Script: &proto.DeployScript{Language: lang, Source: src, TimeoutSeconds: 30}}
}

func libraryPresence(pattern, quantifier string) *proto.DeployCheck {
	return &proto.DeployCheck{Kind: "sensor", SensorID: "installed_apps", Quantifier: quantifier,
		Rows: []proto.DeployPredicate{{Field: "name", Operator: "matches", Value: pattern}}}
}

// definition builds the entry's deploy definition: one variant per
// platform it has a source for.
func (e libraryEntry) definition() proto.DeployDefinition {
	d := proto.DeployDefinition{Version: 1}
	for _, p := range []struct{ os, pkg string }{{"windows", e.Windows}, {"darwin", e.Mac}, {"linux", e.Linux}} {
		if p.pkg == "" {
			continue
		}
		v := proto.DeployVariant{ID: idgen.New("var-"), OS: p.os, Requirements: libraryRequirement(p.os),
			Detection: libraryPresence(e.Detect[p.os], "any"), Actions: map[string]proto.DeployAction{}}
		for _, op := range []string{"install", "update", "remove"} {
			lang, src := libraryScript(p.os, op, p.pkg)
			validation := libraryPresence(e.Detect[p.os], "any")
			if op == "remove" {
				validation = libraryPresence(e.Detect[p.os], "none")
			}
			v.Actions[op] = proto.DeployAction{
				Identity: "administrator", Validation: validation, ValidationSeconds: 120,
				Steps: []proto.DeployStep{{ID: idgen.New("stp-"), Name: strings.ToUpper(op[:1]) + op[1:] + " with " +
					map[string]string{"windows": "winget", "darwin": "Homebrew", "linux": "apt"}[p.os],
					Script: &proto.DeployScript{Language: lang, Source: src, TimeoutSeconds: 1800}}},
			}
		}
		d.Variants = append(d.Variants, v)
	}
	return d
}

func (e libraryEntry) platforms() []string {
	var out []string
	for _, p := range []struct{ os, pkg string }{{"windows", e.Windows}, {"darwin", e.Mac}, {"linux", e.Linux}} {
		if p.pkg != "" {
			out = append(out, p.os)
		}
	}
	return out
}

// libraryItem is one library entry as the console lists it.
type libraryItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Platforms   []string `json:"platforms"`
	// Sources names the package each platform installs from
	// ("winget Google.Chrome"), so an operator can see what they adopt.
	Sources map[string]string `json:"sources"`
	// PackageID is the catalog package this entry was added as, if any.
	PackageID string `json:"package_id,omitempty"`
}

// libraryResponse is what GET /api/software-library answers.
type libraryResponse struct {
	Items []libraryItem `json:"items"`
}

// libraryAddResponse is what POST /api/software-library/{id} answers: the
// new package and its unpublished draft.
type libraryAddResponse struct {
	PackageID  string `json:"package_id"`
	RevisionID string `json:"revision_id"`
}

// libraryOrigin marks a catalog package as added from the library, in its
// category field's absence of anywhere better: the description's source
// line, which the console shows and an operator may edit.
func libraryOrigin(id string) string { return "From the mustra package library (" + id + ")." }

var libraryOriginRe = regexp.MustCompile(`From the mustra package library \(([a-z0-9-]+)\)\.`)

func (s *Server) handleListLibrary(w http.ResponseWriter, r *http.Request) {
	added := map[string]string{}
	if pkgs, err := s.store.ListSoftwarePackages(r.Context()); err == nil {
		for _, p := range pkgs {
			if m := libraryOriginRe.FindStringSubmatch(p.Description); m != nil {
				added[m[1]] = p.ID
			}
		}
	}
	out := libraryResponse{Items: []libraryItem{}}
	for _, e := range softwareLibrary {
		src := map[string]string{}
		if e.Windows != "" {
			src["windows"] = "winget " + e.Windows
		}
		if e.Mac != "" {
			src["darwin"] = "Homebrew cask " + e.Mac
		}
		if e.Linux != "" {
			src["linux"] = "apt " + e.Linux
		}
		out.Items = append(out.Items, libraryItem{ID: e.ID, Name: e.Name, Vendor: e.Vendor, Category: e.Category,
			Description: e.Description, Platforms: e.platforms(), Sources: src, PackageID: added[e.ID]})
	}
	sort.Slice(out.Items, func(i, j int) bool { return strings.ToLower(out.Items[i].Name) < strings.ToLower(out.Items[j].Name) })
	writeJSONResponse(w, out)
}

// handleAddFromLibrary adds a library entry to the catalog as a package
// with an unpublished draft. It deploys nothing.
func (s *Server) handleAddFromLibrary(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var entry *libraryEntry
	for i := range softwareLibrary {
		if softwareLibrary[i].ID == id {
			entry = &softwareLibrary[i]
		}
	}
	if entry == nil {
		http.Error(w, "no such library package", http.StatusNotFound)
		return
	}
	ctx := r.Context()
	if pkgs, err := s.store.ListSoftwarePackages(ctx); err == nil {
		for _, p := range pkgs {
			if m := libraryOriginRe.FindStringSubmatch(p.Description); m != nil && m[1] == id {
				http.Error(w, entry.Name+" is already in the catalog", http.StatusConflict)
				return
			}
		}
	}
	who := auth.CurrentUser(ctx).Username
	pkg, err := s.store.UpsertSoftwarePackage(ctx, store.SoftwarePackage{
		ID: idgen.New("sw-"), Name: entry.Name, Vendor: entry.Vendor, Category: entry.Category, Kind: store.KindSoftware,
		Description: entry.Description + " " + libraryOrigin(id), Commands: map[string]store.SoftwareOps{}, Enabled: true, CreatedBy: who,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The label is the date it was added: the package manager installs the
	// current release, so there is no version of ours to name.
	rev, err := s.store.SaveDeployDraft(ctx, proto.DeployRevision{ID: idgen.New("rev-"), PackageID: pkg.ID,
		Label: time.Now().UTC().Format("2006.1.2"), Definition: entry.definition(), CreatedBy: who})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "software.library_add", Actor: who, Target: entry.Name,
		Detail: map[string]any{"library_id": id, "package_id": pkg.ID, "platforms": entry.platforms()}})
	writeJSONResponse(w, libraryAddResponse{PackageID: pkg.ID, RevisionID: rev.ID})
}

func (e libraryEntry) String() string { return fmt.Sprintf("%s (%s)", e.Name, e.ID) }
