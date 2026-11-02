package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	gonats "github.com/nats-io/nats.go"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectPatches lists available (not yet installed) OS updates. Like
// services/installed-apps, no cross-platform library covers this — each OS
// shells out to its own native update-listing command.
//
// nc/agentID (may be nil/"" in tests) are used only on Linux, to ask the
// server whether a Scan Management patch list overrides the host's native
// repos for this collection — see fetchPatchListOverride.
func collectPatches(ctx context.Context, nc *gonats.Conn, agentID string) ([]proto.PatchInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return collectPatchesLinux(ctx, nc, agentID)
	case "darwin":
		return collectPatchesDarwin(ctx)
	case "windows":
		return collectPatchesWindows(ctx)
	default:
		return nil, fmt.Errorf("patches sensor not supported on %s", runtime.GOOS)
	}
}

// collectPatchesLinux tries apt (Debian/Ubuntu) first, then dnf/yum
// (Fedora/RHEL/derivatives) — whichever package manager is actually
// present, same pattern as collectAppsLinux.
func collectPatchesLinux(ctx context.Context, nc *gonats.Conn, agentID string) ([]proto.PatchInfo, error) {
	if inHAOSAddon() {
		return collectPatchesHAOS(ctx)
	}
	override := fetchPatchListOverride(ctx, nc, agentID)
	if _, err := exec.LookPath("apt-get"); err == nil {
		var repos []string
		if override.OSFamily == "apt" {
			repos = override.Repos
		}
		return collectPatchesAPT(ctx, repos)
	}
	if mgr, err := exec.LookPath("dnf"); err == nil {
		var repos []string
		if override.OSFamily == "dnf" {
			repos = override.Repos
		}
		return collectPatchesDNF(ctx, mgr, repos)
	}
	if mgr, err := exec.LookPath("yum"); err == nil {
		var repos []string
		if override.OSFamily == "dnf" {
			repos = override.Repos
		}
		return collectPatchesDNF(ctx, mgr, repos)
	}
	if apkPresent() {
		return collectPatchesAPK(ctx)
	}
	return nil, fmt.Errorf("no supported package manager found (tried apt-get, dnf, yum, apk)")
}

// writeSourcesTempFile writes a Scan Management patch list's repo lines
// (already full sources.list-format lines) to a temp file apt can be
// pointed at via -o Dir::Etc::sourcelist, fully isolated from the host's
// real /etc/apt/sources.list(.d) — nothing here ever touches the host's
// actual repo config.
func writeSourcesTempFile(repos []string) (string, error) {
	f, err := os.CreateTemp("", "mustra-sources-*.list")
	if err != nil {
		return "", fmt.Errorf("create scoped sources file: %w", err)
	}
	defer f.Close()
	for _, line := range repos {
		if _, err := f.WriteString(line + "\n"); err != nil {
			os.Remove(f.Name())
			return "", fmt.Errorf("write scoped sources file: %w", err)
		}
	}
	return f.Name(), nil
}

// collectPatchesAPT reads the upgradable-package list. With no override,
// it deliberately doesn't run `apt-get update` first (that's a network
// call with its own failure modes, and would make every periodic sensor
// collection touch the network) — it reads whatever apt's package cache
// currently has, reflecting the last time anyone (a cron job, a manual
// apt-get update, or applyPatchesLinux below) refreshed it. With a Scan
// Management override, it does run a scoped `apt-get update` first — that
// network call is the whole point of assigning a patch list, and it's
// bounded to just the assigned repos, never the host's real ones.
func collectPatchesAPT(ctx context.Context, repos []string) ([]proto.PatchInfo, error) {
	args := []string{"list", "--upgradable"}
	if len(repos) > 0 {
		sourceFile, err := writeSourcesTempFile(repos)
		if err != nil {
			return nil, err
		}
		defer os.Remove(sourceFile)
		scopeArgs := []string{"-o", "Dir::Etc::sourcelist=" + sourceFile, "-o", "Dir::Etc::sourceparts=/dev/null"}
		update := exec.CommandContext(ctx, "apt-get", append([]string{"update"}, scopeArgs...)...)
		if out, err := update.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("scoped apt-get update: %w: %s", err, out)
		}
		args = append(args, scopeArgs...)
	}
	out, err := exec.CommandContext(ctx, "apt", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("apt list --upgradable: %w", err)
	}
	held := aptHeld(ctx)
	var patches []proto.PatchInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "Listing...") {
			continue
		}
		// format: pkgname/suite newversion arch [upgradable from: oldversion]
		nameEnd := strings.IndexAny(line, "/ ")
		if nameEnd < 0 {
			continue
		}
		name := line[:nameEnd]
		// apt list shows held packages as upgradable, but a hold is the
		// administrator saying not to; listing one failed every job.
		if held[name] {
			continue
		}
		fields := strings.Fields(line)
		newVersion := ""
		if len(fields) >= 2 {
			newVersion = fields[1]
		}
		currentVersion := ""
		if idx := strings.Index(line, "upgradable from: "); idx >= 0 {
			currentVersion = strings.TrimSuffix(line[idx+len("upgradable from: "):], "]")
		}
		severity := ""
		if strings.Contains(line, "-security") {
			severity = "security"
		}
		patches = append(patches, proto.PatchInfo{Name: name, CurrentVersion: currentVersion, NewVersion: newVersion, Severity: severity})
	}
	return patches, sc.Err()
}

// collectPatchesDNF lists available updates. With a Scan Management
// override, --disablerepo=* plus a --enablerepo= per assigned repo ID
// whitelists exactly those repos for this one invocation without touching
// the host's actual repo config — repos must already be configured on the
// host (dnf's repo IDs reference existing .repo files; this doesn't create
// new ones), matching the doc comment on collectPatchesLinux.
func collectPatchesDNF(ctx context.Context, mgr string, repos []string) ([]proto.PatchInfo, error) {
	args := []string{"check-update"}
	if len(repos) > 0 {
		args = append(args, "--disablerepo=*")
		for _, r := range repos {
			args = append(args, "--enablerepo="+r)
		}
	}
	// check-update exits 100 when updates ARE available (not an error) and
	// 0 when the system is fully up to date — only a genuine non-{0,100}
	// exit is a real failure.
	out, err := exec.CommandContext(ctx, mgr, args...).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 100 {
			return nil, fmt.Errorf("%s check-update: %w", mgr, err)
		}
	}
	var patches []proto.PatchInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "Last") || strings.Contains(sc.Text(), "Obsoleting") {
			continue
		}
		patches = append(patches, proto.PatchInfo{Name: fields[0], NewVersion: fields[1]})
	}
	return patches, sc.Err()
}

// collectPatchesDarwin lists pending macOS updates via softwareupdate,
// which is the only supported interface to it (no library, no JSON output
// mode) — its plain-text output uses one line per update prefixed "* ".
func collectPatchesDarwin(ctx context.Context) ([]proto.PatchInfo, error) {
	updates, err := listSoftwareUpdates(ctx)
	if err != nil {
		return nil, err
	}
	patches := make([]proto.PatchInfo, 0, len(updates))
	for _, u := range updates {
		patches = append(patches, u.PatchInfo)
	}
	return patches, nil
}

// macUpdate is one entry of softwareupdate -l: what the console shows,
// and the label softwareupdate installs it by.
type macUpdate struct {
	proto.PatchInfo
	Label string
}

func listSoftwareUpdates(ctx context.Context) ([]macUpdate, error) {
	out, err := exec.CommandContext(ctx, "softwareupdate", "-l").CombinedOutput()
	if err != nil {
		// softwareupdate exits non-zero when there's simply nothing to
		// update — treat that as "no patches", not a collection failure,
		// same reasoning as apt/dnf's exit-code handling above.
		if strings.Contains(string(out), "No new software available") {
			return nil, nil
		}
		return nil, fmt.Errorf("softwareupdate -l: %w", err)
	}
	return parseSoftwareUpdateList(string(out)), nil
}

// parseSoftwareUpdateList reads softwareupdate -l. Each update is two
// lines, an identifier and its details:
//
//   - Label: macOS Tahoe 26.7.1-25G241
//     Title: macOS Tahoe 26.7.1, Version: 26.7.1, Size: 3912000KiB, Recommended: YES, Action: restart,
//
// (before macOS 10.15: "* Safari13.0.4MojaveAuto-13.0.4" then
// "Safari (13.0.4), 69012K [recommended] [restart]"). The console shows
// the title and version; the label, which is only an install handle, used
// to be shown instead, prefix and all.
func parseSoftwareUpdateList(out string) []macUpdate {
	var updates []macUpdate
	var cur *macUpdate
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "*") {
			label := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "*")), "Label:"))
			if label == "" {
				cur = nil
				continue
			}
			updates = append(updates, macUpdate{Label: label, PatchInfo: proto.PatchInfo{Name: label}})
			cur = &updates[len(updates)-1]
			continue
		}
		if cur == nil || line == "" {
			continue
		}
		if strings.HasPrefix(line, "Title:") {
			fields := map[string]string{}
			key := ""
			for _, part := range strings.Split(line, ", ") {
				part = strings.TrimSuffix(strings.TrimSpace(part), ",")
				if k, v, ok := strings.Cut(part, ": "); ok && !strings.Contains(k, " ") {
					key = k
					fields[key] = strings.TrimSpace(v)
				} else if key != "" {
					fields[key] += ", " + part // a comma inside the value
				}
			}
			if t := fields["Title"]; t != "" {
				cur.Name = t
			}
			cur.NewVersion = fields["Version"]
			cur.RestartRequired = strings.EqualFold(fields["Action"], "restart")
		} else if m := oldUpdateDetail.FindStringSubmatch(line); m != nil {
			cur.Name, cur.NewVersion = strings.TrimSpace(m[1]), m[2]
			cur.RestartRequired = strings.Contains(line, "[restart]")
		}
		// Apple's title omits the version ("Safari", "Safari 27.0"); the
		// version is its own column, so a bare title stays as it is.
		cur = nil
	}
	return updates
}

var oldUpdateDetail = regexp.MustCompile(`^(.+?) \(([^)]+)\)`)

// collectPatchesWindows uses the Windows Update Agent COM API directly
// (CreateUpdateSearcher) rather than the PSWindowsUpdate module, which
// isn't installed by default — this works on a stock Windows install with
// no prerequisites.
func collectPatchesWindows(ctx context.Context) ([]proto.PatchInfo, error) {
	const script = `
$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
$out = @()
foreach ($u in $r.Updates) {
  $severity = ""
  if ($u.MsrcSeverity) { $severity = $u.MsrcSeverity }
  $out += [PSCustomObject]@{ Title = $u.Title; Severity = $severity }
}
$out | ConvertTo-Json -Compress`
	// Stderr is captured and folded into the error rather than discarded:
	// a killed or failing powershell reports nothing but "exit status 1",
	// which is indistinguishable between a COM failure, a WSUS the machine
	// can't reach, and the collection budget running out.
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = "no stderr output"
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("windows update search: %w (search did not finish in time: %v)", err, ctx.Err())
		}
		return nil, fmt.Errorf("windows update search: %w: %s", err, detail)
	}
	out := stdout.Bytes()
	type psUpdate struct {
		Title    string `json:"Title"`
		Severity string `json:"Severity"`
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var raw []psUpdate
	if trimmed[0] == '{' {
		var one psUpdate
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, fmt.Errorf("decode windows update search output: %w", err)
		}
		raw = []psUpdate{one}
	} else if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, fmt.Errorf("decode windows update search output: %w", err)
	}
	patches := make([]proto.PatchInfo, 0, len(raw))
	for _, u := range raw {
		severity := ""
		if u.Severity != "" {
			severity = "security"
		}
		patches = append(patches, proto.PatchInfo{Name: u.Title, Severity: severity})
	}
	return patches, nil
}

// patchProgress is how applyPatches reports stages back to the caller:
// stage is a taxonomy state ("downloading", "installing", "waiting"),
// detail a short human line. Retries carry the attempt number so the
// console can say "installing – retry 2".
type patchProgress func(stage, detail string, attempt int)

// patchApplyResult is what one apply run produced.
type patchApplyResult struct {
	Output         string
	RebootRequired bool
	Attempts       int
	// Notes are what the job skipped and why (an unreachable repository, a
	// held package, an update apt cannot resolve), shown above the output.
	Notes []string
	// Failed names updates this job tried and could not install, so the
	// check afterwards does not mistake one still listed with a restart
	// flag (every macOS update) for one installed and awaiting a restart.
	Failed []string
	// Skipped names updates the job left alone on purpose (macOS itself on
	// Apple Silicon, which needs a password); they are not held against it.
	// PrepareForUser are the macOS updates among them that nobody else will
	// install (no MDM to hand them to): the agent downloads them and asks the
	// person at the Mac to install them (prepareMacOSUpdate).
	PrepareForUser []macUpdate
	Skipped        []string
	// Installed names updates the installer itself reported as installed
	// (Windows result code 2 or 3). Windows keeps listing some of them as
	// pending until a restart (.NET, the Defender platform), so the check
	// afterwards must not read "still listed" as "not installed".
	Installed []string
}

// applyPatches installs pending OS updates: every one when names is
// empty, only the named ones otherwise (the server's patch lists decide).
// It is staged the way it happens -- download, then install --
// and says whether a reboot is outstanding afterwards. See
// proto.AgentCommand's doc comment for why this fixed, agent-constructed
// command is safe to expose over the command channel.
// viaMDM says the server hands macOS updates to an MDM after this job.
func applyPatches(ctx context.Context, nc *gonats.Conn, agentID string, names []string, viaMDM bool, report patchProgress) (patchApplyResult, error) {
	if report == nil {
		report = func(string, string, int) {}
	}
	switch runtime.GOOS {
	case "linux":
		return applyPatchesLinux(ctx, nc, agentID, names, report)
	case "darwin":
		return applyPatchesDarwin(ctx, names, viaMDM, report)
	case "windows":
		return applyPatchesWindows(ctx, names, report)
	default:
		return patchApplyResult{}, fmt.Errorf("apply_patches not supported on %s", runtime.GOOS)
	}
}

// packageManagerBusy recognises the "another process holds the lock"
// failures every package manager has: apt's dpkg lock, dnf's metadata
// lock, an unattended-upgrades run in progress. Those are worth waiting
// out rather than failing the deployment.
func packageManagerBusy(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "could not get lock") || strings.Contains(l, "unable to acquire the dpkg frontend lock") ||
		strings.Contains(l, "waiting for cache lock") || strings.Contains(l, "another app is currently holding") ||
		strings.Contains(l, "is another process using it")
}

// runWithLockRetry runs one package-manager step, retrying a few times
// when the failure is a held lock. It reports "waiting" while it waits.
func runWithLockRetry(ctx context.Context, stage string, report patchProgress, attempt *int, run func() (string, error)) (string, error) {
	const tries = 4
	var out string
	var err error
	for i := 1; i <= tries; i++ {
		*attempt = i
		out, err = run()
		if err == nil || !packageManagerBusy(out) || i == tries {
			return out, err
		}
		report("waiting", "Package manager is busy; retrying in 90 seconds", i)
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(90 * time.Second):
		}
		report(stage, "", i+1)
	}
	return out, err
}

func applyPatchesLinux(ctx context.Context, nc *gonats.Conn, agentID string, names []string, report patchProgress) (patchApplyResult, error) {
	if inHAOSAddon() {
		return patchApplyResult{}, fmt.Errorf("Home Assistant OS updates install from Home Assistant (Settings → System → Updates), not from the agent")
	}
	override := fetchPatchListOverride(ctx, nc, agentID)
	var res patchApplyResult
	var buf bytes.Buffer
	step := func(stage string, cmd func() *exec.Cmd) error {
		report(stage, "", res.Attempts)
		out, err := runWithLockRetry(ctx, stage, report, &res.Attempts, func() (string, error) {
			c := cmd()
			c.Env = append(c.Environ(), "DEBIAN_FRONTEND=noninteractive")
			o, e := c.CombinedOutput()
			return string(o), e
		})
		buf.WriteString(out)
		return err
	}
	if _, err := exec.LookPath("apt-get"); err == nil {
		var scopeArgs []string
		if override.OSFamily == "apt" && len(override.Repos) > 0 {
			sourceFile, err := writeSourcesTempFile(override.Repos)
			if err != nil {
				return res, err
			}
			defer os.Remove(sourceFile)
			scopeArgs = []string{"-o", "Dir::Etc::sourcelist=" + sourceFile, "-o", "Dir::Etc::sourceparts=/dev/null"}
		}
		// Selective installs use install --only-upgrade so a name that is
		// not installed is never pulled in as a new package; --no-remove
		// makes apt stop rather than remove anything to make room.
		upgradeArgs := func(extra ...string) []string {
			if len(names) > 0 {
				return append(append(append([]string{"-y"}, extra...), "install", "--only-upgrade", "--no-remove"), append(names, scopeArgs...)...)
			}
			return append(append([]string{"-y"}, extra...), append([]string{"upgrade"}, scopeArgs...)...)
		}
		if len(names) > 0 {
			held := aptHeld(ctx)
			var keep, skipped []string
			for _, n := range names {
				if held[n] {
					skipped = append(skipped, n)
				} else {
					keep = append(keep, n)
				}
			}
			if len(skipped) > 0 {
				res.Notes = append(res.Notes, "Skipped held package(s): "+strings.Join(skipped, ", "))
			}
			if len(keep) == 0 {
				// An empty list means "everything" below, never "nothing".
				return res, nil
			}
			names = keep
		}
		updateFrom := buf.Len()
		if err := step("downloading", func() *exec.Cmd {
			return exec.CommandContext(ctx, "apt-get", append([]string{"update"}, scopeArgs...)...)
		}); err != nil {
			// One dead third-party repository (a vendor that has not
			// published for this release yet) fails the whole update. The
			// lists of every repository that answered are fresh, so carry on
			// with those rather than leave the OS unpatched.
			out := buf.String()[updateFrom:]
			broken := parseAptUpdateErrors(out)
			if ctx.Err() != nil || packageManagerBusy(out) || len(broken) == 0 || !aptUpdateReachedAny(out) {
				res.Output = buf.String()
				return res, fmt.Errorf("apt-get update: %w", err)
			}
			res.Notes = append(res.Notes, "Some repositories could not be refreshed; installed what the others offer:\n  "+strings.Join(broken, "\n  "))
		}
		if err := step("downloading", func() *exec.Cmd { return exec.CommandContext(ctx, "apt-get", upgradeArgs("-d")...) }); err != nil {
			res.Output = buf.String()
			return res, fmt.Errorf("apt-get download: %w", err)
		}
		before := buf.Len()
		err := step("installing", func() *exec.Cmd { return exec.CommandContext(ctx, "apt-get", upgradeArgs()...) })
		// "apt-get upgrade" never installs a package that is new to the
		// machine, so any update needing one -- every kernel, pve-firewall
		// -- is "kept back" and the run still exits 0 having done nothing
		// for it. Those are installed by name, which may add the new
		// dependencies but, with --no-remove, never takes anything away.
		kept := parseAptKeptBack(buf.String()[before:])
		if held := aptHeld(ctx); len(held) > 0 {
			kept = slices.DeleteFunc(kept, func(n string) bool { return held[n] })
		}
		if err == nil && len(names) == 0 && len(kept) > 0 {
			install := func(pkgs []string) error {
				return step("installing", func() *exec.Cmd {
					return exec.CommandContext(ctx, "apt-get", append(append([]string{"-y", "install", "--only-upgrade", "--no-remove"}, pkgs...), scopeArgs...)...)
				})
			}
			from := buf.Len()
			buf.WriteString("\nInstalling the updates apt upgrade kept back: " + strings.Join(kept, " ") + "\n")
			if kerr := install(kept); kerr != nil && ctx.Err() == nil {
				// apt resolves a command line as a whole, so one package it
				// cannot satisfy (a newer build from another suite that needs
				// a newer libstdc++) blocks the rest. Try each on its own.
				// What still fails stays pending, and the check after the job
				// reports it; the updates that did install stand.
				if len(kept) == 1 {
					res.Notes = append(res.Notes, "Could not install "+kept[0]+": "+aptUnmetReason(buf.String()[from:]))
				} else {
					for _, k := range kept {
						from := buf.Len()
						buf.WriteString("\nInstalling " + k + " on its own\n")
						if install([]string{k}) != nil {
							res.Notes = append(res.Notes, "Could not install "+k+": "+aptUnmetReason(buf.String()[from:]))
						}
					}
				}
			} else if kerr != nil {
				err = kerr
			}
		}
		// Even a failed run may have upgraded some packages, so the
		// restart pass runs either way.
		report("installing", "restarting services that still run a replaced binary", res.Attempts)
		buf.WriteString(restartStaleServices(ctx).summary())
		res.Output = buf.String()
		if _, statErr := os.Stat("/var/run/reboot-required"); statErr == nil {
			res.RebootRequired = true
		}
		return res, err
	}
	if apkPresent() {
		// Alpine: refresh the index, then upgrade everything or only the
		// named packages (apk upgrade never installs a package that is not
		// there already).
		uctx, cancel := context.WithTimeout(ctx, apkUpdateTimeout)
		err := step("downloading", func() *exec.Cmd { return exec.CommandContext(uctx, "apk", "update", "--no-progress") })
		cancel()
		if err != nil {
			res.Output = buf.String()
			return res, fmt.Errorf("apk update: %w", err)
		}
		err = step("installing", func() *exec.Cmd {
			return exec.CommandContext(ctx, "apk", append([]string{"upgrade", "--no-progress"}, names...)...)
		})
		res.Output = buf.String()
		res.RebootRequired = apkKernelReplaced()
		return res, err
	}
	mgr, err := exec.LookPath("dnf")
	verb := "upgrade"
	if err != nil {
		mgr, err = exec.LookPath("yum")
		verb = "update"
	}
	if err != nil {
		return res, fmt.Errorf("no supported package manager found (tried apt-get, dnf, yum)")
	}
	args := func(extra ...string) []string {
		a := append([]string{"-y"}, extra...)
		a = append(a, verb)
		if override.OSFamily == "dnf" && len(override.Repos) > 0 {
			a = append(a, "--disablerepo=*")
			for _, r := range override.Repos {
				a = append(a, "--enablerepo="+r)
			}
		}
		return append(a, names...)
	}
	if err := step("downloading", func() *exec.Cmd { return exec.CommandContext(ctx, mgr, args("--downloadonly")...) }); err != nil {
		res.Output = buf.String()
		return res, fmt.Errorf("%s download: %w", mgr, err)
	}
	err = step("installing", func() *exec.Cmd { return exec.CommandContext(ctx, mgr, args()...) })
	report("installing", "restarting services that still run a replaced binary", res.Attempts)
	buf.WriteString(restartStaleServices(ctx).summary())
	res.Output = buf.String()
	// needs-restarting -r exits 1 when a reboot is required (dnf-utils);
	// absent tool means unknown, reported as no reboot rather than guessed.
	if nr, lookErr := exec.LookPath("needs-restarting"); lookErr == nil {
		if rerr := exec.CommandContext(ctx, nr, "-r").Run(); rerr != nil {
			if exitErr, ok := rerr.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				res.RebootRequired = true
			}
		}
	}
	return res, err
}

// applyPatchesDarwin downloads then installs. softwareupdate reports
// updates by label ("* Label: macOS Sonoma 14.5-23F79"); the collector
// keeps that whole line as the name, so the label is recovered here.
func applyPatchesDarwin(ctx context.Context, names []string, viaMDM bool, report patchProgress) (patchApplyResult, error) {
	var res patchApplyResult
	// The console selects by what it shows: the title since 0.57.8, the
	// label (with its "Label:" prefix) before. Both are mapped back to the
	// label softwareupdate installs by.
	var labels []string
	var listed []macUpdate
	if len(names) > 0 {
		listed, _ = listSoftwareUpdates(ctx)
	}
	for _, n := range names {
		n = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n), "Label:"))
		if n == "" {
			continue
		}
		label := n
		for _, u := range listed {
			if u.Label == n || u.Name == n {
				label = u.Label
				break
			}
		}
		if !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	titles := map[string]string{}
	osUpdate := map[string]bool{}
	note := func(u macUpdate) {
		titles[u.Label] = u.Name
		osUpdate[u.Label] = u.RestartRequired && strings.HasPrefix(u.Name, "macOS")
	}
	if len(labels) == 0 {
		all, err := listSoftwareUpdates(ctx)
		if err != nil {
			return res, err
		}
		for _, u := range all {
			labels = append(labels, u.Label)
			note(u)
		}
	} else {
		for _, u := range listed {
			note(u)
		}
	}
	// On Apple Silicon softwareupdate installs macOS itself only with the
	// password of a user who owns the disk. Without one it downloads the
	// whole update (4-12 GB) and then fails, so skip it and say why.
	if runtime.GOARCH == "arm64" {
		labels = slices.DeleteFunc(labels, func(l string) bool {
			if !osUpdate[l] {
				return false
			}
			res.Skipped = append(res.Skipped, titles[l])
			if viaMDM {
				res.Notes = append(res.Notes, "Left "+titles[l]+" to the MDM: on Apple Silicon macOS installs only with a password the agent does not have; "+
					"the server asks the MDM to install it once this job is done.")
				return true
			}
			res.PrepareForUser = append(res.PrepareForUser, macUpdate{Label: l, PatchInfo: proto.PatchInfo{Name: titles[l]}})
			res.Notes = append(res.Notes, "Left "+titles[l]+" to the person at the Mac: on Apple Silicon macOS installs only with the password of a user who owns the disk, "+
				"which the agent does not have. The agent downloads it now and then asks them to install it.")
			return true
		})
	}
	// One update at a time: softwareupdate stops at the first failure, so
	// a macOS update that needs a password (every one on Apple Silicon,
	// where the agent has none to give) also kept Safari from installing.
	res.Attempts = 1
	var failed []string
	var buf strings.Builder
	for _, label := range labels {
		title := titles[label]
		if title == "" {
			title = label
		}
		report("installing", title, 1)
		out, err := exec.CommandContext(ctx, "softwareupdate", "-i", label).CombinedOutput()
		buf.WriteString(withoutProgress(string(out)))
		if err == nil {
			if strings.Contains(strings.ToLower(string(out)), "restart") {
				res.RebootRequired = true
			}
			continue
		}
		failed = append(failed, title)
		res.Failed = append(res.Failed, title)
		if strings.Contains(string(out), "Failed to authenticate") {
			res.Notes = append(res.Notes, "Could not install "+title+": macOS asks for the password of a user who owns the disk, "+
				"and the agent has none to give. Install it from System Settings → General → Software Update.")
		} else {
			res.Notes = append(res.Notes, "Could not install "+title+": "+lastLine(string(out), err))
		}
	}
	res.Output = buf.String()
	if len(failed) > 0 {
		return res, fmt.Errorf("%d update(s) could not be installed: %s", len(failed), strings.Join(failed, ", "))
	}
	// Skipped macOS updates are not a failed job: everything the agent can
	// install went in, and the notes and the check afterwards say what is
	// left for the user to install.
	return res, nil
}

// withoutProgress drops softwareupdate's "Downloading: 41.00%" lines,
// thousands of them for a macOS update, which buried the one line that
// said why it failed.
func withoutProgress(out string) string {
	var b strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "Downloading: ") && strings.HasSuffix(t, "%") {
			continue
		}
		b.WriteString(line + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func lastLine(out string, err error) string {
	lines := strings.Split(strings.TrimSpace(withoutProgress(out)), "\n")
	if l := strings.TrimSpace(lines[len(lines)-1]); l != "" {
		return l
	}
	return err.Error()
}

// applyPatchesWindows uses the Windows Update Agent COM API. The selection
// travels as base64 JSON so titles with quotes or brackets cannot break
// the script, and STAGE lines on stdout drive the progress report.
func applyPatchesWindows(ctx context.Context, names []string, report patchProgress) (patchApplyResult, error) {
	var res patchApplyResult
	res.Attempts = 1
	selection, _ := json.Marshal(names)
	script := `
$sel = @()
$raw = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("` + base64.StdEncoding.EncodeToString(selection) + `"))
if ($raw -and $raw -ne "null") { $sel = @(ConvertFrom-Json $raw) }
$s = New-Object -ComObject Microsoft.Update.Session
$searcher = $s.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0")
$wanted = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) { if ($sel.Count -eq 0 -or $sel -contains $u.Title) { $wanted.Add($u) | Out-Null } }
if ($wanted.Count -eq 0) { Write-Output "no pending updates selected"; exit 0 }
# One update at a time, so the person at the computer (Self Service) and
# the console see "3 of 7: <title>" rather than one long silence.
$n = $wanted.Count; $i = 0
foreach ($u in $wanted) {
  $i++; Write-Output ("STEP downloading " + $i + " " + $n + " " + $u.Title)
  $one = New-Object -ComObject Microsoft.Update.UpdateColl; $one.Add($u) | Out-Null
  $d = $s.CreateUpdateDownloader(); $d.Updates = $one; $d.Download() | Out-Null
}
$ok = $true; $reboot = $false; $i = 0
foreach ($u in $wanted) {
  $i++
  if (-not $u.IsDownloaded) { Write-Output ("not downloaded: " + $u.Title); $ok = $false; continue }
  Write-Output ("STEP installing " + $i + " " + $n + " " + $u.Title)
  $one = New-Object -ComObject Microsoft.Update.UpdateColl; $one.Add($u) | Out-Null
  $inst = $s.CreateUpdateInstaller(); $inst.Updates = $one
  $r = $inst.Install()
  Write-Output ("installed " + $u.Title + ": result code " + $r.ResultCode + ", reboot required: " + $r.RebootRequired)
  if ($r.RebootRequired) { $reboot = $true }
  if ($r.ResultCode -ne 2) { $ok = $false }
}
if ($reboot) { Write-Output "REBOOT_REQUIRED" }
if (-not $ok) { exit 1 }`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return res, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return res, err
	}
	var out bytes.Buffer
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		out.WriteString(line + "\n")
		switch {
		case strings.HasPrefix(line, "STAGE "):
			report(strings.TrimPrefix(line, "STAGE "), "", 1)
		case strings.HasPrefix(line, "STEP "):
			if stage, detail, ok := parsePatchStep(line); ok {
				report(stage, detail, 1)
			}
		case line == "REBOOT_REQUIRED":
			res.RebootRequired = true
		default:
			if title, ok := parseWindowsInstalled(line); ok {
				res.Installed = append(res.Installed, title)
			}
		}
	}
	err = cmd.Wait()
	res.Output = out.String() + stderr.String()
	return res, err
}

// parseWindowsInstalled reads "installed <title>: result code <n>, ..."
// and returns the title when the code is 2 (succeeded) or 3 (succeeded
// with errors). The last ": result code " splits it, since a title may
// carry colons of its own.
func parseWindowsInstalled(line string) (string, bool) {
	if !strings.HasPrefix(line, "installed ") {
		return "", false
	}
	i := strings.LastIndex(line, ": result code ")
	if i < 0 {
		return "", false
	}
	code, _, _ := strings.Cut(line[i+len(": result code "):], ",")
	if c := strings.TrimSpace(code); c != "2" && c != "3" {
		return "", false
	}
	return line[len("installed "):i], true
}

// parsePatchStep reads "STEP <stage> <i> <n> <title>" from the Windows
// script into the stage and "i of n: title", the form the Self Service
// window turns into a progress bar.
func parsePatchStep(line string) (stage, detail string, ok bool) {
	f := strings.SplitN(strings.TrimPrefix(line, "STEP "), " ", 4)
	if len(f) < 3 {
		return "", "", false
	}
	i, e1 := strconv.Atoi(f[1])
	n, e2 := strconv.Atoi(f[2])
	if e1 != nil || e2 != nil || i < 1 || n < i {
		return "", "", false
	}
	detail = fmt.Sprintf("%d of %d", i, n)
	if len(f) == 4 && strings.TrimSpace(f[3]) != "" {
		detail += ": " + strings.TrimSpace(f[3])
	}
	return f[0], detail, true
}

// parseAptKeptBack lists the packages apt-get reported as "kept back":
//
//	The following packages have been kept back:
//	  linux-image-rpi-2712 pve-firewall
func parseAptKeptBack(out string) []string {
	var kept []string
	in := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "The following packages have been kept back") {
			in = true
			continue
		}
		if in {
			if !strings.HasPrefix(line, " ") {
				in = false
				continue
			}
			for _, f := range strings.Fields(line) {
				if !slices.Contains(kept, f) {
					kept = append(kept, f)
				}
			}
		}
	}
	return kept
}

// aptHeld lists the packages held with apt-mark hold. A failure reads as
// no holds, and apt itself still refuses to change a held package.
func aptHeld(ctx context.Context) map[string]bool {
	out, err := exec.CommandContext(ctx, "apt-mark", "showhold").Output()
	if err != nil {
		return nil
	}
	held := map[string]bool{}
	for _, f := range strings.Fields(string(out)) {
		held[strings.SplitN(f, ":", 2)[0]] = true
	}
	return held
}

// parseAptUpdateErrors returns apt-get update's error lines, without the
// generic "some index files failed" summary that follows the real ones.
func parseAptUpdateErrors(out string) []string {
	var errs []string
	for _, line := range strings.Split(out, "\n") {
		msg, ok := strings.CutPrefix(strings.TrimSpace(line), "E: ")
		if !ok || strings.HasPrefix(msg, "Some index files failed to download") {
			continue
		}
		if !slices.Contains(errs, msg) {
			errs = append(errs, msg)
		}
	}
	return errs
}

// aptUpdateReachedAny says whether any repository answered, so a machine
// with no network still fails the job rather than install from old lists.
func aptUpdateReachedAny(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Hit:") || strings.HasPrefix(line, "Get:") {
			return true
		}
	}
	return false
}

// aptUnmetReason picks the line that says why a failed install failed:
// the first unmet dependency, else the first error.
func aptUnmetReason(out string) string {
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if i := strings.Index(line, "Depends: "); i >= 0 {
			return strings.TrimSpace(line[i:])
		}
	}
	for _, line := range lines {
		if msg, ok := strings.CutPrefix(line, "E: "); ok {
			return msg
		}
	}
	return "apt could not resolve it"
}

// patchesStillPending checks the job's work against the machine: the
// updates it set out to install (by name) that are still reported
// pending afterwards. Split into those waiting only on a restart and the
// rest, which did not install.
func patchesStillPending(targeted []string, after []proto.PatchInfo) (needRestart, notInstalled []string) {
	want := map[string]bool{}
	for _, n := range targeted {
		want[strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n), "Label:"))] = true
	}
	for _, p := range after {
		if !want[p.Name] {
			continue
		}
		if p.RestartRequired {
			needRestart = append(needRestart, p.Name)
		} else {
			notInstalled = append(notInstalled, p.Name)
		}
	}
	return needRestart, notInstalled
}

// collectPatchesReported is collectPatches for the paths that keep the
// patches sensor current (the sensor loop, the republish after a patch job,
// Rescan now), and it also publishes how the check went as the
// patch_status sensor.
func (a *Agent) collectPatchesReported(ctx context.Context) ([]proto.PatchInfo, error) {
	patches, err := collectPatches(ctx, a.nc, a.agentID)
	st := proto.PatchStatus{OK: err == nil, CheckedAt: time.Now().UTC()}
	if err != nil {
		st.Error = err.Error()
		if len(st.Error) > 2000 {
			st.Error = st.Error[:2000]
		}
		st.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	}
	a.publishSensor(context.WithoutCancel(ctx), proto.SensorPatchStatus, st)
	return patches, err
}
