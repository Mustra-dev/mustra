package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectProcesses lists currently running processes. gopsutil's process
// package is genuinely cross-platform, unlike services/installed-apps
// below, so this needs no OS branching.
// maxCmdlineChars bounds what a process reports for its command line. Long
// enough to keep the arguments that matter for working out what something
// was doing, short enough that a pathological one cannot bloat the sensor.
const maxCmdlineChars = 512

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func collectProcesses(ctx context.Context) ([]proto.ProcessInfo, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	out := make([]proto.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue // process exited between listing and inspection; skip rather than fail the whole sensor
		}
		info := proto.ProcessInfo{PID: p.Pid, Name: name}
		if ppid, err := p.PpidWithContext(ctx); err == nil {
			info.PPID = ppid
		}
		if cmd, err := p.CmdlineWithContext(ctx); err == nil {
			// Bounded here rather than at the server: an unbounded command
			// line is paid for on every collection by every endpoint, and a
			// Java service's classpath alone can run to kilobytes.
			info.Cmdline = truncate(redactCmdline(cmd), maxCmdlineChars)
		}
		if cpu, err := p.CPUPercentWithContext(ctx); err == nil {
			info.CPUPercent = cpu
		}
		if mp, err := p.MemoryPercentWithContext(ctx); err == nil {
			info.MemPercent = mp
		}
		if mi, err := p.MemoryInfoWithContext(ctx); err == nil && mi != nil {
			info.MemRSSMB = mi.RSS / (1024 * 1024)
		}
		if user, err := p.UsernameWithContext(ctx); err == nil {
			info.Username = user
		}
		out = append(out, info)
	}
	return out, nil
}

// collectServices lists OS services. No single library covers Linux
// (systemd), macOS (launchd), and Windows (SCM) — each is shelled out to
// its native inventory command rather than pulling in three more
// dependencies for something this agent-footprint-sensitive.
func collectServices(ctx context.Context) ([]proto.ServiceInfo, error) {
	if inHAOSAddon() {
		return collectServicesHAOS(ctx)
	}
	switch runtime.GOOS {
	case "linux":
		return collectServicesLinux(ctx)
	case "darwin":
		return collectServicesDarwin(ctx)
	case "windows":
		return collectServicesWindows(ctx)
	default:
		return nil, fmt.Errorf("services sensor not supported on %s", runtime.GOOS)
	}
}

func collectServicesLinux(ctx context.Context) ([]proto.ServiceInfo, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		if _, rcErr := exec.LookPath("rc-status"); rcErr == nil {
			return collectServicesOpenRC(ctx)
		}
	}
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	var services []proto.ServiceInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		// UNIT LOAD ACTIVE SUB DESCRIPTION
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		services = append(services, proto.ServiceInfo{
			Name:   strings.TrimSuffix(fields[0], ".service"),
			Status: fields[3], // SUB state: running, dead, exited, ...
		})
	}
	return services, sc.Err()
}

// collectServicesOpenRC lists OpenRC services (Alpine) from `rc-status
// -a`: "name [ state ]" lines under runlevel headings. A service in
// several runlevels is listed once.
func collectServicesOpenRC(ctx context.Context) ([]proto.ServiceInfo, error) {
	out, err := exec.CommandContext(ctx, "rc-status", "-a", "--nocolor").Output()
	if err != nil {
		return nil, fmt.Errorf("rc-status: %w", err)
	}
	return parseRCStatus(string(out)), nil
}

func parseRCStatus(out string) []proto.ServiceInfo {
	var services []proto.ServiceInfo
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		open, close := strings.IndexByte(line, '['), strings.LastIndexByte(line, ']')
		if open <= 0 || close <= open {
			continue
		}
		name := strings.TrimSpace(line[:open])
		state := strings.TrimSpace(line[open+1 : close])
		if name == "" || strings.Contains(name, " ") || seen[name] {
			continue
		}
		seen[name] = true
		services = append(services, proto.ServiceInfo{Name: name, Status: state})
	}
	return services
}

func collectServicesDarwin(ctx context.Context) ([]proto.ServiceInfo, error) {
	out, err := exec.CommandContext(ctx, "launchctl", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("launchctl list: %w", err)
	}
	var services []proto.ServiceInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	first := true
	for sc.Scan() {
		if first { // header line: PID Status Label
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		status := "stopped"
		if fields[0] != "-" {
			status = "running"
		}
		services = append(services, proto.ServiceInfo{Name: fields[2], Status: status})
	}
	return services, sc.Err()
}

// collectServicesWindows lists Win32 services from the Service Control
// Manager (sensors_native_windows.go).
func collectServicesWindows(ctx context.Context) ([]proto.ServiceInfo, error) {
	return collectServicesNative(ctx)
}

func windowsServiceStatus(v int) string {
	switch v {
	case 1:
		return "stopped"
	case 4:
		return "running"
	case 2, 3, 6, 7:
		return "changing"
	case 5:
		return "paused"
	default:
		return "unknown"
	}
}

func windowsServiceStartType(v int) string {
	switch v {
	case 0, 1:
		return "boot/system"
	case 2:
		return "automatic"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	default:
		return ""
	}
}

// collectInstalledApps lists installed applications/packages.
func collectInstalledApps(ctx context.Context) ([]proto.InstalledApp, error) {
	if inHAOSAddon() {
		return collectAppsHAOS(ctx)
	}
	switch runtime.GOOS {
	case "linux":
		return collectAppsLinux(ctx)
	case "darwin":
		return collectAppsDarwin(ctx)
	case "windows":
		return collectAppsWindows(ctx)
	default:
		return nil, fmt.Errorf("installed_apps sensor not supported on %s", runtime.GOOS)
	}
}

func collectAppsLinux(ctx context.Context) ([]proto.InstalledApp, error) {
	if out, err := exec.CommandContext(ctx, "dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n").Output(); err == nil {
		return parseDpkgApps(out), nil
	}
	if out, err := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\n").Output(); err == nil {
		return parseTabbedApps(out, rpmInstallDate), nil
	}
	if apkPresent() {
		return collectAppsAPK()
	}
	return nil, fmt.Errorf("no supported package manager found (tried dpkg-query, rpm, apk)")
}

// dpkgInstallDate is when the package's file list was last written —
// its install or last upgrade. dpkg keeps no other install record.
func dpkgInstallDate(pkg, arch string) string {
	for _, name := range []string{pkg + ".list", pkg + ":" + arch + ".list"} {
		if st, err := os.Stat("/var/lib/dpkg/info/" + name); err == nil {
			return st.ModTime().UTC().Format("2006-01-02")
		}
	}
	return ""
}

// parseDpkgApps reads dpkg-query's "package, version, architecture, source
// package, source version" lines.
func parseDpkgApps(out []byte) []proto.InstalledApp {
	var apps []proto.InstalledApp
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		app := proto.InstalledApp{Name: f[0], Version: f[1]}
		if len(f) >= 3 {
			app.InstallDate = dpkgInstallDate(f[0], f[2])
		}
		if len(f) >= 5 {
			app.Source, app.SourceVersion = f[3], f[4]
		}
		apps = append(apps, app)
	}
	return apps
}

func rpmInstallDate(_, epoch string) string {
	n, err := strconv.ParseInt(strings.TrimSpace(epoch), 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return time.Unix(n, 0).UTC().Format("2006-01-02")
}

// parseTabbedApps reads "name\tversion[\textra]" lines; installDate turns
// the name and the extra column into an install date, if it can.
func parseTabbedApps(out []byte, installDate func(name, extra string) string) []proto.InstalledApp {
	var apps []proto.InstalledApp
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 3)
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		app := proto.InstalledApp{Name: parts[0]}
		if len(parts) >= 2 {
			app.Version = parts[1]
		}
		if len(parts) == 3 && installDate != nil {
			app.InstallDate = installDate(parts[0], parts[2])
		}
		apps = append(apps, app)
	}
	return apps
}

func collectAppsDarwin(ctx context.Context) ([]proto.InstalledApp, error) {
	var apps []proto.InstalledApp
	for _, dir := range []string{"/Applications", "/Applications/Utilities"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // directory may not exist (e.g. no /Applications/Utilities); not fatal to the sensor
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			if ctx.Err() != nil {
				return apps, ctx.Err()
			}
			bundle := dir + "/" + e.Name()
			app := proto.InstalledApp{Name: strings.TrimSuffix(e.Name(), ".app")}
			// One plutil call gives the version and the executable together;
			// the old defaults-read-per-key approach cost a process per key.
			if out, err := exec.CommandContext(ctx, "plutil", "-convert", "json", "-o", "-", bundle+"/Contents/Info.plist").Output(); err == nil {
				var info struct {
					Version    string `json:"CFBundleShortVersionString"`
					Executable string `json:"CFBundleExecutable"`
				}
				if json.Unmarshal(out, &info) == nil {
					app.Version = strings.TrimSpace(info.Version)
					app.Executable = strings.ToLower(strings.TrimSpace(info.Executable))
				}
			}
			if st, err := os.Stat(bundle); err == nil {
				app.InstallDate = st.ModTime().UTC().Format("2006-01-02")
			}
			// Spotlight records the last launch; "(null)" when it never
			// indexed the bundle or the app was never opened.
			if out, err := exec.CommandContext(ctx, "mdls", "-name", "kMDItemLastUsedDate", "-raw", bundle).Output(); err == nil {
				if t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(string(out))); err == nil {
					app.LastUsed = t.UTC().Format(time.RFC3339)
				}
			}
			apps = append(apps, app)
		}
	}
	return apps, nil
}

// collectAppsWindows reads the Uninstall registry keys in-process
// (sensors_native_windows.go).
func collectAppsWindows(ctx context.Context) ([]proto.InstalledApp, error) {
	raw, err := collectAppsNative(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the uninstall registry: %w", err)
	}
	lastRun := prefetchLastRun()
	apps := make([]proto.InstalledApp, 0, len(raw))
	for _, a := range raw {
		app := proto.InstalledApp{Name: a.DisplayName, Version: a.DisplayVersion, Publisher: a.Publisher}
		if d := strings.TrimSpace(a.InstallDate); len(d) == 8 { // yyyymmdd
			app.InstallDate = d[:4] + "-" + d[4:6] + "-" + d[6:]
		}
		if exe := exeFromDisplayIcon(a.DisplayIcon); exe != "" {
			app.Executable = exe
			if t, ok := lastRun[strings.ToUpper(exe)+".EXE"]; ok {
				app.LastUsed = t.UTC().Format(time.RFC3339)
			}
		}
		apps = append(apps, app)
	}
	return apps, nil
}

// exeFromDisplayIcon takes the program's own icon path — which is the
// program itself for most installers ("C:\...\chrome.exe,0") — and returns
// the lower-case base name without ".exe". Anything that is not an .exe
// (an .ico, a DLL resource) yields "".
func exeFromDisplayIcon(icon string) string {
	p := strings.Trim(strings.TrimSpace(icon), `"`)
	if i := strings.LastIndex(p, ","); i > 0 {
		p = p[:i]
	}
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	l := strings.ToLower(p)
	if !strings.HasSuffix(l, ".exe") {
		return ""
	}
	return strings.TrimSuffix(l, ".exe")
}

// prefetchLastRun reads C:\Windows\Prefetch: each NAME.EXE-HASH.pf is
// rewritten when that program runs, so its modification time is the last
// launch. Needs SYSTEM (the agent is), and prefetch enabled — server SKUs
// often have it off, which just means an empty map.
func prefetchLastRun() map[string]time.Time {
	out := map[string]time.Time{}
	if runtime.GOOS != "windows" {
		return out
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	entries, err := os.ReadDir(root + `\Prefetch`)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := strings.ToUpper(e.Name())
		if !strings.HasSuffix(name, ".PF") {
			continue
		}
		i := strings.LastIndex(name, "-")
		if i <= 0 {
			continue
		}
		exe := name[:i]
		info, err := e.Info()
		if err != nil {
			continue
		}
		if t, ok := out[exe]; !ok || info.ModTime().After(t) {
			out[exe] = info.ModTime()
		}
	}
	return out
}
