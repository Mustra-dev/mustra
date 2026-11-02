//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Host health for the "health" metrics collector: what an upgrade left
// behind. These are the names and labels of the textfile collectors
// operators already alert on (node_health_metrics.py for dpkg and stale
// executables, prometheus-node-exporter-collectors' apt_info.py for apt),
// so rules written for them keep working:
//
//	node_dpkg_broken_packages, node_dpkg_broken_package{package,state}
//	node_service_stale_exe{service}, node_service_stale_exe_count,
//	node_service_stale_libs_count
//	apt_upgrades_pending{origin,arch}, apt_upgrades_held{origin,arch},
//	apt_autoremove_pending, apt_package_cache_timestamp_seconds
//	node_reboot_required
//	node_health_metrics_ok, node_health_metrics_last_run_seconds
//
// Collecting them runs apt, dpkg-query and systemctl, a second or two of
// work, so it happens in the background every healthEvery and each batch
// carries the latest result.

const healthEvery = 5 * time.Minute

// healthIgnoreServices are never reported stale, as in
// node_health_metrics.py: restarting them is more disruptive than the
// staleness.
var healthIgnoreServices = map[string]bool{
	"user@0.service": true, "systemd-journald.service": true,
	"systemd-logind.service": true, "dbus.service": true,
}

// dpkgBrokenStates are dpkg states meaning an install or upgrade did not
// finish. config-files (removed, not purged) is normal and absent.
var dpkgBrokenStates = map[string]bool{
	"half-configured": true, "half-installed": true, "unpacked": true,
	"triggers-awaited": true, "triggers-pending": true,
}

type healthSample struct {
	name   string
	value  float64
	labels []string
}

// backgroundCollector runs a collection too slow for every batch (it
// shells out) at most once per every, in the background; each batch
// carries the latest result. The first batches after start carry none
// until the first run finishes.
type backgroundCollector struct {
	every   time.Duration
	timeout time.Duration
	collect func(context.Context) []healthSample

	mu      sync.Mutex
	samples []healthSample
	at      time.Time
	running bool
}

func (b *backgroundCollector) addTo(m *metricSet) {
	b.mu.Lock()
	if !b.running && time.Since(b.at) >= b.every {
		b.running = true
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
			s := b.collect(ctx)
			cancel()
			b.mu.Lock()
			b.samples, b.at, b.running = s, time.Now(), false
			b.mu.Unlock()
		}()
	}
	samples := b.samples
	b.mu.Unlock()
	for _, s := range samples {
		m.gauge(s.name, s.value, s.labels...)
	}
}

var healthCollector = &backgroundCollector{every: healthEvery, timeout: 2 * time.Minute, collect: collectHealth}

func addHealthMetrics(m *metricSet) { healthCollector.addTo(m) }

func collectHealth(ctx context.Context) []healthSample {
	var out []healthSample
	add := func(name string, v float64, labels ...string) {
		out = append(out, healthSample{name, v, labels})
	}
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		broken := dpkgBroken(ctx)
		add("node_dpkg_broken_packages", float64(len(broken)))
		for _, b := range broken {
			add("node_dpkg_broken_package", 1, "package", b[0], "state", b[1])
		}
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		if units, libs, ok := staleServices(ctx); ok {
			for _, u := range units {
				add("node_service_stale_exe", 1, "service", u)
			}
			add("node_service_stale_exe_count", float64(len(units)))
			add("node_service_stale_libs_count", float64(libs))
		}
	}
	if _, err := exec.LookPath("apt"); err == nil {
		out = append(out, aptHealth(ctx)...)
	}
	reboot := 0.0
	if _, err := os.Stat("/run/reboot-required"); err == nil {
		reboot = 1
	}
	add("node_reboot_required", reboot)
	ok := 1.0
	if ctx.Err() != nil {
		ok = 0
	}
	add("node_health_metrics_ok", ok)
	add("node_health_metrics_last_run_seconds", float64(time.Now().Unix()))
	return out
}

// dpkgBroken lists [package, state] for packages whose install did not
// finish: an error flag, or a broken state.
func dpkgBroken(ctx context.Context) [][2]string {
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W",
		"-f=${binary:Package}\t${db:Status-Want}\t${db:Status-Status}\t${db:Status-Eflag}\n").Output()
	if err != nil {
		return nil
	}
	return parseDpkgBroken(string(out))
}

func parseDpkgBroken(out string) [][2]string {
	var broken [][2]string
	for _, line := range strings.Split(out, "\n") {
		p := strings.Split(line, "\t")
		if len(p) != 4 {
			continue
		}
		if p[3] != "ok" || dpkgBrokenStates[p[2]] {
			broken = append(broken, [2]string{strings.SplitN(p[0], ":", 2)[0], p[2]})
		}
	}
	return broken
}

// staleServices returns the active services whose main process runs a
// deleted executable, and how many have deleted shared libraries mapped.
func staleServices(ctx context.Context) (units []string, libs int, ok bool) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--type=service", "--state=active",
		"--property=Id", "--property=MainPID", "--property=ActiveState", "*").Output()
	if err != nil {
		return nil, 0, false
	}
	for _, svc := range parseSystemctlServices(string(out)) {
		if healthIgnoreServices[svc.unit] {
			continue
		}
		if exeDeleted(svc.pid) {
			units = append(units, svc.unit)
		}
		if libsDeleted(svc.pid) {
			libs++
		}
	}
	sort.Strings(units)
	return units, libs, true
}

func libsDeleted(pid int) bool {
	f, err := os.Open(procRoot + "/" + strconv.Itoa(pid) + "/maps")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasSuffix(line, " (deleted)") && (strings.Contains(line, ".so.") || strings.HasSuffix(strings.TrimSuffix(line, " (deleted)"), ".so")) {
			return true
		}
	}
	return false
}

// aptHealth is apt_info.py without python-apt: pending and held upgrades
// by origin ("Origin:Codename/Suite", from the lists' Release files) and
// architecture, autoremovable packages, when the lists were last
// refreshed, as that script reports them.
func aptHealth(ctx context.Context) []healthSample {
	var out []healthSample
	cmd := exec.CommandContext(ctx, "apt", "list", "--upgradable")
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	listing, err := cmd.Output()
	if err == nil {
		origins := aptReleaseOrigins(filepath.Join("/var/lib/apt/lists"))
		pending, held := countAptUpgrades(string(listing), origins, aptHeld(ctx))
		for _, k := range sortedKeys(pending) {
			out = append(out, healthSample{"apt_upgrades_pending", float64(pending[k]), []string{"origin", k[0], "arch", k[1]}})
		}
		for _, k := range sortedKeys(held) {
			out = append(out, healthSample{"apt_upgrades_held", float64(held[k]), []string{"origin", k[0], "arch", k[1]}})
		}
	}
	sim := exec.CommandContext(ctx, "apt-get", "-s", "autoremove")
	sim.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	if b, err := sim.Output(); err == nil {
		n := 0
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Remv ") {
				n++
			}
		}
		out = append(out, healthSample{"apt_autoremove_pending", float64(n), nil})
	}
	stamp := "/var/lib/apt/lists/partial"
	if b, err := exec.CommandContext(ctx, "apt-config", "shell", "V", "APT::Periodic::Update-Package-Lists").Output(); err == nil {
		v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "V=")), "'\"")
		if v != "" && v != "0" && !strings.EqualFold(v, "false") && !strings.EqualFold(v, "no") {
			if _, err := os.Stat("/var/lib/apt/periodic/update-success-stamp"); err == nil {
				stamp = "/var/lib/apt/periodic/update-success-stamp"
			}
		}
	}
	if fi, err := os.Stat(stamp); err == nil {
		out = append(out, healthSample{"apt_package_cache_timestamp_seconds", float64(fi.ModTime().UnixNano()) / 1e9, nil})
	}
	return out
}

// aptOrigin is one Release file's identity.
type aptOrigin struct{ origin, codename, suite string }

// aptReleaseOrigins maps each suite and codename apt list may name to the
// Release file that defines it.
func aptReleaseOrigins(dir string) map[string]aptOrigin {
	out := map[string]aptOrigin{}
	files, _ := filepath.Glob(filepath.Join(dir, "*Release"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		o := parseReleaseFile(b)
		if o.suite != "" {
			out[o.suite] = o
		}
		if o.codename != "" {
			if _, taken := out[o.codename]; !taken {
				out[o.codename] = o
			}
		}
	}
	return out
}

func parseReleaseFile(b []byte) aptOrigin {
	var o aptOrigin
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "-----BEGIN PGP SIGNATURE") {
			break
		}
		if line == "" || line[0] == ' ' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Origin":
			o.origin = strings.TrimSpace(v)
		case "Codename":
			o.codename = strings.TrimSpace(v)
		case "Suite":
			o.suite = strings.TrimSpace(v)
		}
	}
	return o
}

// countAptUpgrades counts `apt list --upgradable` lines by origin label
// and architecture. As in apt_info.py, held packages count as pending too
// and are also counted as held.
func countAptUpgrades(listing string, origins map[string]aptOrigin, held map[string]bool) (pending, heldCount map[[2]string]int) {
	pending, heldCount = map[[2]string]int{}, map[[2]string]int{}
	sc := bufio.NewScanner(bytes.NewReader([]byte(listing)))
	for sc.Scan() {
		line := sc.Text()
		slash := strings.IndexByte(line, '/')
		if slash <= 0 || strings.HasPrefix(line, "Listing") {
			continue
		}
		name := line[:slash]
		f := strings.Fields(line[slash+1:])
		if len(f) < 3 {
			continue
		}
		set := map[string]bool{}
		for _, s := range strings.Split(f[0], ",") {
			if s == "now" || s == "" {
				continue
			}
			if o, ok := origins[s]; ok {
				set[o.origin+":"+o.codename+"/"+o.suite] = true
			} else {
				set[":/"+s] = true
			}
		}
		labels := make([]string, 0, len(set))
		for k := range set {
			labels = append(labels, k)
		}
		sort.Strings(labels)
		key := [2]string{strings.Join(labels, ","), f[2]}
		pending[key]++
		if held[name] {
			heldCount[key]++
		}
	}
	return pending, heldCount
}

func sortedKeys(m map[[2]string]int) [][2]string {
	keys := make([][2]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	return keys
}
