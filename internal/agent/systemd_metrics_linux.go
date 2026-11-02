//go:build linux

package agent

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// The "systemd" metrics collector is node_exporter's: every loaded
// service, socket, timer and path unit in each of the five active states
// (node_systemd_unit_state{name,state,type}, 1 for the current one, type
// being a service's Type=), the count of units per state, whether the
// system is running, and the systemd version. It asks systemctl, so it
// runs in the background once a minute.

var systemdCollector = &backgroundCollector{every: time.Minute, timeout: 30 * time.Second, collect: collectSystemd}

var systemdStates = []string{"activating", "active", "deactivating", "failed", "inactive"}

func addSystemdMetrics(m *metricSet) {
	if _, err := exec.LookPath("systemctl"); err == nil {
		systemdCollector.addTo(m)
	}
}

func collectSystemd(ctx context.Context) []healthSample {
	var out []healthSample
	show, err := exec.CommandContext(ctx, "systemctl", "show", "--all", "--type=service,socket,timer,path",
		"--property=Id,Type,ActiveState,LoadState", "--no-pager", "*").Output()
	if err != nil {
		return nil
	}
	for _, u := range parseSystemdUnits(string(show)) {
		for _, st := range systemdStates {
			v := 0.0
			if st == u.active {
				v = 1
			}
			out = append(out, healthSample{"node_systemd_unit_state", v, []string{"name", u.name, "state", st, "type", u.typ}})
		}
	}
	if list, err := exec.CommandContext(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager").Output(); err == nil {
		counts := map[string]int{}
		for _, line := range strings.Split(string(list), "\n") {
			f := strings.Fields(line)
			// Every unit counts, masked and not-found ones too, as in
			// node_exporter.
			if len(f) >= 3 {
				counts[f[2]]++
			}
		}
		for _, st := range systemdStates {
			out = append(out, healthSample{"node_systemd_units", float64(counts[st]), []string{"state", st}})
		}
	}
	running := 0.0
	if b, _ := exec.CommandContext(ctx, "systemctl", "is-system-running").Output(); strings.TrimSpace(string(b)) == "running" {
		running = 1
	}
	out = append(out, healthSample{"node_systemd_system_running", running, nil})
	if b, err := exec.CommandContext(ctx, "systemctl", "--version").Output(); err == nil {
		if v, num, ok := parseSystemdVersion(string(b)); ok {
			out = append(out, healthSample{"node_systemd_version", num, []string{"version", v}})
		}
	}
	return out
}

type systemdUnit struct{ name, typ, active string }

// parseSystemdUnits reads `systemctl show` blocks, keeping loaded units.
// Only a service has a Type=; node_exporter leaves it empty for the rest.
func parseSystemdUnits(out string) []systemdUnit {
	var units []systemdUnit
	cur := map[string]string{}
	flush := func() {
		if cur["Id"] != "" && cur["LoadState"] == "loaded" {
			typ := ""
			if strings.HasSuffix(cur["Id"], ".service") {
				typ = cur["Type"]
			}
			units = append(units, systemdUnit{name: cur["Id"], typ: typ, active: cur["ActiveState"]})
		}
		cur = map[string]string{}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		cur[k] = v
	}
	flush()
	return units
}

var systemdVersionRe = regexp.MustCompile(`^systemd (\d+)(?: \(([^)]+)\))?`)
var leadingVersion = regexp.MustCompile(`^\d+(\.\d+)?`)

// parseSystemdVersion reads "systemd 257 (257.13-1~deb13u1)": the label is
// the full version in parentheses, the value its leading number.
func parseSystemdVersion(out string) (string, float64, bool) {
	m := systemdVersionRe.FindStringSubmatch(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
	if m == nil {
		return "", 0, false
	}
	v := m[2]
	if v == "" {
		v = m[1]
	}
	return v, atof(leadingVersion.FindString(v)), true
}
