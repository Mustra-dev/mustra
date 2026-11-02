package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A package upgrade replaces a binary on disk, but a service that is
// already running keeps executing the old, now-deleted, file until it is
// restarted. apt and dnf restart some services from their maintainer
// scripts and leave the rest, so after every Linux patch install the agent
// restarts whatever is still running a deleted executable. Without this a
// fleet-wide cloudflared upgrade (2026-10-06) left every tunnel on the old
// build for four days, until something else restarted it.

// staleRestartExclude names the services that are reported but never
// restarted: restarting them would cut the session or the bus the agent
// depends on, or would be more disruptive than running stale (databases,
// the hypervisor stack). Anchored on the full unit name so that, for
// example, prometheus-pve-exporter.service is still restarted while
// prometheus.service is not. Kept identical to stale_restart_exclude in
// the ansible heal_stale_services.yml playbook.
var staleRestartExclude = regexp.MustCompile(`^(systemd-|user@)|^(ssh|sshd|salt-minion|salt-master|dbus|docker|containerd|` +
	`postgresql.*|mariadb.*|mysql.*|mongod.*|redis.*|prometheus|` +
	`prometheus-alertmanager|pve.*|corosync|mustra-agent|beacon-agent)\.service$`)

const staleRestartTimeout = 90 * time.Second

type staleServiceResult struct {
	Restarted []string
	Failed    []string
	Skipped   []string
}

// summary is the text appended to the patch run's output, so the console
// shows what was restarted next to what was installed. Empty when nothing
// was stale.
func (r staleServiceResult) summary() string {
	if len(r.Restarted)+len(r.Failed)+len(r.Skipped) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nServices running a replaced binary:\n")
	if len(r.Restarted) > 0 {
		b.WriteString("  restarted: " + strings.Join(r.Restarted, ", ") + "\n")
	}
	if len(r.Failed) > 0 {
		b.WriteString("  restart failed: " + strings.Join(r.Failed, ", ") + "\n")
	}
	if len(r.Skipped) > 0 {
		b.WriteString("  not restarted (excluded, restart by hand): " + strings.Join(r.Skipped, ", ") + "\n")
	}
	return b.String()
}

// restartStaleServices finds active systemd services whose main process
// runs a deleted executable and restarts the ones not excluded. Hosts
// without systemctl (Alpine, the HAOS add-on container) are skipped.
func restartStaleServices(ctx context.Context) staleServiceResult {
	var res staleServiceResult
	if _, err := exec.LookPath("systemctl"); err != nil {
		return res
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--type=service", "--state=active",
		"--property=Id", "--property=MainPID", "--property=ActiveState", "*").Output()
	if err != nil {
		return res
	}
	self := os.Getpid()
	for _, svc := range parseSystemctlServices(string(out)) {
		if svc.pid == self || !exeDeleted(svc.pid) {
			continue
		}
		if staleRestartExclude.MatchString(svc.unit) {
			res.Skipped = append(res.Skipped, svc.unit)
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, staleRestartTimeout)
		err := exec.CommandContext(rctx, "systemctl", "restart", svc.unit).Run()
		cancel()
		if err != nil {
			res.Failed = append(res.Failed, fmt.Sprintf("%s (%v)", svc.unit, err))
			continue
		}
		res.Restarted = append(res.Restarted, svc.unit)
	}
	return res
}

type systemdService struct {
	unit string
	pid  int
}

// parseSystemctlServices reads `systemctl show` output: blank-line
// separated blocks of Key=Value. Only active services with a main PID are
// returned.
func parseSystemctlServices(out string) []systemdService {
	var svcs []systemdService
	cur := map[string]string{}
	flush := func() {
		pid, _ := strconv.Atoi(cur["MainPID"])
		if cur["ActiveState"] == "active" && pid > 0 && strings.HasSuffix(cur["Id"], ".service") {
			svcs = append(svcs, systemdService{unit: cur["Id"], pid: pid})
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
	return svcs
}

func exeDeleted(pid int) bool {
	target, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	return err == nil && strings.HasSuffix(target, " (deleted)")
}
