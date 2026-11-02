//go:build !windows

package agent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Where the agent's own service is defined, by service manager, as the
// installer (internal/server/deploy.go) writes it.
const (
	agentSystemdUnit = "/etc/systemd/system/mustra-agent.service"
	openrcScript     = "/etc/init.d/mustra-agent"
	launchdPlist     = "/Library/LaunchDaemons/com.mustra.agent.plist"
	launchdLabel     = "com.mustra.agent"
	recoverUnit      = "/etc/systemd/system/mustra-agent-recover.service"
	recoverTimer     = "/etc/systemd/system/mustra-agent-recover.timer"
	recoverCron      = "/etc/cron.d/mustra-agent-recover"
	recoverPlist     = "/Library/LaunchDaemons/com.mustra.agent.recover.plist"
	recoverLDLabel   = "com.mustra.agent.recover"
)

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// agentServiceRegistered reports whether the agent's service is installed
// and, if so, whether it is enabled to run.
func agentServiceRegistered() (installed, enabled bool) {
	switch runtime.GOOS {
	case "linux":
		if fileExists(agentSystemdUnit) {
			out, _ := exec.Command("systemctl", "is-enabled", "mustra-agent").Output()
			state := strings.TrimSpace(string(out))
			return true, state == "enabled" || state == "enabled-runtime"
		}
		if fileExists(openrcScript) {
			out, _ := exec.Command("rc-update", "show", "default").Output()
			return true, bytes.Contains(out, []byte("mustra-agent"))
		}
	case "darwin":
		if fileExists(launchdPlist) {
			out, _ := exec.Command("launchctl", "print-disabled", "system").Output()
			return true, !bytes.Contains(out, []byte(`"`+launchdLabel+`" => disabled`)) &&
				!bytes.Contains(out, []byte(`"`+launchdLabel+`" => true`))
		}
	}
	return false, false
}

// restartAgentService starts the service again after the recovery job
// found it down: whatever supervises it on this host.
func restartAgentService(dataDir string) error {
	if runtime.GOOS == "linux" && !hasSystemd() && fileExists(openrcScript) {
		return exec.Command("rc-service", "mustra-agent", "restart").Run()
	}
	return startAgentService(dataDir)
}

func recoverArgs(lkg, exe, dataDir string) []string {
	return []string{lkg, "--recover", dataDir, "--recover-exe", exe}
}

// writeIfChanged writes content to path only when it differs, and reports
// whether it wrote: the job is re-registered on every start, and a
// rewrite should not reload a service manager for nothing.
func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		return false, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}

// installRecoveryJob registers the recovery job with the host's scheduler.
func installRecoveryJob(lkg, exe, dataDir string) error {
	args := recoverArgs(lkg, exe, dataDir)
	switch {
	case runtime.GOOS == "linux" && hasSystemd():
		unit := fmt.Sprintf(`[Unit]
Description=mustra agent recovery: restart the agent, or restore its last known good build, if it stopped running
ConditionPathExists=%s

[Service]
Type=oneshot
ExecStart=%s
`, lkg, systemdQuote(args))
		timer := fmt.Sprintf(`[Unit]
Description=Check every %d minutes that the mustra agent is running

[Timer]
OnBootSec=%dmin
OnUnitActiveSec=%dmin
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
`, int(recoverInterval.Minutes()), int(recoverInterval.Minutes()), int(recoverInterval.Minutes()))
		a, err := writeIfChanged(recoverUnit, unit, 0o644)
		if err != nil {
			return err
		}
		b, err := writeIfChanged(recoverTimer, timer, 0o644)
		if err != nil {
			return err
		}
		if a || b {
			if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
				return err
			}
		}
		return exec.Command("systemctl", "enable", "--now", "mustra-agent-recover.timer").Run()
	case runtime.GOOS == "linux":
		if !fileExists("/etc/cron.d") {
			return fmt.Errorf("no systemd and no /etc/cron.d to schedule recovery with")
		}
		line := fmt.Sprintf("# mustra agent recovery; removed with the agent.\n*/%d * * * * root %s >/dev/null 2>&1\n",
			int(recoverInterval.Minutes()), shellJoin(args))
		_, err := writeIfChanged(recoverCron, line, 0o644)
		return err
	case runtime.GOOS == "darwin":
		var b strings.Builder
		for _, a := range args {
			b.WriteString("    <string>" + xmlEscape(a) + "</string>\n")
		}
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
%s  </array>
  <key>StartInterval</key><integer>%d</integer>
  <key>RunAtLoad</key><false/>
</dict>
</plist>
`, recoverLDLabel, b.String(), int(recoverInterval.Seconds()))
		changed, err := writeIfChanged(recoverPlist, plist, 0o644)
		if err != nil {
			return err
		}
		if changed {
			_ = exec.Command("launchctl", "bootout", "system/"+recoverLDLabel).Run()
			return exec.Command("launchctl", "bootstrap", "system", recoverPlist).Run()
		}
		return nil
	}
	return fmt.Errorf("no scheduler for recovery on %s", runtime.GOOS)
}

// uninstallRecoveryJob removes the job once the agent itself is gone.
func uninstallRecoveryJob() error {
	switch runtime.GOOS {
	case "linux":
		if fileExists(recoverTimer) {
			_ = exec.Command("systemctl", "disable", "--now", "mustra-agent-recover.timer").Run()
			_ = os.Remove(recoverTimer)
			_ = os.Remove(recoverUnit)
			_ = exec.Command("systemctl", "daemon-reload").Run()
		}
		_ = os.Remove(recoverCron)
	case "darwin":
		_ = exec.Command("launchctl", "bootout", "system/"+recoverLDLabel).Run()
		_ = os.Remove(recoverPlist)
	}
	return nil
}

// systemdQuote joins arguments for an ExecStart= line, quoting each so a
// path with a space stays one argument.
func systemdQuote(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(a) + `"`
	}
	return strings.Join(q, " ")
}

func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shQuoteArg(a)
	}
	return strings.Join(q, " ")
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
