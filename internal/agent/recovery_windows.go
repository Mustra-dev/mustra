package agent

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/svc/mgr"
)

// The recovery job on Windows is a scheduled task running as SYSTEM.
const recoverTaskName = `\mustra\agent recovery`

// agentServiceRegistered reports whether the agent's service is installed
// and not set to Disabled.
func agentServiceRegistered() (installed, enabled bool) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return false, false
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return true, true
	}
	return true, cfg.StartType != mgr.StartDisabled
}

func restartAgentService(dataDir string) error { return startAgentService(dataDir) }

// winQuote quotes one argument for a command line the way
// CommandLineToArgvW reads it.
func winQuote(s string) string { return syscall.EscapeArg(s) }

// installRecoveryJob registers (or updates) the scheduled task.
func installRecoveryJob(lkg, exe, dataDir string) error {
	tr := strings.Join([]string{winQuote(lkg), "--recover", winQuote(dataDir), "--recover-exe", winQuote(exe)}, " ")
	if len(tr) > 261 {
		return fmt.Errorf("the recovery command is longer than a scheduled task allows (%d characters)", len(tr))
	}
	out, err := exec.Command("schtasks.exe", "/Create", "/F", "/TN", recoverTaskName, "/TR", tr,
		"/SC", "MINUTE", "/MO", fmt.Sprint(int(recoverInterval.Minutes())), "/RU", "SYSTEM", "/RL", "HIGHEST").CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallRecoveryJob() error {
	_ = exec.Command("schtasks.exe", "/Delete", "/F", "/TN", recoverTaskName).Run()
	return nil
}
