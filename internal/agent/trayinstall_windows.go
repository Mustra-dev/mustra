//go:build windows

package agent

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// installEmbeddedTray puts the tray this agent build carries beside it,
// when the installed one differs. The tray used to be written only by the
// installer, so no agent update ever reached it; now it rides in the
// signed agent binary and updates with it.
func (a *Agent) installEmbeddedTray() {
	if len(embeddedTray) == 0 {
		return // a development build without the tray baked in
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	dst := filepath.Join(dir, "mustra-tray.exe")
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, embeddedTray) {
		a.migrateSelfServiceShortcuts(dir)
		return
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, embeddedTray, 0o755); err != nil {
		a.logger.Warn("could not write the tray helper", "error", err)
		return
	}
	// A running image cannot be overwritten but can be renamed; the old
	// copy is cleared on the next install.
	_ = os.Remove(dst + ".old")
	hadOld := false
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, dst+".old"); err != nil {
			_ = os.Remove(tmp)
			a.logger.Warn("could not move the old tray helper aside", "error", err)
			return
		}
		hadOld = true
	}
	if err := os.Rename(tmp, dst); err != nil {
		if hadOld {
			_ = os.Rename(dst+".old", dst)
		}
		a.logger.Warn("could not install the tray helper", "error", err)
		return
	}
	// A tray still running is the old build. End it; the supervisor starts
	// the new one in the signed-in session.
	kill := exec.Command("taskkill.exe", "/F", "/IM", "mustra-tray.exe")
	kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindowTray}
	_ = kill.Run()
	a.tray.reset()
	a.logger.Info("tray helper installed from this agent build")
	a.migrateSelfServiceShortcuts(dir)
}

// migrateSelfServiceShortcuts makes the Self Service shortcuts open the
// tray app (which shows the window and stays in the notification area)
// and removes the separate "Mustra Tray" Start Menu entry and the old
// .cmd launcher, so a machine has one Mustra app, not two. Done once per
// machine; the installer creates the new layout directly.
func (a *Agent) migrateSelfServiceShortcuts(dir string) {
	marker := filepath.Join(a.dataDir(), "shortcuts-one-app")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	const script = `$ErrorActionPreference = 'SilentlyContinue'
$tray = Join-Path $env:MUSTRA_DIR 'mustra-tray.exe'
if (-not (Test-Path $tray)) { exit 1 }
$menu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Mustra'
$shell = New-Object -ComObject WScript.Shell
foreach ($p in @((Join-Path $menu 'Mustra Self Service.lnk'), (Join-Path $env:PUBLIC 'Desktop\Mustra Self Service.lnk'))) {
  if (Test-Path $p) { $l = $shell.CreateShortcut($p); $l.TargetPath = $tray; $l.Arguments = '--open'; $l.WorkingDirectory = $env:MUSTRA_DIR; $l.Save() }
}
Remove-Item -Force (Join-Path $menu 'Mustra Tray.lnk')
Remove-Item -Force (Join-Path $env:MUSTRA_DIR 'Open Self Service.cmd')
exit 0`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(os.Environ(), "MUSTRA_DIR="+dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindowTray}
	if err := cmd.Run(); err != nil {
		a.logger.Warn("could not update the Self Service shortcuts", "error", err)
		return
	}
	_ = os.WriteFile(marker, []byte("1\n"), 0o600)
	a.logger.Info("Self Service shortcuts now open the tray app; the separate tray entry was removed")
}
