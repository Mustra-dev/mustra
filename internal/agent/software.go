package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// runSoftwareCommand executes one software-package operation.
//
// The command text comes from the control plane, authored by an operator
// with deploy.manage — that is what a software package *is*, and it's the
// same trust any installer already demands. Two things are still worth
// doing carefully:
//
//   - it runs through the platform's own shell, so a package can use
//     pipes, redirection and && the way an operator expects when they
//     write an install line;
//   - it gets a hard timeout and a non-interactive environment, so a
//     package that stops to ask a question fails in fifteen minutes
//     instead of pinning a goroutine and an endpoint forever.
//
// On macOS the agent is root, which Homebrew refuses to be. A brew command
// is redirected through the account that owns the prefix, so the obvious
// `brew install x` in a package works instead of failing with advice.
// defaultSoftwareTimeout is the budget a package gets when it doesn't
// declare one of its own.
const defaultSoftwareTimeout = 15 * time.Minute

// runSoftwareCommand runs one package operation. timeoutSeconds is the
// package's own command timeout; 0 falls back to
// the default, because the right budget differs enormously between flushing
// a DNS cache and installing an office suite.
func runSoftwareCommand(ctx context.Context, command string, timeoutSeconds int) (string, error) {
	return runSoftwareCommandIn(ctx, command, timeoutSeconds, "")
}

// runSoftwareCommandIn runs the command with workDir as its working
// directory, which is how a staged payload becomes reachable: a package can
// say `msiexec /i setup.msi /qn` and mean the file just placed beside it.
func runSoftwareCommandIn(ctx context.Context, command string, timeoutSeconds int, workDir string) (string, error) {
	budget := defaultSoftwareTimeout
	if timeoutSeconds > 0 {
		budget = time.Duration(timeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	cmd := shellCommand(ctx, command)
	if workDir != "" {
		cmd.Dir = workDir
	}
	cmd.Env = append(childEnv(),
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=a",
		"HOMEBREW_NO_AUTO_UPDATE=1",
		"HOMEBREW_NO_ANALYTICS=1",
	)
	if workDir != "" {
		// Exported as well as being the working directory, for commands
		// that need an absolute path — an installer invoked with a full
		// path, or a script that changes directory itself.
		cmd.Env = append(cmd.Env, "MUSTRA_PACKAGE_DIR="+workDir)
	}
	// The whole process tree goes on timeout, and the output pipes are
	// closed shortly after the shell exits or is killed, so a backgrounded
	// child holding stdout cannot stretch the call past its budget.
	cmd.WaitDelay = softwareWaitDelay
	afterStart, release, err := configureSoftwareProcess(cmd)
	if err != nil {
		return "", err
	}
	defer release()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err = cmd.Start(); err == nil {
		if scopeErr := afterStart(); scopeErr != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return out.String(), fmt.Errorf("configure package process: %w", scopeErr)
		}
		err = cmd.Wait()
	}
	// A killed process only reports a generic non-zero exit, so say plainly
	// that the budget ran out rather than leaving an unexplained failure.
	// The server recognizes this wording (softwareTimeoutPrefix) and records
	// the endpoint as timed out rather than failed; older agents already
	// send the same text, so keep it stable.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out.String(), fmt.Errorf("command exceeded its %s timeout", budget)
	}
	// The command itself finished cleanly; only something it left running
	// in the background kept the output open past WaitDelay.
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		err = nil
	}
	return out.String(), err
}

// softwareWaitDelay bounds how long the agent keeps reading output after the
// command exited or was killed.
const softwareWaitDelay = 5 * time.Second

// wingetPreamble puts the real winget on PATH before an operator's command
// runs.
//
// The agent is a service running as LocalSystem, and winget is not a
// program on PATH — it is an app execution alias in the *user's*
// %LOCALAPPDATA%\Microsoft\WindowsApps. LocalSystem's LOCALAPPDATA is
// C:\Windows\System32\config\systemprofile\AppData\Local, which has no
// such alias. So `winget --version` works perfectly in an administrator's
// PowerShell and reports "not recognized" from a package, which reads as
// mustra being broken rather than as the two contexts being different
// places.
//
// The executable is there and LocalSystem can run it; only the name is
// missing. Measured on a real Windows 11 endpoint: the alias is absent,
// C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__* is
// present, and invoking winget.exe inside it as SYSTEM prints its version.
//
// Prepending the directory to PATH rather than defining an alias, so that
// anything the command shells out to finds winget too. A winget that
// already resolves and runs is left alone; one that resolves but fails to
// start is not: on Windows Server the SYSTEM profile can hold an
// app-execution alias that exits 0xC0000135.
//
// The executable alone is not enough on Windows Server: winget.exe links
// against the framework packages its manifest names (VCLibs and the
// Windows App Runtime), which a packaged app finds through its package
// graph and a process started by path does not, so as SYSTEM it exits
// 0xC0000135 (a DLL not found). Those packages' folders, read from
// winget's own AppxManifest.xml so they follow whatever version is
// installed, go on PATH with it. Only those: putting every runtime on
// PATH loads the wrong one first. Measured on Windows Server 2025.
const wingetPreamble = `$wingetWorks = $false
$c = Get-Command winget -ErrorAction SilentlyContinue
if ($c) { try { & $c.Source --version *> $null; $wingetWorks = ($LASTEXITCODE -eq 0) } catch {} }
if (-not $wingetWorks) {
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
  }
}
`

// needsWinget reports whether a command refers to winget at all. The
// preamble is cheap but not free — it enumerates a directory — so it is
// only prepended when it could matter.
func needsWinget(command string) bool {
	return strings.Contains(strings.ToLower(command), "winget")
}

func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		// PowerShell rather than cmd: winget, Get-Service and the rest of
		// what a Windows package needs all assume it.
		if needsWinget(command) {
			command = wingetPreamble + command
		}
		return exec.CommandContext(ctx, "powershell.exe", "-NoProfile",
			"-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)
	}
	return exec.CommandContext(ctx, "/bin/sh", "-c", rewriteForPlatform(command))
}
