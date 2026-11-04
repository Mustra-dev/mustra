package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
)

type sensorBuffer struct {
	buffer    bytes.Buffer
	truncated bool
	limit     int
}

func (b *sensorBuffer) Len() int       { return b.buffer.Len() }
func (b *sensorBuffer) String() string { return b.buffer.String() }
func (b *sensorBuffer) Bytes() []byte  { return b.buffer.Bytes() }

func (b *sensorBuffer) Write(p []byte) (int, error) {
	n := len(p)
	limit := b.limit
	if limit == 0 {
		limit = sensoroutput.MaxBytes
	}
	remaining := limit - b.Len()
	if n > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	b.buffer.Write(p)
	return n, nil
}

func privatePython() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	path := filepath.Join(filepath.Dir(exe), "python", "bin", "python3")
	if runtime.GOOS == "windows" {
		path = filepath.Join(filepath.Dir(exe), "python", "python.exe")
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("bundled Python 3 unavailable; reinstall or update the mustra agent: %w", err)
	}
	return path, nil
}
func executeCustomSensor(ctx context.Context, def proto.CustomSensorDef) proto.CustomSensorResult {
	return executeCustomSensorAs(ctx, def, "", "")
}
func executeCustomSensorAs(ctx context.Context, def proto.CustomSensorDef, identity, username string) proto.CustomSensorResult {
	if noRemoteCodeActive.Load() {
		return proto.CustomSensorResult{Error: errNoRemoteCode.Error()}
	}
	res := proto.CustomSensorResult{Revision: def.Revision}
	timeout := def.TimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}
	if timeout > 600 {
		timeout = 600
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "mustra-sensor-")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer os.RemoveAll(dir)
	lang := sensoroutput.Language(runtime.GOOS, def.Platform.Language)
	var cmd *exec.Cmd
	script := def.Command
	filename := "sensor.sh"
	switch lang {
	case "go":
		filename = "sensor.bin"
		if runtime.GOOS == "windows" {
			filename = "sensor.exe"
		}
		if err := stageGoSensor(cctx, def.Artifact, filepath.Join(dir, filename)); err != nil {
			res.Error = err.Error()
			return res
		}
		cmd = exec.CommandContext(cctx, filepath.Join(dir, filename))
	case "shell":
		if runtime.GOOS == "windows" {
			res.Error = "shell is unsupported on Windows"
			return res
		}
		cmd = exec.CommandContext(cctx, "/bin/sh", filename)
	case "python":
		path, e := privatePython()
		if e != nil {
			res.Error = e.Error()
			return res
		}
		filename = "sensor.py"
		cmd = exec.CommandContext(cctx, path, "-I", "-S", "-X", "utf8", filename)
	case "powershell", "wql":
		if runtime.GOOS != "windows" {
			res.Error = lang + " is only supported on Windows"
			return res
		}
		filename = "sensor.ps1"
		if lang == "wql" {
			ns := def.Platform.Namespace
			if ns == "" {
				ns = `root\cimv2`
			}
			// Pass the query as data. No interpolation into executable PowerShell source.
			query := base64.StdEncoding.EncodeToString([]byte(script))
			namespace := base64.StdEncoding.EncodeToString([]byte(ns))
			script = `$ErrorActionPreference='Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$q=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + query + `'))
$ns=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + namespace + `'))
try {
 $rows=@(Get-CimInstance -Namespace $ns -Query $q -OperationTimeoutSec ` + fmt.Sprint(timeout) + ` | Select-Object -First 501 | ForEach-Object {
  $row=[ordered]@{}; foreach($p in $_.CimInstanceProperties) { $row[$p.Name]=$p.Value }; $row
 })
 ConvertTo-Json -InputObject $rows -Depth 32 -Compress
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
`
		}
		// Windows PowerShell 5.1 recognizes UTF-8 source reliably with a BOM.
		script = "\xef\xbb\xbf" + script
		cmd = exec.CommandContext(cctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "run.ps1")
	case "batch":
		if runtime.GOOS != "windows" {
			res.Error = "Batch is only supported on Windows"
			return res
		}
		filename = "sensor.cmd"
		script = "@echo off\r\nchcp 65001 >nul\r\n" + strings.ReplaceAll(strings.ReplaceAll(script, "\r\n", "\n"), "\n", "\r\n")
		cmd = exec.CommandContext(cctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/D", "/C", filename)
	default:
		res.Error = "unsupported sensor language: " + lang
		return res
	}
	if len(script) > 512<<10 {
		res.Error = "script exceeds size limit"
		return res
	}
	if lang == "powershell" || lang == "wql" {
		// The script's own exit code wins: "exit 7" inside it sets both
		// $LASTEXITCODE and $? = $false, and checking $? first reported every
		// such exit as 1. For a check script that turned "error" (2) into
		// "false" (1), choosing an else branch it must not. Found by the
		// Windows CI job (#235).
		wrapper := `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
 & (Join-Path $PSScriptRoot 'sensor.ps1')
 $ok = $?
 if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }
 if (-not $ok) { exit 1 }
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
`
		if err = os.WriteFile(filepath.Join(dir, "run.ps1"), []byte(wrapper), 0600); err != nil {
			res.Error = err.Error()
			return res
		}
	}
	if lang != "go" {
		if err = os.WriteFile(filepath.Join(dir, filename), []byte(script), 0600); err != nil {
			res.Error = err.Error()
			return res
		}
	}
	cmd.Dir = dir
	cmd.Env = childEnv()
	for name, value := range def.Inputs {
		cmd.Env = append(cmd.Env, "MUSTRA_PARAM_"+name+"="+value)
	}
	cmd.WaitDelay = 2 * time.Second
	afterStart, cleanup, err := configureSensorProcess(cmd)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer cleanup()
	if identity == "user" {
		defer cleanupDeployUser(cmd)
		if err = configureDeployUser(cctx, cmd, username, dir); err != nil {
			res.Error = err.Error()
			return res
		}
	}
	var stdout, stderr sensorBuffer
	stderr.limit = 16 << 10
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Start()
	if err == nil {
		if scopeErr := afterStart(); scopeErr != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			err = fmt.Errorf("configure sensor process scope: %w", scopeErr)
		} else {
			err = cmd.Wait()
		}
	}
	raw := stdout.String()
	res.Raw = &raw
	res.Lines = splitSensorLines(stdout.Bytes())
	res.Stderr = stderr.String()
	res.Truncated = stdout.truncated || stderr.truncated
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		res.TimedOut = true
		res.Error = "collection timed out"
	} else if err != nil {
		res.Error = err.Error()
		res.ExitCode = -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
		}
	}
	if res.Truncated {
		res.Error = "collection output exceeded limit"
	}
	return res
}
