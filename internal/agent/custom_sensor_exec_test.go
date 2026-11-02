package agent

import (
	"context"
	"encoding/json"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCustomExecutionSeparateOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	r := executeCustomSensor(context.Background(), proto.CustomSensorDef{Command: "printf 'value\\n'; printf 'diagnostic\\n' >&2", TimeoutSeconds: 2})
	if r.Error != "" || r.Raw == nil || *r.Raw != "value\n" || r.Stderr != "diagnostic\n" {
		t.Fatalf("%#v", r)
	}
}
func TestCustomExecutionBoundsAndTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	r := executeCustomSensor(context.Background(), proto.CustomSensorDef{Command: "yes value | head -c 100000", TimeoutSeconds: 2})
	if !r.Truncated || len(*r.Raw) != sensoroutput.MaxBytes {
		t.Fatalf("not bounded: %#v", r.Error)
	}
	start := time.Now()
	r = executeCustomSensor(context.Background(), proto.CustomSensorDef{Command: "sleep 30 & wait", TimeoutSeconds: 1})
	if !r.TimedOut || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout did not bound descendants: %#v", r)
	}
}
func TestSensorPayloadFitsBroker(t *testing.T) {
	r := proto.CustomSensorResult{Lines: []string{strings.Repeat("\x00", sensoroutput.MaxBytes)}, Stderr: strings.Repeat("\x00", 16<<10)}
	raw := strings.Repeat("\x00", sensoroutput.MaxBytes)
	r.Raw = &raw
	b, _ := json.Marshal(r)
	snap, _ := json.Marshal(proto.SensorSnapshot{Data: b})
	if len(snap) >= 1<<20 {
		t.Fatalf("payload too large: %d", len(snap))
	}
}

func TestBundledPythonExecution(t *testing.T) {
	if _, err := privatePython(); err != nil {
		t.Skip("run test binary beside packaged python/ to check bundled execution")
	}
	t.Setenv("PYTHONPATH", "/a/path/that/must/not/be/imported")
	r := executeCustomSensor(context.Background(), proto.CustomSensorDef{Command: `import json,sys,ssl,sqlite3
assert sys.flags.isolated and sys.flags.no_site
assert '/a/path/that/must/not/be/imported' not in sys.path
print(json.dumps([{'value':'python-ok'}]))`, Platform: proto.SensorPlatform{Language: "python"}, TimeoutSeconds: 10})
	if r.Error != "" || r.Raw == nil || !strings.Contains(*r.Raw, "python-ok") {
		t.Fatalf("%#v", r)
	}
}

func TestWindowsCustomExecution(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("requires a Windows endpoint")
	}
	for _, tc := range []struct {
		language, script string
		code             int
	}{
		{"powershell", `param([string]$Value='parameter-ok'); Write-Output $Value`, 0},
		{"powershell", `Write-Output 'parameter-ok'; exit 7`, 7},
		// A check script's "error" exit must not read as "false" (1).
		{"powershell", `Write-Output 'parameter-ok'; exit 2`, 2},
		{"batch", "echo parameter-ok\r\nexit /b 7", 7},
	} {
		r := executeCustomSensor(context.Background(), proto.CustomSensorDef{Platform: proto.SensorPlatform{Language: tc.language}, Command: tc.script, TimeoutSeconds: 10})
		if r.Raw == nil || !strings.Contains(*r.Raw, "parameter-ok") || r.ExitCode != tc.code {
			t.Fatalf("%s: %#v", tc.language, r)
		}
	}
	r := executeCustomSensor(context.Background(), proto.CustomSensorDef{Platform: proto.SensorPlatform{Language: "wql", Namespace: `root\cimv2`}, Command: "SELECT Caption FROM Win32_OperatingSystem", TimeoutSeconds: 30})
	if r.Error != "" || r.Raw == nil {
		t.Fatalf("WQL: %#v", r)
	}
	rows, err := sensoroutput.Parse(*r.Raw, proto.SensorOutput{Format: "json"}, []proto.SensorField{{Name: "Caption", Type: "string"}})
	if err != nil || len(rows) != 1 || rows[0]["Caption"] == nil {
		t.Fatalf("WQL output: %v %v", rows, err)
	}
}
