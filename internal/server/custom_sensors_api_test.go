package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const profileCleanupPreamble = `#Requires -Version 5.1

<#
.SYNOPSIS
    Removes inactive and corrupt user profiles from Windows systems.
#>

[CmdletBinding()]
param(
    [int]$DaysThreshold = 30,
    [switch]$DryRun
)
`

func TestCustomSensorRejectsPowerShellOnUnix(t *testing.T) {
	for _, os := range []string{"linux", "darwin"} {
		for _, method := range []string{"POST", "PUT"} {
			t.Run(os+"/"+method, func(t *testing.T) {
				body, err := json.Marshal(map[string]any{"id": "csn-test", "name": "Profile cleanup", "commands": map[string]string{os: profileCleanupPreamble}})
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(method, "/api/sensors/custom", bytes.NewReader(body))
				w := httptest.NewRecorder()
				// A rejected script must never reach persistence or dispatch.
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("PowerShell reached persistence instead of being rejected: %v", recovered)
					}
				}()
				(&Server{}).handleUpsertCustomSensor(w, r)
				if w.Code != 422 {
					t.Fatalf("got HTTP %d, want 422: %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestCustomSensorScriptValidation(t *testing.T) {
	cases := []struct {
		name, script string
		invalid      bool
	}{
		{"powershell preamble", profileCleanupPreamble, true},
		{"powershell parameters", "[CmdletBinding()]\nparam([int]$DaysThreshold = 30)", true},
		{"broken shell", "if true; then echo ok", true},
		{"bash array", "items=(one two)", true},
		{"posix sensor", "if [ -f /var/run/reboot-required ]; then echo pending; else echo none; fi", false},
		{"variables and functions", "report() { printf '%s\\n' \"$HOME\"; }\nreport", false},
		{"quoted powershell", "cat <<'EOF_PS'\n[CmdletBinding()]\nparam([int]$DaysThreshold = 30)\nEOF_PS\n", false},
		{"blank", " \n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, platform := range []string{"linux", "darwin", "windows"} {
				result := validateCustomSensorScripts(map[string]string{platform: tc.script})
				want := tc.invalid && platform != "windows"
				if got := len(result.Errors[platform]) > 0; got != want {
					t.Fatalf("%s: invalid=%v, want %v: %+v", platform, got, want, result)
				}
			}
		})
	}
}

func TestCustomSensorDiagnosticPositions(t *testing.T) {
	// Unicode before the error must not shift the editor underline.
	script := "# 😀 café\nitems=(one two)"
	result := validateCustomSensorScripts(map[string]string{" Darwin ": script})
	diagnostics := result.Errors["darwin"]
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics: %+v", result)
	}
	d := diagnostics[0]
	if d.From != 16 || d.To != 17 {
		t.Fatalf("invalid UTF-16 range: %+v", d)
	}
	if !strings.Contains(d.Message, "macOS requires /bin/sh") {
		t.Fatal(d.Message)
	}
}

func TestValidateCustomSensorScriptsHandler(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, map[string]any{"diagnostics": map[string]any{"windows": []any{}}})
	}))
	defer upstream.Close()
	s := &Server{cfg: Config{ScriptToolsURL: upstream.URL}}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"commands":{"linux":"if true; then"}}`, 200},
		{`{"commands":{"windows":"[CmdletBinding()]"}}`, 200},
		{`{`, 400},
		{`{"commands":{"linux":"` + strings.Repeat("x", 1<<20) + `"}}`, 400},
	} {
		w := httptest.NewRecorder()
		s.handleValidateCustomSensorScripts(w, httptest.NewRequest("POST", "/api/sensors/custom/validate", strings.NewReader(tc.body)))
		if w.Code != tc.status {
			t.Fatalf("got %d want %d", w.Code, tc.status)
		}
		if w.Code == 200 {
			var result scriptValidation
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(tc.body, "linux") && len(result.Errors["linux"]) == 0 {
				t.Fatal("missing Linux diagnostic")
			}
		}
	}
}
