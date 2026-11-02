package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScriptToolsValidationSeparatesSyntaxAndAdvice(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/validate" || r.Method != "POST" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("credentials forwarded to analysis service")
		}
		var body struct {
			Commands map[string]string `json:"commands"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Commands["windows"] != "param([int]$Days = )" {
			t.Error("source changed before analysis")
		}
		writeJSONResponse(w, map[string]any{"diagnostics": map[string]any{
			"windows": []map[string]any{{"from": 17, "to": 18, "severity": "error", "blocking": true, "message": "ExpectedValueExpression"}},
			"linux":   []map[string]any{{"from": 5, "to": 10, "severity": "error", "blocking": false, "message": "SC2086"}},
		}})
	}))
	defer upstream.Close()
	s := &Server{cfg: Config{ScriptToolsURL: upstream.URL}}
	result, err := s.validateSensorScripts(context.Background(), map[string]string{"windows": "param([int]$Days = )", "linux": "echo $HOME"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Errors["windows"]) != 1 || len(result.Errors["linux"]) != 0 {
		t.Fatalf("syntax errors: %+v", result)
	}
	if len(result.Warnings["linux"]) != 1 || result.Warnings["linux"][0].Severity != "warning" {
		t.Fatalf("advice: %+v", result)
	}
}

func TestCustomSensorSaveRequiresSuccessfulValidation(t *testing.T) {
	for _, tc := range []struct {
		name, upstreamBody   string
		upstreamStatus, want int
	}{
		{"syntax error", `{"diagnostics":{"windows":[{"from":0,"to":1,"blocking":true,"message":"ParseError"}]}}`, 200, 422},
		{"unavailable", `{}`, 503, 503},
		{"missing platform", `{"diagnostics":{}}`, 200, 503},
		{"malformed", `{`, 200, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.upstreamStatus)
				w.Write([]byte(tc.upstreamBody))
			}))
			defer upstream.Close()
			s := &Server{cfg: Config{ScriptToolsURL: upstream.URL}}
			for _, method := range []string{"POST", "PUT"} {
				r := httptest.NewRequest(method, "/api/sensors/custom", strings.NewReader(`{"name":"Profile cleanup","commands":{"windows":"param([int]$Days = )"}}`))
				if method == "PUT" {
					r.SetPathValue("id", "csn-test")
				}
				w := httptest.NewRecorder()
				// A nil store ensures neither invalid nor unchecked code reaches persistence.
				s.handleUpsertCustomSensor(w, r)
				if w.Code != tc.want {
					t.Fatalf("%s: got %d, want %d: %s", method, w.Code, tc.want, w.Body.String())
				}
			}
		})
	}
}

func TestNormalizeSensorScripts(t *testing.T) {
	if _, err := normalizeSensorScripts(map[string]string{"linux": "echo ok", " Linux ": "echo other"}); err == nil {
		t.Fatal("duplicate platform accepted")
	}
	if _, err := normalizeSensorScripts(map[string]string{"python": "pass"}); err == nil {
		t.Fatal("unknown platform accepted")
	}
	if _, err := normalizeSensorScripts(map[string]string{"windows": strings.Repeat("x", maxSensorScriptBytes+1)}); err == nil {
		t.Fatal("oversized script accepted")
	}
	got, err := normalizeSensorScripts(map[string]string{" Darwin ": "\n echo ok\n"})
	if err != nil || got["darwin"] != "\n echo ok\n" {
		t.Fatalf("normalization changed source offsets: %+v, %v", got, err)
	}
}
