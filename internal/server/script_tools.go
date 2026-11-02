package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

const maxSensorScriptBytes = 256 << 10

var scriptToolsHTTP = &http.Client{
	Timeout:       55 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
}
var errScriptToolsUnavailable = errors.New("script validation is unavailable; try again shortly (your edits have not been saved)")

func (s *Server) callScriptTools(ctx context.Context, path string, body, result any) error {
	base := s.cfg.ScriptToolsURL
	if base == "" {
		base = "http://127.0.0.1:8091"
	}
	endpoint, err := url.Parse(base)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errScriptToolsUnavailable
	}
	endpoint = endpoint.JoinPath(path)
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// Construct a new request: console cookies and bearer tokens never reach tools.
	resp, err := scriptToolsHTTP.Do(req)
	if err != nil {
		return errScriptToolsUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errScriptToolsUnavailable
	}
	limit := 4 << 20
	if path == "build" {
		limit = 24 << 20
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil || len(raw) > limit || json.Unmarshal(raw, result) != nil {
		return errScriptToolsUnavailable
	}
	return nil
}

func normalizeSensorScripts(commands map[string]string) (map[string]string, error) {
	normalized := make(map[string]string)
	for platform, script := range commands {
		platform = strings.ToLower(strings.TrimSpace(platform))
		if platform != "linux" && platform != "darwin" && platform != "windows" {
			return nil, errors.New("unsupported script platform")
		}
		if len(script) > maxSensorScriptBytes {
			return nil, errors.New("each script must be at most 256 KiB")
		}
		if _, exists := normalized[platform]; exists {
			return nil, errors.New("duplicate script platform")
		}
		normalized[platform] = script
	}
	return normalized, nil
}

func (s *Server) validateSensorScripts(ctx context.Context, commands map[string]string) (scriptValidation, error) {
	return s.validateSensorLanguages(ctx, commands, nil)
}

func (s *Server) validateSensorLanguages(ctx context.Context, commands map[string]string, platforms map[string]proto.SensorPlatform) (scriptValidation, error) {
	shellCommands := map[string]string{}
	languages := map[string]string{}
	for os, cmd := range commands {
		l := sensoroutput.Language(os, platforms[os].Language)
		languages[os] = l
		if l == "shell" {
			shellCommands[os] = cmd
		}
	}
	result := validateCustomSensorScripts(shellCommands)
	if len(result.Errors) != 0 {
		return result, nil
	}
	var response struct {
		Diagnostics map[string][]struct {
			scriptDiagnostic
			Blocking bool `json:"blocking"`
		} `json:"diagnostics"`
	}
	if err := s.callScriptTools(ctx, "validate", map[string]any{"commands": commands, "languages": languages}, &response); err != nil {
		return result, err
	}
	if response.Diagnostics == nil {
		return result, errScriptToolsUnavailable
	}
	result.Warnings = map[string][]scriptDiagnostic{}
	for platform := range commands {
		diagnostics, exists := response.Diagnostics[platform]
		if !exists {
			return result, errScriptToolsUnavailable
		}
		for _, diagnostic := range diagnostics {
			if diagnostic.Blocking {
				diagnostic.Severity = "error"
				result.Errors[platform] = append(result.Errors[platform], diagnostic.scriptDiagnostic)
			} else {
				if diagnostic.Severity != "info" {
					diagnostic.Severity = "warning"
				}
				result.Warnings[platform] = append(result.Warnings[platform], diagnostic.scriptDiagnostic)
			}
		}
	}
	return result, nil
}

// completeCustomSensorScriptRequest is the body of POST /api/sensors/custom/complete.
type completeCustomSensorScriptRequest struct {
	Platform string         `json:"platform" api:"required"`
	Language string         `json:"language"`
	Script   string         `json:"script"`
	Session  string         `json:"session" api:"required"`
	Position scriptPosition `json:"position"`
}

// scriptPosition is where in the script to complete, counted from 0 the
// way a language server counts.
type scriptPosition struct {
	// Line is the cursor's line, from 0.
	Line int `json:"line"`
	// Character is the cursor's place within the line, from 0.
	Character int `json:"character"`
}

// completeCustomSensorScriptResponse is what POST
// /api/sensors/custom/complete answers.
type completeCustomSensorScriptResponse struct {
	Items []any `json:"items"`
}

func (s *Server) handleCompleteCustomSensorScript(w http.ResponseWriter, r *http.Request) {
	var body completeCustomSensorScriptRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
		http.Error(w, "invalid JSON body", 400)
		return
	}
	body.Platform = strings.ToLower(strings.TrimSpace(body.Platform))
	if _, err := normalizeSensorScripts(map[string]string{body.Platform: body.Script}); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if len(body.Session) < 1 || len(body.Session) > 80 || strings.IndexFunc(body.Session, func(c rune) bool {
		return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')
	}) >= 0 || body.Position.Line < 0 || body.Position.Character < 0 {
		http.Error(w, "invalid completion request", 400)
		return
	}
	if language := sensoroutput.Language(body.Platform, body.Language); language != "shell" && language != "powershell" {
		writeJSONResponse(w, completeCustomSensorScriptResponse{Items: []any{}})
		return
	}
	// Session identifiers are scoped by the authenticated user, never by the client.
	body.Session = auth.CurrentUser(r.Context()).ID + ":" + body.Session
	var result json.RawMessage
	if err := s.callScriptTools(r.Context(), "complete", body, &result); err != nil {
		http.Error(w, "script completion is unavailable; try again shortly", 503)
		return
	}
	writeJSONResponse(w, result)
}
