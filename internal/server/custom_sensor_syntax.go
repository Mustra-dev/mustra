package server

import (
	"encoding/json"
	"fmt"
	"github.com/mustra-dev/mustra/internal/proto"
	"net/http"
	"strings"
	"unicode/utf16"

	"mvdan.cc/sh/v3/syntax"
)

type scriptDiagnostic struct {
	From     int    `json:"from"`
	To       int    `json:"to"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type scriptValidation struct {
	Errors   map[string][]scriptDiagnostic `json:"errors"`
	Warnings map[string][]scriptDiagnostic `json:"warnings,omitempty"`
}

func validateCustomSensorScripts(commands map[string]string) scriptValidation {
	result := scriptValidation{Errors: map[string][]scriptDiagnostic{}}
	for platform, script := range commands {
		platform = strings.ToLower(strings.TrimSpace(platform))
		if strings.TrimSpace(script) == "" || (platform != "linux" && platform != "darwin") {
			continue
		}
		// Parse only: validation must never execute operator code on the server.
		_, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(script), "")
		if err == nil {
			continue
		}
		var pos syntax.Pos
		switch e := err.(type) {
		case syntax.ParseError:
			pos = e.Pos
		case syntax.LangError:
			pos = e.Pos
		}
		offset := min(int(pos.Offset()), len(script))
		// Parser offsets are bytes; CodeMirror positions are UTF-16 code units.
		from := len(utf16.Encode([]rune(script[:offset])))
		length := len(utf16.Encode([]rune(script)))
		label := "Linux"
		if platform == "darwin" {
			label = "macOS"
		}
		result.Errors[platform] = []scriptDiagnostic{{From: from, To: min(from+1, length), Severity: "error", Message: fmt.Sprintf("%s requires /bin/sh syntax; PowerShell scripts belong in Windows. %s", label, err)}}
	}
	return result
}

// validateCustomSensorScriptsRequest is the body of POST /api/sensors/custom/validate.
type validateCustomSensorScriptsRequest struct {
	Commands  map[string]string               `json:"commands"`
	Platforms map[string]proto.SensorPlatform `json:"platforms"`
}

func (s *Server) handleValidateCustomSensorScripts(w http.ResponseWriter, r *http.Request) {
	var body validateCustomSensorScriptsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid or oversized JSON body", http.StatusBadRequest)
		return
	}
	commands, err := normalizeSensorScripts(body.Commands)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.validateSensorLanguages(r.Context(), commands, body.Platforms)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSONResponse(w, result)
}
