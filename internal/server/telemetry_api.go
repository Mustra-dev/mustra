package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// telemetryResponse is what GET and PUT /api/telemetry answer.
type telemetryResponse struct {
	Settings telemetrySettings `json:"settings"`
	// Collectors are the metric families an agent can collect.
	Collectors []string `json:"collectors"`
	// Endpoints are the endpoints whose metrics arrived lately.
	Endpoints []telemetryStatusRow `json:"endpoints"`
	Stats     telemetryStats       `json:"stats"`
	// ScrapePath is where Prometheus scrapes endpoint metrics when Scrape
	// is on, with the Prometheus integration's token.
	ScrapePath string `json:"scrape_path"`
}

func (s *Server) telemetryResponse(ctx context.Context) telemetryResponse {
	rows, stats := s.telemetryStatus(ctx)
	if rows == nil {
		rows = []telemetryStatusRow{}
	}
	t := s.telemetrySettings(ctx)
	if t.Metrics.Collectors == nil {
		t.Metrics.Collectors = []string{}
	}
	if t.Metrics.GroupIDs == nil {
		t.Metrics.GroupIDs = []string{}
	}
	if t.Labels.Extra == nil {
		t.Labels.Extra = map[string]string{}
	}
	if t.Labels.Groups == nil {
		t.Labels.Groups = []telemetryGroupLabels{}
	}
	return telemetryResponse{Settings: t, Collectors: telemetryCollectorNames, Endpoints: rows, Stats: stats, ScrapePath: "/metrics/endpoints"}
}

// GET /api/telemetry
func (s *Server) handleGetTelemetry(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, s.telemetryResponse(r.Context()))
}

// PUT /api/telemetry
func (s *Server) handlePutTelemetry(w http.ResponseWriter, r *http.Request) {
	var t telemetrySettings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&t); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if t.Metrics.IntervalSeconds == 0 {
		t.Metrics.IntervalSeconds = 15
	}
	if t.Metrics.IntervalSeconds < 5 || t.Metrics.IntervalSeconds > 3600 {
		http.Error(w, "interval_seconds must be 5-3600", http.StatusBadRequest)
		return
	}
	known := map[string]bool{}
	for _, c := range telemetryCollectorNames {
		known[c] = true
	}
	for _, c := range t.Metrics.Collectors {
		if !known[c] {
			http.Error(w, "unknown collector: "+c, http.StatusBadRequest)
			return
		}
	}
	t.RemoteWrite.URL = strings.TrimSpace(t.RemoteWrite.URL)
	if t.RemoteWrite.URL != "" {
		u, err := url.Parse(t.RemoteWrite.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			http.Error(w, "remote_write url must be an http(s) URL, e.g. http://prometheus:9090/api/v1/write", http.StatusBadRequest)
			return
		}
	}
	if t.RemoteWrite.Enabled && t.RemoteWrite.URL == "" {
		http.Error(w, "give remote_write a URL, or turn it off", http.StatusBadRequest)
		return
	}
	if t.RemoteWrite.Enabled {
		if err := checkWebhookURL(t.RemoteWrite.URL, s.webhookAllowedHosts(r.Context())); err != nil {
			http.Error(w, "remote_write: "+err.Error()+"; see Administration → Network Allowlists", http.StatusBadRequest)
			return
		}
	}
	t.Labels.Job = strings.TrimSpace(t.Labels.Job)
	if t.Labels.Job == "" {
		t.Labels.Job = "mustra"
	}
	for k := range t.Labels.Extra {
		if !validLabelName(k) || k == "job" || k == "instance" || k == "instance_name" {
			http.Error(w, "invalid extra label name: "+k, http.StatusBadRequest)
			return
		}
	}
	groups := t.Labels.Groups[:0]
	for _, g := range t.Labels.Groups {
		if g.GroupID == "" {
			http.Error(w, "each group's labels need a group_id", http.StatusBadRequest)
			return
		}
		for k := range g.Labels {
			if !validLabelName(k) || k == "job" || k == "instance" || k == "instance_name" {
				http.Error(w, "invalid group label name: "+k, http.StatusBadRequest)
				return
			}
		}
		if len(g.Labels) > 0 {
			groups = append(groups, g)
		}
	}
	t.Labels.Groups = groups
	ctx := r.Context()
	u := auth.CurrentUser(ctx)
	switch {
	case t.RemoteWrite.ClearSecret:
		if err := s.store.SetSetting(ctx, settingTelemetryRemoteWriteSecret, "", u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case t.RemoteWrite.Secret != "":
		sealed, err := s.sealSetting(settingTelemetryRemoteWriteSecret, t.RemoteWrite.Secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.store.SetSetting(ctx, settingTelemetryRemoteWriteSecret, sealed, u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	t.RemoteWrite.Secret, t.RemoteWrite.ClearSecret, t.RemoteWrite.SecretSet = "", false, false
	raw, _ := json.Marshal(t)
	if err := s.store.SetSetting(ctx, settingTelemetry, string(raw), u.Username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "telemetry.settings", Actor: u.Username, Target: "telemetry", Severity: "notice",
		Detail: map[string]any{"metrics": t.Metrics.Enabled, "interval_seconds": t.Metrics.IntervalSeconds,
			"remote_write": t.RemoteWrite.Enabled, "remote_write_url": t.RemoteWrite.URL, "scrape": t.Scrape.Enabled,
			"groups": len(t.Metrics.GroupIDs), "collectors": t.Metrics.Collectors,
			"job": t.Labels.Job, "extra_labels": t.Labels.Extra, "group_labels": t.Labels.Groups}})
	writeJSONResponse(w, s.telemetryResponse(ctx))
}

// telemetryTestResponse is what POST /api/telemetry/test answers.
type telemetryTestResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// POST /api/telemetry/test sends one series, mustra_telemetry_test, to the
// configured remote_write endpoint, so a URL or credential mistake shows
// at once rather than as a growing error count.
func (s *Server) handleTestTelemetry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := s.telemetrySettings(ctx)
	if t.RemoteWrite.URL == "" {
		http.Error(w, "no remote_write URL is configured", http.StatusBadRequest)
		return
	}
	secret := ""
	if stored, _ := s.store.GetSetting(ctx, settingTelemetryRemoteWriteSecret); stored != "" {
		secret, _ = s.openSetting(settingTelemetryRemoteWriteSecret, stored)
	}
	series := []telemetrySeries{{Name: "mustra_telemetry_test", Type: "gauge",
		Labels: [][2]string{{"job", t.Labels.Job}}, Value: 1, TimeMs: time.Now().UnixMilli()}}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.remoteWrite(cctx, t.RemoteWrite.URL, t.RemoteWrite.Username, secret, series); err != nil {
		writeJSONResponse(w, telemetryTestResponse{OK: false, Message: err.Error()})
		return
	}
	writeJSONResponse(w, telemetryTestResponse{OK: true, Message: "accepted: query mustra_telemetry_test in Prometheus"})
}
