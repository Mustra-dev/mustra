package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// auditEventsResponse is what GET /api/audit answers.
type auditEventsResponse struct {
	ActionCounts map[string]int        `json:"action_counts"`
	Events       []store.AuditEvent    `json:"events"`
	Forwarding   auditEventsForwarding `json:"forwarding"`
	LogLevel     string                `json:"log_level"`
}

// auditEventsForwarding is where audit events are forwarded, if anywhere.
type auditEventsForwarding struct {
	Enabled bool   `json:"enabled"`
	Format  string `json:"format"`
	Target  string `json:"target"`
}

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	limit := 300
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	events, err := s.store.ListAuditEvents(r.Context(),
		r.URL.Query().Get("action"), r.URL.Query().Get("actor"),
		r.URL.Query().Get("since"), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []store.AuditEvent{}
	}
	counts, _ := s.store.AuditActionCounts(r.Context(), 7)

	fwd := s.syslog.settings()
	writeJSONResponse(w, auditEventsResponse{
		Events: events, ActionCounts: counts,
		LogLevel: levelName(levelVar.Level()),
		Forwarding: auditEventsForwarding{
			Enabled: fwd.Enabled, Target: fwd.Target, Format: fwd.Format,
		},
	})
}

// loggingSettings is what GET and POST /api/admin/logging answer: the
// level and forwarding the server is running now.
type loggingSettings struct {
	LogLevel string `json:"log_level"`
	Enabled  bool   `json:"forward_enabled"`
	// Target as it was saved, scheme included.
	Target string `json:"forward_target"`
	Format string `json:"forward_format"`
}

// updateLoggingRequest is the body of POST /api/admin/logging. Every
// field is optional: one that is omitted (or null) is left as it is, so a
// request that only sets the level does not touch forwarding.
type updateLoggingRequest struct {
	// LogLevel is debug, info, warn or error. Empty leaves it unchanged.
	LogLevel *string `json:"log_level"`
	// Enabled turns forwarding of audit events on or off.
	Enabled *bool `json:"forward_enabled"`
	// Target is the collector, as host:port (UDP), udp://host:port or
	// tcp://host:port. With forwarding on, a new target is dialled before
	// anything is saved: one that cannot be reached is refused with 400
	// and changes nothing.
	Target *string `json:"forward_target"`
	// Format is rfc5424, cef or json. Empty means rfc5424.
	Format *string `json:"forward_format"`
}

func (s *Server) handleGetLogging(w http.ResponseWriter, r *http.Request) {
	fwd := s.syslog.settings()
	writeJSONResponse(w, loggingSettings{
		LogLevel: levelName(levelVar.Level()),
		Enabled:  fwd.Enabled, Target: fwd.Target, Format: fwd.Format,
	})
}

// handleUpdateLogging changes the log level and SIEM forwarding at
// runtime. The level takes effect immediately across every goroutine —
// slog reads the LevelVar on each call — which is the point: turning on
// debug to diagnose something live should not require a restart that
// destroys the state you were trying to observe.
//
// The whole request is checked, a new target dialled included, before
// any of it is applied, so a request refused with 400 has changed
// nothing: not the level, not the stored settings, not the forwarding
// already running.
func (s *Server) handleUpdateLogging(w http.ResponseWriter, r *http.Request) {
	var body updateLoggingRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	who := auth.CurrentUser(r.Context()).Username

	level := ""
	if body.LogLevel != nil {
		level = *body.LogLevel
	}
	want := parseLevel(level)
	if level != "" && levelName(want) != strings.ToLower(level) &&
		!(strings.ToLower(level) == "warning" && want == slog.LevelWarn) {
		http.Error(w, "level must be debug, info, warn or error", http.StatusBadRequest)
		return
	}

	forwarding := body.Enabled != nil || body.Target != nil || body.Format != nil
	var change syslogChange
	if forwarding {
		// Held to the end, so concurrent forwarding saves apply and
		// persist in the same order, and each builds on the settings the
		// one before it left. A level-only save does not take it: it has
		// nothing to merge, and should not wait behind another save's dial.
		s.syslog.edit.Lock()
		defer s.syslog.edit.Unlock()

		cfg := s.syslog.settings()
		if body.Enabled != nil {
			cfg.Enabled = *body.Enabled
		}
		if body.Target != nil {
			cfg.Target = *body.Target
		}
		if body.Format != nil {
			cfg.Format = *body.Format
		}
		var err error
		if change, err = s.syslog.prepare(cfg); err != nil {
			// Reported rather than stored: a forwarding target that cannot
			// be reached is a configuration mistake worth seeing now, not
			// a setting that silently never delivers.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Everything is valid; nothing below refuses the request. The swap
	// comes first so nothing slow (the level's audit write) sits between
	// prepare finding the current connection up and apply relying on it.
	if forwarding {
		s.syslog.apply(change)
	}
	if level != "" {
		previous := levelName(levelVar.Level())
		levelVar.Set(want)
		if err := s.store.SetSetting(r.Context(), "log_level", level, who); err != nil {
			s.logger.Warn("persisting log level failed", "error", err)
		}
		s.audit(r.Context(), auditEvent{
			Action: "logging.level", Actor: who, Target: level,
			Detail: map[string]any{"from": previous, "to": levelName(want)},
		})
	}
	if forwarding {
		cfg := change.cfg
		for k, v := range map[string]string{
			"log_forward_enabled": strconv.FormatBool(cfg.Enabled),
			"log_forward_target":  cfg.Target,
			"log_forward_format":  cfg.Format,
		} {
			if err := s.store.SetSetting(r.Context(), k, v, who); err != nil {
				s.logger.Warn("persisting logging setting failed", "key", k, "error", err)
			}
		}
		s.audit(r.Context(), auditEvent{
			Action: "logging.forwarding", Actor: who, Target: cfg.Target,
			Detail: map[string]any{"enabled": cfg.Enabled, "format": cfg.Format},
		})
	}

	s.handleGetLogging(w, r)
}

// loadLoggingSettings restores the persisted level and forwarding on
// start, so a restart doesn't quietly revert to defaults and stop
// delivering to a SIEM that is still expecting events.
func (s *Server) loadLoggingSettings(ctx context.Context) {
	if v, err := s.store.GetSetting(ctx, "log_level"); err == nil && v != "" {
		levelVar.Set(parseLevel(v))
	}
	enabled, _ := s.store.GetSetting(ctx, "log_forward_enabled")
	target, _ := s.store.GetSetting(ctx, "log_forward_target")
	format, _ := s.store.GetSetting(ctx, "log_forward_format")
	if !slices.Contains(syslogFormats, format) {
		// Saved before formats were checked; forwarding always sent
		// anything unrecognised as RFC 5424.
		format = "rfc5424"
	}
	cfg := syslogConfig{Enabled: enabled == "true" && target != "", Target: target, Format: format}

	s.syslog.edit.Lock()
	defer s.syslog.edit.Unlock()
	change, err := s.syslog.prepare(cfg)
	if err != nil {
		// Shown as off with the stored target, so the console says what
		// it was meant to reach; saving it again retries.
		s.logger.Warn("restoring log forwarding failed", "target", target, "error", err)
		cfg.Enabled = false
		change, _ = s.syslog.prepare(cfg)
	} else if cfg.Enabled {
		s.logger.Info("log forwarding restored", "target", target, "format", format)
	}
	s.syslog.apply(change)
}
