package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Client configuration profiles, endpoint half.
//
// The server decides which profile covers this endpoint and pushes its
// settings with a "configure" command; the agent applies what is set,
// keeps it across restarts, and reports what it is running with in every
// facts message so the server can see drift rather than assume compliance.
// A setting the profile leaves at zero is left alone here, which is what
// lets a profile change one thing without resetting the rest.

type agentSettings struct {
	mu       sync.Mutex
	current  proto.AgentSettings
	interval time.Duration // effective sensor interval
}

// loadSettings applies what a previous run persisted, before the sensor
// loops start, so a restart does not fall back to the flags for a minute.
func (a *Agent) loadSettings() {
	a.settings.mu.Lock()
	defer a.settings.mu.Unlock()
	a.settings.interval = a.cfg.SensorInterval
	raw, err := a.store.LoadSettings()
	if err != nil || len(raw) == 0 {
		return
	}
	var s proto.AgentSettings
	if json.Unmarshal(raw, &s) != nil {
		return
	}
	a.settings.current = s
	if s.SensorIntervalSeconds >= 5 && s.SensorIntervalSeconds <= maxSensorIntervalSeconds {
		a.settings.interval = time.Duration(s.SensorIntervalSeconds) * time.Second
		a.cfg.SensorInterval = a.settings.interval
	}
	if lvl, ok := parseLogLevel(s.LogLevel); ok && a.cfg.LogLevel != nil {
		a.cfg.LogLevel.Set(lvl)
	}
	a.logger.Info("client profile settings restored", "profile", s.Profile, "sensor_interval", a.settings.interval, "log_level", s.LogLevel, "random_delay_seconds", s.RandomDelaySeconds)
}

// maxSensorIntervalSeconds is the longest a sensor may go between reports:
// a day. A larger value (the server bounds it too) silences an endpoint's
// telemetry for all practical purposes, which is a way to hide it.
const maxSensorIntervalSeconds = 24 * 60 * 60

// applySettings is the "configure" command. It changes only what the
// profile sets, persists the merged result, and republishes facts.
func (a *Agent) applySettings(ctx context.Context, in proto.AgentSettings, chans map[proto.SensorKind]chan time.Duration) error {
	a.settings.mu.Lock()
	cur := a.settings.current
	if in.SensorIntervalSeconds != 0 {
		if in.SensorIntervalSeconds < 5 || in.SensorIntervalSeconds > maxSensorIntervalSeconds {
			a.settings.mu.Unlock()
			return errBadInterval
		}
		cur.SensorIntervalSeconds = in.SensorIntervalSeconds
		a.settings.interval = time.Duration(in.SensorIntervalSeconds) * time.Second
	}
	if in.LogLevel != "" {
		lvl, ok := parseLogLevel(in.LogLevel)
		if !ok {
			a.settings.mu.Unlock()
			return errBadLogLevel
		}
		cur.LogLevel = strings.ToLower(in.LogLevel)
		if a.cfg.LogLevel != nil {
			a.cfg.LogLevel.Set(lvl)
		}
	}
	if in.RandomDelaySeconds >= 0 {
		cur.RandomDelaySeconds = in.RandomDelaySeconds
	}
	cur.Profile = in.Profile
	a.settings.current = cur
	interval := a.settings.interval
	a.settings.mu.Unlock()

	if in.SensorIntervalSeconds != 0 {
		// Every periodic sensor except performance, which has its own
		// cadence and is not what "sensor interval" has ever meant.
		for kind, ch := range chans {
			if kind == proto.SensorPerformance {
				continue
			}
			select {
			case ch <- interval:
			case <-time.After(2 * time.Second):
				a.logger.Warn("sensor loop busy; interval not applied", "sensor", kind)
			}
		}
	}
	if raw, err := json.Marshal(cur); err == nil {
		if err := a.store.SaveSettings(raw); err != nil {
			a.logger.Warn("persist settings failed", "error", err)
		}
	}
	a.logger.Info("client profile applied", "profile", cur.Profile, "sensor_interval", interval, "log_level", cur.LogLevel, "random_delay_seconds", cur.RandomDelaySeconds)
	go a.sendFacts(context.WithoutCancel(ctx))
	return nil
}

// currentSettings is what facts report: the effective values, whether
// they came from a profile or from the flags the agent started with.
func (a *Agent) currentSettings() *proto.AgentSettings {
	a.settings.mu.Lock()
	defer a.settings.mu.Unlock()
	out := a.settings.current
	out.SensorIntervalSeconds = int(a.settings.interval / time.Second)
	if out.LogLevel == "" && a.cfg.LogLevel != nil {
		out.LogLevel = strings.ToLower(a.cfg.LogLevel.Level().String())
	}
	return &out
}

// randomDelay is the wait before a sensor publish, zero when no profile
// asked for one.
func (a *Agent) randomDelay() time.Duration {
	a.settings.mu.Lock()
	d := a.settings.current.RandomDelaySeconds
	a.settings.mu.Unlock()
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.IntN(d*1000)) * time.Millisecond
}

func parseLogLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return 0, false
}

type settingsError string

func (e settingsError) Error() string { return string(e) }

const (
	errBadInterval settingsError = "sensor_interval_seconds must be between 5 and 86400"
	errBadLogLevel settingsError = "log_level must be debug, info, warn or error"
)
