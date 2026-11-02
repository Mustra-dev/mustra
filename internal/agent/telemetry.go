package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// The agent's side of telemetry export: it asks the server what to
// collect (at start and every telemetryConfigEvery), and while metrics are
// on, collects host metrics every interval and publishes them on its
// telemetry subject. A plain publish, not the durable outbox: a batch that
// cannot be delivered is replaced by the next one, so there is nothing to
// keep.

const (
	telemetryConfigEvery   = 5 * time.Minute
	metricsIntervalDefault = 15 * time.Second
	metricsIntervalMin     = 5 * time.Second
	metricsIntervalMax     = time.Hour
)

func (a *Agent) telemetryLoop(ctx context.Context) {
	var (
		current proto.TelemetryConfig
		stop    context.CancelFunc
	)
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	apply := func(c proto.TelemetryConfig) {
		if c.Revision == current.Revision && (stop != nil) == c.Metrics.Enabled {
			return
		}
		if stop != nil {
			stop()
			stop = nil
		}
		current = c
		if c.Metrics.Enabled {
			mctx, cancel := context.WithCancel(ctx)
			stop = cancel
			go a.metricsLoop(mctx, c.Metrics)
			a.logger.Info("host metrics on", "interval", metricsInterval(c.Metrics), "collectors", c.Metrics.Collectors)
		} else {
			a.logger.Info("host metrics off")
		}
	}
	// A moment after start, so registration has settled.
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	tick := time.NewTicker(telemetryConfigEvery)
	defer tick.Stop()
	for {
		reply := a.askServer(ctx, proto.SelfServiceRequest{Action: "telemetry_config"})
		// A server that cannot be reached keeps the current settings; one
		// that answers without a config (older, or telemetry off for this
		// endpoint) turns it off.
		if reply.OK || reply.Telemetry != nil {
			cfg := proto.TelemetryConfig{}
			if reply.Telemetry != nil {
				cfg = *reply.Telemetry
			}
			apply(cfg)
		} else if reply.Error != "" && !isUnreachable(reply.Error) {
			apply(proto.TelemetryConfig{})
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// isUnreachable tells "the server did not answer" from "the server said
// no", using askServer's own wording for the first.
func isUnreachable(err string) bool {
	return strings.HasPrefix(err, "the mustra server didn't answer") || err == "not connected to the mustra server yet"
}

func metricsInterval(c proto.MetricsConfig) time.Duration {
	d := time.Duration(c.IntervalSeconds) * time.Second
	switch {
	case d <= 0:
		return metricsIntervalDefault
	case d < metricsIntervalMin:
		return metricsIntervalMin
	case d > metricsIntervalMax:
		return metricsIntervalMax
	}
	return d
}

func (a *Agent) metricsLoop(ctx context.Context, c proto.MetricsConfig) {
	interval := metricsInterval(c)
	on := enabledCollectors(c.Collectors)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		cctx, cancel := context.WithTimeout(ctx, min(interval, 10*time.Second))
		set := collectHostMetrics(cctx, on)
		cancel()
		batch := proto.MetricsBatch{AgentID: a.agentID, Timestamp: time.Now().UTC(), Families: set.families()}
		if payload, err := json.Marshal(batch); err == nil && a.nc != nil {
			if err := a.nc.Publish(bnats.TelemetryMetrics(a.agentID), payload); err != nil {
				a.logger.Debug("publish metrics failed", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
