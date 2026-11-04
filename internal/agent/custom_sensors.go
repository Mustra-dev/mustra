package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// Custom sensors: collection an operator wrote, rather than one mustra
// shipped.
//
// The definitions are pulled from the server rather than configured on the
// endpoint, so adding a sensor is a change in one place instead of a fleet
// rollout — the same reason compliance benchmarks are sent with the command
// rather than installed alongside the agent.
//
// One goroutine drives all of them. The obvious alternative — a goroutine
// per sensor, started and stopped as definitions change — means reconciling
// a set of live timers against a set of definitions on every refresh, and
// getting that wrong leaks goroutines that keep running a sensor somebody
// deleted. A single loop that checks "is this one due yet" has no such state
// to get wrong.

const (
	// customSensorRefresh is how often the agent re-asks which sensors apply
	// to it. Editing a sensor takes effect within this, without a restart.
	customSensorRefresh = 5 * time.Minute
	// customSensorTick is how often the loop checks whether anything is due.
	// It bounds how far past its interval a sensor can drift.
	customSensorTick = 30 * time.Second
	// maxCustomSensorLines caps what one collection may report. A command
	// that accidentally cats a logfile should produce a truncated sensor,
	// not a message large enough to hurt the bus.
	maxCustomSensorLines = 500
	maxCustomSensorLine  = 4000
)

func (a *Agent) runCustomSensorLoop(ctx context.Context) {
	if a.noRemoteCode {
		return
	}
	defs := a.fetchCustomSensors(ctx)
	lastRun := map[string]time.Time{}
	lastRefresh := time.Now()

	ticker := time.NewTicker(customSensorTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if time.Since(lastRefresh) >= customSensorRefresh {
			if fresh := a.fetchCustomSensors(ctx); fresh != nil {
				defs = fresh
			}
			lastRefresh = time.Now()
			// Forget timers for sensors that no longer apply, so a deleted
			// sensor's entry doesn't sit here for the life of the process.
			live := map[string]bool{}
			for _, d := range defs {
				live[d.Sensor] = true
			}
			for k := range lastRun {
				if !live[k] {
					delete(lastRun, k)
				}
			}
		}

		for _, def := range defs {
			every := time.Duration(def.IntervalSeconds) * time.Second
			if every <= 0 {
				every = 15 * time.Minute
			}
			if every > maxSensorIntervalSeconds*time.Second {
				every = maxSensorIntervalSeconds * time.Second
			}
			if last, ok := lastRun[def.Sensor]; ok && time.Since(last) < every {
				continue
			}
			lastRun[def.Sensor] = time.Now()
			a.collectCustomSensor(ctx, def)
		}
	}
}

func (a *Agent) fetchCustomSensors(ctx context.Context) []proto.CustomSensorDef {
	if a.nc == nil || a.agentID == "" {
		return nil
	}
	payload, err := json.Marshal(proto.CustomSensorRequest{Version: 3})
	if err != nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	msg, err := a.nc.RequestWithContext(rctx, bnats.CustomSensors(a.agentID), payload)
	if err != nil {
		// The server being briefly unreachable is not worth an error log on
		// every refresh; the previous definitions keep running.
		a.logger.Debug("custom sensor definitions unavailable", "error", err)
		return nil
	}
	var reply proto.CustomSensorReply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		a.logger.Warn("malformed custom sensor definitions", "error", err)
		return nil
	}
	if reply.Error != "" {
		return nil
	}
	if reply.Sensors == nil {
		return []proto.CustomSensorDef{}
	}
	return reply.Sensors
}

// collectCustomSensor runs one operator-authored command and publishes what
// it said. Failure is reported as data rather than swallowed: "this command
// exits 127 on every Mac" is exactly what the author needs to see, and it is
// invisible if a failed collection simply publishes nothing.
func (a *Agent) collectCustomSensor(ctx context.Context, def proto.CustomSensorDef) {
	res := executeCustomSensor(ctx, def)

	raw, merr := json.Marshal(res)
	if merr != nil {
		a.logger.Error("marshal custom sensor result failed", "sensor", def.Name, "error", merr)
		return
	}
	snap := proto.SensorSnapshot{
		AgentID: a.agentID, Sensor: proto.SensorKind(def.Sensor),
		Timestamp: time.Now().UTC(), Data: raw,
	}
	payload, merr := json.Marshal(snap)
	if merr != nil {
		return
	}
	if perr := a.pub.PublishLatest(ctx, bnats.AgentSensor(a.agentID, def.Sensor), payload); perr != nil {
		a.logger.Error("publish custom sensor failed", "sensor", def.Name, "error", perr)
	}
}

// splitSensorLines turns command output into bounded lines. Lines are the
// right shape because that is what an operator's command actually emits;
// forcing JSON would tax the simple case -- "run this and tell me what it
// said" -- which is most of them.
func splitSensorLines(out []byte) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), maxCustomSensorLine)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if len(line) > maxCustomSensorLine {
			line = line[:maxCustomSensorLine] + "… (truncated)"
		}
		lines = append(lines, line)
		if len(lines) >= maxCustomSensorLines {
			lines = append(lines, "… (output truncated)")
			break
		}
	}
	return lines
}
