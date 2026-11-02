package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// maxRedeliveries bounds how many times a message the server could not
// process is tried again before it is dropped.
//
// A plain Nak is redelivered immediately, so a message that can *never*
// succeed — one that violates a database constraint, say — becomes a hot
// loop: it is retried as fast as the server can fail it, burning CPU,
// flooding the log, and starving every other consumer sharing the
// connection. That is not hypothetical; one agent publishing facts with no
// IP addresses produced 178,000 log lines in ninety seconds. Dropping the
// message loses one update; leaving it spinning loses the whole pipeline.
const maxRedeliveries = 5

// retryOrTerm redelivers a failed message with backoff, and gives up on it
// once it is clear the failure is permanent rather than transient.
func (s *Server) retryOrTerm(msg jetstream.Msg, kind string, cause error) {
	if meta, err := msg.Metadata(); err == nil && meta.NumDelivered >= maxRedeliveries {
		s.logger.Error("dropping message after repeated failures",
			"kind", kind, "deliveries", meta.NumDelivered, "error", cause)
		msg.Term()
		return
	}
	msg.NakWithDelay(2 * time.Second)
}

// consumeHeartbeats starts a durable JetStream consumer over the agent
// stream, filtered to heartbeat subjects. Durable (not ephemeral) so a
// server restart resumes from where it left off instead of silently
// skipping heartbeats that arrived while it was down — the same
// no-data-loss guarantee the agent's bbolt buffer provides on its side.
func (s *Server) consumeHeartbeats(ctx context.Context) (jetstream.ConsumeContext, error) {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, bnats.AgentStreamName, jetstream.ConsumerConfig{
		Durable:       "server-heartbeat",
		FilterSubject: bnats.AgentHeartbeatWildcard(),
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create heartbeat consumer: %w", err)
	}
	return cons.Consume(func(msg jetstream.Msg) {
		var hb proto.Heartbeat
		if err := json.Unmarshal(msg.Data(), &hb); err != nil {
			s.logger.Warn("discarding malformed heartbeat", "error", err)
			msg.Term() // malformed payload will never parse; don't redeliver forever
			return
		}
		id, err := attributeFromSubject(msg.Subject(), hb.AgentID)
		if err != nil {
			s.logger.Warn("discarding misattributed heartbeat", "error", err)
			msg.Term()
			return
		}
		hb.AgentID = id
		if err := s.store.RecordHeartbeat(ctx, hb.AgentID, hb.Timestamp); err != nil {
			// An endpoint whose row was expired while it was away heartbeats
			// every two seconds against nothing. Retrying that produces a
			// warning every two seconds for a condition the agent's next
			// facts publish repairs on its own, so it is dropped quietly.
			if errors.Is(err, store.ErrUnknownAgent) {
				s.logger.Debug("heartbeat from an agent with no row; waiting for its facts",
					"agent_id", hb.AgentID)
				msg.Term()
				return
			}
			s.logger.Warn("record heartbeat failed", "error", err, "agent_id", hb.AgentID)
			s.retryOrTerm(msg, "heartbeat", err)
			return
		}
		msg.Ack()
		s.refreshAgentHub(ctx)
	})
}

// consumeFacts mirrors consumeHeartbeats for the facts subjects.
func (s *Server) consumeFacts(ctx context.Context) (jetstream.ConsumeContext, error) {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, bnats.AgentStreamName, jetstream.ConsumerConfig{
		Durable:       "server-facts",
		FilterSubject: bnats.AgentFactsWildcard(),
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create facts consumer: %w", err)
	}
	return cons.Consume(func(msg jetstream.Msg) {
		var facts proto.Facts
		if err := json.Unmarshal(msg.Data(), &facts); err != nil {
			s.logger.Warn("discarding malformed facts", "error", err)
			msg.Term()
			return
		}
		id, err := attributeFromSubject(msg.Subject(), facts.AgentID)
		if err != nil {
			s.logger.Warn("discarding misattributed facts", "error", err)
			msg.Term()
			return
		}
		facts.AgentID = id
		normalizeFacts(&facts)
		if err := s.store.RecordFacts(ctx, facts); err != nil {
			s.logger.Warn("record facts failed", "error", err, "agent_id", facts.AgentID)
			s.retryOrTerm(msg, "facts", err)
			return
		}
		msg.Ack()
		s.refreshAgentHub(ctx)
	})
}

// consumeSensors persists periodic sensor snapshots (processes, services,
// installed_apps — see proto.SensorKind) into the agent_sensor_data cache.
// One consumer handles every sensor kind; SensorSnapshot.Sensor says which.
func (s *Server) consumeSensors(ctx context.Context) (jetstream.ConsumeContext, error) {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, bnats.AgentStreamName, jetstream.ConsumerConfig{
		Durable:       "server-sensors",
		FilterSubject: bnats.AgentSensorWildcard(),
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create sensors consumer: %w", err)
	}
	return cons.Consume(func(msg jetstream.Msg) {
		var snap proto.SensorSnapshot
		if err := json.Unmarshal(msg.Data(), &snap); err != nil {
			s.logger.Warn("discarding malformed sensor snapshot", "error", err)
			msg.Term()
			return
		}
		id, err := attributeFromSubject(msg.Subject(), snap.AgentID)
		if err != nil {
			s.logger.Warn("discarding misattributed sensor snapshot", "error", err)
			msg.Term()
			return
		}
		snap.AgentID = id
		// The subject's last token is the kind the broker routed; the body
		// must agree, or a snapshot could be filed under a kind its
		// publisher was not reporting on that subject.
		if subjectKind := msg.Subject()[strings.LastIndex(msg.Subject(), ".")+1:]; string(snap.Sensor) != subjectKind {
			s.logger.Warn("discarding sensor snapshot whose kind disagrees with its subject", "agent_id", id,
				"sensor", snap.Sensor, "subject", msg.Subject())
			msg.Term()
			return
		}
		normalized, err := normalizeSnapshotData(snap.Sensor, snap.Data)
		if err != nil {
			s.logger.Warn("discarding sensor snapshot that does not match its type", "agent_id", id,
				"sensor", snap.Sensor, "error", err)
			msg.Term()
			return
		}
		snap.Data = normalized
		// Integrity is diffed against the stored snapshot *before* it is
		// overwritten — once the new state is saved the previous one is
		// gone, and with it any way to see what changed.
		if snap.Sensor == proto.SensorIntegrity {
			s.diffIntegritySnapshot(ctx, snap.AgentID, snap.Data)
		}
		var persistErr error
		if strings.HasPrefix(string(snap.Sensor), "custom_") {
			persistErr = s.store.RecordCustomSensor(ctx, snap)
		} else if snap.Sensor == proto.SensorReveal {
			// A scan report, not a periodic snapshot: it lands in Reveal's
			// own tables rather than the per-sensor cache.
			persistErr = s.recordRevealReport(ctx, snap)
		} else {
			if snap.Sensor == proto.SensorPatchStatus {
				snap.Data = s.carryPatchFailingSince(ctx, snap.AgentID, snap.Data)
			}
			if snap.Sensor == proto.SensorSecurityPosture {
				// Recovery passwords go to the encrypted escrow table and
				// never into the sensor cache.
				snap.Data = s.escrowRecoveryKeys(ctx, snap)
			}
			persistErr = s.store.UpsertSensorData(ctx, snap.AgentID, string(snap.Sensor), snap.Timestamp, snap.Data)
			if persistErr == nil && snap.Sensor == proto.SensorPatches {
				s.recordPatchObservations(ctx, snap)
			}
			// The software list a remediation's endpoint sends once the
			// direct refresh failed (vulnscan_after.go).
			if persistErr == nil && snap.Sensor == proto.SensorInstalledApps && s.remediatedRecently(snap.AgentID) {
				s.requestVulnScan()
			}
		}
		if err := persistErr; err != nil {
			s.logger.Warn("record sensor data failed", "error", err, "agent_id", snap.AgentID, "sensor", snap.Sensor)
			s.retryOrTerm(msg, "sensor", err)
			return
		}
		msg.Ack()
	})
}

// consumeActionResults records the real outcome of a command that outlived
// its request/reply — today that means apply_patches, which acknowledges in
// milliseconds and finishes minutes or hours later.
//
// Durable, like the other consumers, and for a sharper reason here: a patch
// run routinely outlasts a server deploy. If this were ephemeral, restarting
// the server mid-run would drop the result and leave the deployment open
// forever with no way to learn how it ended.
func (s *Server) consumeActionResults(ctx context.Context) (jetstream.ConsumeContext, error) {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, bnats.AgentStreamName, jetstream.ConsumerConfig{
		Durable:       "server-action-results",
		FilterSubject: bnats.AgentActionResultWildcard(),
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create action result consumer: %w", err)
	}
	return cons.Consume(func(msg jetstream.Msg) {
		var res proto.AgentActionResult
		if err := json.Unmarshal(msg.Data(), &res); err != nil {
			s.logger.Warn("discarding malformed action result", "error", err)
			msg.Term()
			return
		}
		id, err := attributeFromSubject(msg.Subject(), res.AgentID)
		if err != nil {
			s.logger.Warn("discarding misattributed action result", "error", err)
			msg.Term()
			return
		}
		res.AgentID = id
		if res.DeployEvent != nil {
			ev := *res.DeployEvent
			if msg.Subject() != bnats.AgentActionResult(ev.AgentID) {
				msg.Term()
				return
			}
			if err := s.consumeDeployEvent(ctx, ev); err != nil {
				s.retryOrTerm(msg, "deploy event", err)
				return
			}
			msg.Ack()
			return
		}
		if res.ActionID == "" {
			s.logger.Warn("discarding action result with no action id", "agent_id", res.AgentID)
			msg.Term()
			return
		}
		// A timeout is reported as its own status rather than folded into
		// "failed": the update may well still be installing on the device,
		// so "we stopped watching" is the honest answer and a different
		// operational problem from a run that genuinely errored.
		// An interim report moves the action through the patch taxonomy
		// (downloading, installing, waiting on a lock) without closing it.
		if res.Progress {
			detail := res.Detail
			if res.Attempt > 1 {
				detail = strings.TrimSpace(fmt.Sprintf("Retry %d. %s", res.Attempt-1, detail))
			}
			if err := s.store.SetAgentActionProgress(ctx, res.AgentID, res.ActionID, res.Status, detail); err != nil {
				s.retryOrTerm(msg, "action progress", err)
				return
			}
			msg.Ack()
			return
		}
		// A survey's answers are the payload, not a side effect of the
		// action closing, so they are stored before the action is finished:
		// a write that fails here must not leave the action recorded as
		// succeeded with nothing behind it.
		if res.Survey != nil {
			if err := s.recordSurveyAnswers(ctx, res); err != nil {
				s.logger.Warn("recording survey answers failed", "agent_id", res.AgentID, "error", err)
				s.retryOrTerm(msg, "survey answers", err)
				return
			}
		}
		// The agent's check after a restart closes the action it left at
		// "pending restart"; it is not a new run, so nothing else fires.
		if res.Verification {
			status := "failed"
			switch {
			case res.OK && res.RebootRequired:
				status = "pending_restart"
			case res.OK:
				status = "succeeded"
			}
			closed, err := s.store.VerifyPendingRestart(ctx, res.AgentID, res.ActionID, status, safeTruncate(res.Detail, 2000))
			if err != nil {
				s.retryOrTerm(msg, "patch verification", err)
				return
			}
			if closed {
				s.afterRemediation(ctx, res.AgentID)
			}
			if closed && status == "failed" {
				s.notify(ctx, "warning", "Patch", "Updates still pending after a restart",
					safeTruncate(strings.TrimSpace(res.Detail), 300), "/patches#deployments")
			}
			s.logger.Info("patch job verified after restart", "agent_id", res.AgentID, "action_id", res.ActionID,
				"status", status, "applied", closed)
			msg.Ack()
			return
		}
		status := "failed"
		switch {
		case res.OK && res.RebootRequired:
			// Installed but not in effect: the endpoint has to restart
			// before the patch counts, and the deployment says so.
			status = "pending_restart"
		case res.OK:
			status = "succeeded"
		case res.TimedOut:
			status = "timed_out"
		}
		detail := res.Detail
		if res.Attempt > 1 {
			detail = fmt.Sprintf("Retry %d.\n%s", res.Attempt-1, detail)
		}
		if err := s.store.FinishAgentAction(ctx, res.AgentID, res.ActionID, status, detail); err != nil {
			s.logger.Warn("finish action from result failed", "action_id", res.ActionID, "error", err)
			s.retryOrTerm(msg, "action result", err)
			return
		}
		if res.Kind == "patch_apply" {
			s.afterRemediation(ctx, res.AgentID)
		}
		// A run that ends badly goes looking for the operator rather than
		// waiting to be discovered. Success is deliberately silent: a tray
		// that fills up with things that went fine is a tray people stop
		// opening, and then the one that mattered is missed too.
		if status != "succeeded" && status != "pending_restart" {
			severity := "warning"
			title := "Patch run failed on an endpoint"
			if status == "timed_out" {
				title = "Patch run timed out on an endpoint"
			}
			// The notification body is a Postgres text column too, and a
			// patch transcript cut at 300 bytes lands mid-character often.
			detail := safeTruncate(strings.TrimSpace(res.Detail), 300)
			s.notify(ctx, severity, "Patch", title, detail, "/patches#deployments")
		}
		// A Mac's patch job leaves macOS itself to the MDM, which can
		// install it without a user's password; started once the agent's
		// own installs are done so its restart cannot cut them short.
		if res.Kind == "patch_apply" {
			go s.macOSUpdateViaMDM(context.WithoutCancel(ctx), res.AgentID, res.RunID, res.ActionID)
		}
		s.logger.Info("action result recorded", "agent_id", res.AgentID, "run_id", res.RunID,
			"action_id", res.ActionID, "kind", res.Kind, "status", status)
		msg.Ack()
	})
}

// recordPatchObservations notes when the fleet first saw each pending
// patch; the "at least N days old" list rule and the superseded flag both
// read from it. Failure here is logged, not retried: the snapshot itself
// is already persisted and the next one will try again.
func (s *Server) recordPatchObservations(ctx context.Context, snap proto.SensorSnapshot) {
	var patches []proto.PatchInfo
	if json.Unmarshal(snap.Data, &patches) != nil || len(patches) == 0 {
		return
	}
	// The one row: this runs on the sensor consumer for every patches
	// snapshot, where reading the whole agents table made ingest O(fleet²).
	os, _, err := s.store.GetAgentOSArch(ctx, snap.AgentID)
	if err != nil || os == "" {
		return
	}
	names := make([]string, 0, len(patches))
	versions := make([]string, 0, len(patches))
	for _, p := range patches {
		names = append(names, p.Name)
		versions = append(versions, p.NewVersion)
	}
	if err := s.store.RecordPatchObservations(ctx, os, names, versions, snap.Timestamp); err != nil {
		s.logger.Warn("record patch observations", "agent_id", snap.AgentID, "error", err)
	}
}
