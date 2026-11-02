package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/reveal"
)

type sensorCollector func(ctx context.Context) (any, error)

// patchApplyTimeout caps a single apply_patches run. It has to be generous:
// a Windows cumulative update on a machine that is months behind routinely
// runs past an hour, and the old 20-minute cap silently killed those
// mid-install — leaving the device half-patched and reboot-pending while
// the console showed a clean success.
const patchApplyTimeout = 2 * time.Hour

// sensorTimeout is how long one collection may take. Most sensors read
// local state and finish in milliseconds; the patches sensor is the
// exception, because a Windows Update COM search has to talk to Microsoft
// Update (or WSUS) and a cold search regularly exceeds half a minute. It
// was sharing the 30-second budget, so on Windows the patch scan was
// killed on nearly every tick and the console never saw a patch list.
func sensorTimeout(kind proto.SensorKind) time.Duration {
	if kind == proto.SensorPatches {
		return 10 * time.Minute
	}
	if kind == proto.SensorDirectory {
		return time.Minute // an LDAP round trip to a distant DC, then PowerShell
	}
	if kind == proto.SensorBackups {
		return 3 * time.Minute // a remote PBS storage can take a while to list
	}
	return 30 * time.Second
}

// runSensorLoop periodically collects and publishes one sensor's snapshot
// — the "keep a cached answer fresh" half of the sensor
// story. The interval starts at initial and can be changed at runtime by
// sending on intervalCh (see subscribeCommands), so "refresh every 15
// minutes by default, but adjustable on the fly" doesn't require an agent
// restart. A one-time immediate refresh is just a live query — it doesn't
// touch this loop at all.
func (a *Agent) runSensorLoop(ctx context.Context, kind proto.SensorKind, initial time.Duration, intervalCh <-chan time.Duration, collect sensorCollector) {
	// Every sensor shares one interval and starts with the agent, so
	// without an offset they all run in the same second, every interval;
	// on a Windows domain controller that was three PowerShell sensors at
	// once, over a core of CPU. The offset is the sensor's place in
	// sensorPhases, kept for every later tick because the ticker starts
	// after it.
	if off := sensorPhaseOffset(kind); off > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(off):
		}
	}
	ticker := time.NewTicker(initial)
	defer ticker.Stop()

	publish := func() {
		// A profile's random delay spreads a fleet sharing one interval
		// across the interval rather than into the same second.
		if d := a.randomDelay(); d > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
			}
		}
		a.collectAndPublishSensor(ctx, kind, collect)
	}

	publish()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publish()
		case newInterval, ok := <-intervalCh:
			if !ok {
				continue
			}
			a.logger.Info("sensor interval changed", "sensor", kind, "interval", newInterval)
			ticker.Reset(newInterval)
		}
	}
}

// sensorPhases orders the sensors that cost the most to collect; each
// starts sensorPhaseStep after the one before it. The rest start at once.
var sensorPhases = []proto.SensorKind{
	proto.SensorInstalledApps, proto.SensorPatches, proto.SensorSecurityPosture, proto.SensorDirectory,
	proto.SensorCertificates, proto.SensorLocalAdmins, proto.SensorServices, proto.SensorIntegrity,
}

const sensorPhaseStep = 15 * time.Second

func sensorPhaseOffset(kind proto.SensorKind) time.Duration {
	for i, k := range sensorPhases {
		if k == kind {
			return time.Duration(i) * sensorPhaseStep
		}
	}
	return 0
}

// collectAndPublishSensor runs one sensor collection and publishes the
// resulting snapshot — the shared body behind both runSensorLoop's regular
// ticks and an out-of-band republish (e.g. after apply_patches finishes,
// so the console's cached patches view reflects the new state without
// waiting for the next periodic tick).
func (a *Agent) collectAndPublishSensor(ctx context.Context, kind proto.SensorKind, collect sensorCollector) {
	cctx, cancel := context.WithTimeout(ctx, sensorTimeout(kind))
	data, err := collect(cctx)
	timedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
	cancel()
	if err != nil {
		// Say so explicitly when the budget ran out: a killed child
		// process only reports a generic non-zero exit, which reads as an
		// unexplained failure rather than "this needs longer".
		a.logger.Error("collect sensor failed", "sensor", kind, "error", err, "timed_out", timedOut)
		return
	}
	a.publishSensor(ctx, kind, data)
}

// publishSensor publishes one collected snapshot as the sensor's latest.
func (a *Agent) publishSensor(ctx context.Context, kind proto.SensorKind, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		a.logger.Error("marshal sensor data failed", "sensor", kind, "error", err)
		return
	}
	snap := proto.SensorSnapshot{AgentID: a.agentID, Sensor: kind, Timestamp: time.Now().UTC(), Data: raw}
	payload, err := json.Marshal(snap)
	if err != nil {
		a.logger.Error("marshal sensor snapshot failed", "sensor", kind, "error", err)
		return
	}
	if err := a.pub.PublishLatest(ctx, bnats.AgentSensor(a.agentID, string(kind)), payload); err != nil {
		a.logger.Error("publish sensor snapshot failed", "sensor", kind, "error", err)
	}
}

// reportActionResult tells the server how a long-running command actually
// ended. It goes through the durable publisher rather than a plain publish
// on purpose: the interesting failures here are the ones where the device
// rebooted or dropped off the network partway through a patch run, and a
// result that evaporates in exactly that case is worse than none — the
// console would go back to showing an eternally-open deployment.
//
// A result with no RunID came from a command issued by an older server
// that doesn't track deployments, so there is nothing to attribute it to.
func (a *Agent) reportActionResult(ctx context.Context, res proto.AgentActionResult) {
	if res.RunID == "" || res.ActionID == "" {
		return
	}
	res.AgentID = a.agentID
	res.Timestamp = time.Now().UTC()
	if len(res.Detail) > 8000 {
		// Keep both ends: the summary leads and the error that ended the
		// run comes last, which a head-only cut threw away.
		res.Detail = strings.ToValidUTF8(res.Detail[:2000]+"\n… (truncated) …\n"+res.Detail[len(res.Detail)-5900:], "")
	}
	payload, err := json.Marshal(res)
	if err != nil {
		a.logger.Error("marshal action result failed", "error", err)
		return
	}
	if err := a.pub.Publish(ctx, bnats.AgentActionResult(a.agentID), payload); err != nil {
		a.logger.Error("publish action result failed", "error", err)
	}
}

// subscribeCommands handles mustra.cmd.<agent_id> request/reply. v1
// supports only "set_sensor_interval" — see docs/ROADMAP.md for the
// targeted-command channel's other planned uses.
func (a *Agent) subscribeCommands(ctx context.Context, intervalChans map[proto.SensorKind]chan time.Duration) (*gonats.Subscription, error) {
	return a.nc.Subscribe(bnats.Cmd(a.agentID), func(msg *gonats.Msg) {
		result := a.handleCommand(ctx, msg.Data, intervalChans)
		payload, err := json.Marshal(result)
		if err != nil {
			a.logger.Error("marshal command result failed", "error", err)
			return
		}
		if msg.Reply != "" {
			if err := a.nc.Publish(msg.Reply, payload); err != nil {
				a.logger.Error("reply to command failed", "error", err)
			}
		}
	})
}

func (a *Agent) handleCommand(ctx context.Context, data []byte, intervalChans map[proto.SensorKind]chan time.Duration) proto.AgentCommandResult {
	var cmd proto.AgentCommand
	if err := json.Unmarshal(data, &cmd); err != nil {
		return proto.AgentCommandResult{OK: false, Error: "malformed command: " + err.Error()}
	}
	switch cmd.Cmd {
	case "deploy_settings":
		if cmd.DeploySettings == nil {
			return proto.AgentCommandResult{Error: "missing deploy settings"}
		}
		if err := a.store.saveDeploySettings(*cmd.DeploySettings); err != nil {
			return proto.AgentCommandResult{Error: err.Error()}
		}
		return proto.AgentCommandResult{OK: true}
	case "deploy_capabilities":
		return proto.AgentCommandResult{OK: true, DeployVersion: proto.DeployVersion}
	case "run_deploy":
		if cmd.Deploy == nil || cmd.Deploy.AgentID != a.agentID {
			return proto.AgentCommandResult{Error: "invalid deployment target"}
		}
		_ = a.store.saveDeploySettings(cmd.Deploy.Settings)
		if err := a.store.acceptDeploy(*cmd.Deploy); err != nil {
			return proto.AgentCommandResult{Error: err.Error()}
		}
		return proto.AgentCommandResult{OK: true, DeployVersion: proto.DeployVersion}
	case "cancel_deploy":
		if err := a.store.cancelDeploy(cmd.ActionID); err != nil {
			return proto.AgentCommandResult{Error: err.Error()}
		}
		if cmd.Force {
			a.deployMu.Lock()
			if a.deployActive == cmd.ActionID && a.deployCancel != nil {
				a.deployCancel()
			}
			a.deployMu.Unlock()
		}
		return proto.AgentCommandResult{OK: true}

	case "action_logs":
		return a.queryActionLogs(ctx, cmd.ActionID)
	case "cert_csr":
		if cmd.Cert == nil {
			return proto.AgentCommandResult{Error: "missing certificate job"}
		}
		csr, err := certCSR(*cmd.Cert)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error()}
		}
		return proto.AgentCommandResult{OK: true, Output: csr}
	case "cert_install":
		if cmd.Cert == nil {
			return proto.AgentCommandResult{Error: "missing certificate job"}
		}
		out, err := certInstall(ctx, *cmd.Cert)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		// Report the new certificate now rather than on the next sensor
		// tick, so Cert Manager's inventory shows it straight away.
		go a.collectAndPublishSensor(context.WithoutCancel(ctx), proto.SensorCertificates, func(ctx context.Context) (any, error) {
			return collectCertificates(ctx)
		})
		return proto.AgentCommandResult{OK: true, Output: out}
	case "cert_tailscale":
		if cmd.Cert == nil {
			return proto.AgentCommandResult{Error: "missing certificate job"}
		}
		out, err := certTailscale(ctx, *cmd.Cert)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "cert_adcs_submit":
		if cmd.Cert == nil {
			return proto.AgentCommandResult{Error: "missing certificate job"}
		}
		out, err := certADCSSubmit(ctx, *cmd.Cert)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "trust_root":
		if cmd.Cert == nil {
			return proto.AgentCommandResult{Error: "missing certificate job"}
		}
		out, err := trustRoot(ctx, *cmd.Cert)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "secret_write":
		if cmd.Secret == nil {
			return proto.AgentCommandResult{Error: "missing secret job"}
		}
		out, err := secretWrite(ctx, *cmd.Secret)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "jit_create":
		if cmd.JIT == nil {
			return proto.AgentCommandResult{Error: "missing account"}
		}
		out, err := a.jitCreate(ctx, *cmd.JIT)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "jit_remove":
		if cmd.JIT == nil {
			return proto.AgentCommandResult{Error: "missing account"}
		}
		out, err := a.jitRemove(ctx, cmd.JIT.Username)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "cert_adcs_revoke":
		if cmd.Cert == nil {
			return proto.AgentCommandResult{Error: "missing certificate job"}
		}
		out, err := certADCSRevoke(ctx, *cmd.Cert)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "cert_adcs_ca":
		if cmd.Cert == nil {
			return proto.AgentCommandResult{Error: "missing certificate job"}
		}
		out, err := certADCSCA(ctx, *cmd.Cert)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error(), Output: out}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "macos_update_progress":
		out, err := macOSUpdateProgress(ctx)
		if err != nil {
			return proto.AgentCommandResult{Error: err.Error()}
		}
		return proto.AgentCommandResult{OK: true, Output: out}
	case "test_custom_sensor":
		if cmd.CustomSensor == nil {
			return proto.AgentCommandResult{Error: "missing sensor"}
		}
		result := executeCustomSensor(ctx, *cmd.CustomSensor)
		return proto.AgentCommandResult{OK: result.Error == "", Error: result.Error, CustomSensor: &result}
	case "configure":
		if cmd.Settings == nil {
			return proto.AgentCommandResult{OK: false, Error: "configure needs settings"}
		}
		if err := a.applySettings(ctx, *cmd.Settings, intervalChans); err != nil {
			return proto.AgentCommandResult{OK: false, Error: err.Error()}
		}
		return proto.AgentCommandResult{OK: true}
	case "watch":
		if cmd.Watch == nil {
			return proto.AgentCommandResult{OK: false, Error: "watch needs a watch set"}
		}
		if err := a.applyWatchConfig(ctx, *cmd.Watch); err != nil {
			return proto.AgentCommandResult{OK: false, Error: err.Error()}
		}
		return proto.AgentCommandResult{OK: true}
	case "set_sensor_interval":
		ch, ok := intervalChans[cmd.Sensor]
		if !ok {
			return proto.AgentCommandResult{OK: false, Error: "unknown sensor: " + string(cmd.Sensor)}
		}
		if cmd.IntervalSeconds < 5 || cmd.IntervalSeconds > maxSensorIntervalSeconds {
			return proto.AgentCommandResult{OK: false, Error: "interval_seconds must be between 5 and 86400"}
		}
		select {
		case ch <- time.Duration(cmd.IntervalSeconds) * time.Second:
			return proto.AgentCommandResult{OK: true}
		case <-time.After(2 * time.Second):
			return proto.AgentCommandResult{OK: false, Error: "sensor loop busy, try again"}
		case <-ctx.Done():
			return proto.AgentCommandResult{OK: false, Error: "shutting down"}
		}
	case "apply_patches":
		// Applying updates can genuinely take minutes (download + install,
		// sometimes a package manager lock wait) — don't hold the
		// request/reply open for that. Acknowledge immediately that the
		// job started, run it in the background, and republish the
		// patches sensor when done so the console's cached view catches
		// up without polling.
		runID, actionID := cmd.RunID, cmd.ActionID
		names, selective := cmd.Patches, cmd.Selective
		rebootMode, rebootWarn := cmd.RebootMode, cmd.RebootWarnMinutes
		viaMDM := cmd.MacOSViaMDM
		go func() {
			if selective && len(names) == 0 {
				// The server's patch lists permitted nothing here. Say so
				// and stop; running the unfiltered command instead would be
				// the one outcome the policy exists to prevent.
				a.reportActionResult(ctx, proto.AgentActionResult{RunID: runID, ActionID: actionID, Kind: "patch_apply", OK: true, Detail: "No pending patches are permitted by the patch lists that cover this endpoint"})
				return
			}
			actx, cancel := context.WithTimeout(ctx, patchApplyTimeout)
			defer cancel()
			progress := func(stage, detail string, attempt int) {
				a.reportActionResult(ctx, proto.AgentActionResult{RunID: runID, ActionID: actionID, Kind: "patch_apply", Progress: true, Status: stage, Detail: detail, Attempt: attempt})
			}
			// What this job is for: the selection, or everything pending
			// now. Checked again afterwards, because a package manager
			// exiting 0 is not the same as the update being installed.
			targeted := names
			if len(targeted) == 0 {
				if before, berr := collectPatches(actx, a.nc, a.agentID); berr == nil {
					for _, p := range before {
						targeted = append(targeted, p.Name)
					}
				}
			}
			res, err := applyPatches(actx, a.nc, a.agentID, names, viaMDM, progress)
			for _, u := range res.PrepareForUser {
				go a.prepareMacOSUpdate(context.WithoutCancel(ctx), runID, actionID, u)
			}
			out := res.Output
			if len(res.Notes) > 0 {
				out = strings.Join(res.Notes, "\n") + "\n" + out
			}
			var after []proto.PatchInfo
			var waiting []string // installed, waiting on a restart
			checked := false
			if !errors.Is(actx.Err(), context.DeadlineExceeded) {
				progress("installing", "checking that the updates are installed", res.Attempts)
				var afterErr error
				after, afterErr = collectPatches(ctx, a.nc, a.agentID)
				checked = afterErr == nil
			}
			if checked {
				targeted = slices.DeleteFunc(slices.Clone(targeted), func(n string) bool { return slices.Contains(res.Skipped, n) })
				needRestart, notInstalled := patchesStillPending(targeted, after)
				// An update the job failed to install is not waiting for a
				// restart, whatever flag its listing carries.
				needRestart = slices.DeleteFunc(needRestart, func(n string) bool {
					if slices.Contains(res.Failed, n) {
						notInstalled = append(notInstalled, n)
						return true
					}
					return false
				})
				// One the installer itself reported installed is done, even
				// if Windows lists it until a restart: waiting on the restart
				// when one is due, else on Windows' next scan to drop it.
				var listedAnyway []string
				notInstalled = slices.DeleteFunc(notInstalled, func(n string) bool {
					if !slices.Contains(res.Installed, n) {
						return false
					}
					if res.RebootRequired {
						needRestart = append(needRestart, n)
					} else {
						listedAnyway = append(listedAnyway, n)
					}
					return true
				})
				if len(listedAnyway) > 0 {
					out = fmt.Sprintf("Windows reported these installed but still lists them; the next patch scan should clear them: %s\n", strings.Join(listedAnyway, ", ")) + out
				}
				switch {
				case err == nil && len(notInstalled) > 0:
					err = fmt.Errorf("%d of %d update(s) still pending after the install: %s",
						len(notInstalled), len(targeted), strings.Join(notInstalled, ", "))
				case len(needRestart) > 0:
					waiting = needRestart
					res.RebootRequired = true
					out = fmt.Sprintf("Installed; waiting for a restart to finish: %s\n", strings.Join(needRestart, ", ")) + out
				case err == nil && len(targeted) > 0:
					out = fmt.Sprintf("Verified: all %d update(s) are installed.\n", len(targeted)) + out
				}
			}
			// A killed child process reports a generic non-zero exit, so
			// ask the context — not the error — whether we ran out of time.
			timedOut := errors.Is(actx.Err(), context.DeadlineExceeded)
			// A job left waiting on a restart is checked again once the
			// endpoint is back (patch_verify.go), so it ends verified or not
			// rather than at "pending restart" forever.
			if err == nil && !timedOut && res.RebootRequired {
				if len(waiting) == 0 {
					waiting = targeted
				}
				a.rememberPatchVerification(patchVerification{RunID: runID, ActionID: actionID, Names: waiting, Saved: time.Now()})
			}
			switch {
			case timedOut:
				a.logger.Error("apply patches timed out", "after", patchApplyTimeout, "output", out)
			case err != nil:
				a.logger.Error("apply patches failed", "error", err, "output", out)
			default:
				a.logger.Info("apply patches finished", "selected", len(names), "reboot_required", res.RebootRequired, "output", out)
			}
			detail := out
			if err != nil {
				detail = err.Error() + "\n" + out
			}
			if timedOut {
				detail = "the agent stopped waiting after " + patchApplyTimeout.String() +
					"; the update may still be installing on the device\n" + detail
			}
			// The restart the console asked for, scheduled before the
			// result goes out so the result can say so; the countdown is at
			// least a minute, so the report reaches the server first.
			if note := patchRestartNote(ctx, rebootMode, rebootWarn, res.RebootRequired, err == nil && !timedOut); note != "" {
				a.logger.Info("patch restart", "mode", rebootMode, "note", note)
				detail = note + "\n" + detail
			}
			a.reportActionResult(ctx, proto.AgentActionResult{
				RunID: runID, ActionID: actionID, Kind: "patch_apply",
				OK: err == nil, TimedOut: timedOut, Detail: detail,
				RebootRequired: res.RebootRequired, Attempt: res.Attempts,
			})
			// The list just checked is what the console shows next, so a
			// finished job and its device's pending count agree at once.
			a.collectAndPublishSensor(ctx, proto.SensorPatches, func(ctx context.Context) (any, error) {
				if checked {
					return after, nil
				}
				return a.collectPatchesReported(ctx)
			})
			// Updated packages change the installed versions the
			// vulnerability scan reads, so they go out now rather than at
			// the next tick, which can be hours away.
			a.collectAndPublishSensor(ctx, proto.SensorInstalledApps, func(ctx context.Context) (any, error) {
				return collectInstalledApps(ctx)
			})
		}()
		return proto.AgentCommandResult{OK: true}
	case "kill_process":
		out, err := killProcess(cmd.PID, cmd.ProcessName)
		if err != nil {
			a.logger.Warn("kill process refused or failed", "pid", cmd.PID,
				"expected", cmd.ProcessName, "error", err)
			return proto.AgentCommandResult{OK: false, Error: err.Error()}
		}
		a.logger.Warn("process killed by operator", "pid", cmd.PID, "name", cmd.ProcessName)
		// Republish immediately: the console's cached process list still
		// shows the thing that was just killed, and an operator watching to
		// confirm it worked should not have to wait a sensor interval.
		go a.collectAndPublishSensor(context.WithoutCancel(ctx), proto.SensorProcesses,
			func(ctx context.Context) (any, error) { return collectProcesses(ctx) })
		return proto.AgentCommandResult{OK: true, Output: out}
	case "update_agent":
		// The console asking this endpoint to update itself.
		//
		// It deliberately re-asks the server for authorization rather than
		// trusting a command that says "update": that keeps the version
		// comparison, the downgrade guard and the console URL in the one
		// place they already live, server-side, instead of teaching a
		// second path the same rules and letting the two drift.
		//
		// Either way the update itself is verified here, against the key
		// this agent pinned when it enrolled, and applied by the agent's own
		// updater (selfupdate_apply.go). UpdateCommand, the shell one-liner
		// older agents run, is ignored.
		offer := cmd.Update
		if offer == nil {
			auth := a.askServer(ctx, proto.SelfServiceRequest{Action: "update_agent", User: "console"})
			if !auth.OK {
				return proto.AgentCommandResult{OK: false,
					Error: firstNonEmpty(auth.Error, "the server did not authorize an update")}
			}
			offer = auth.Update
		}
		out, err := a.startVerifiedUpdate(context.WithoutCancel(ctx), offer)
		if err != nil {
			a.logger.Warn("console update refused or failed", "error", err)
			return proto.AgentCommandResult{OK: false, Error: err.Error()}
		}
		a.logger.Info("agent update started from the console", "detail", out)
		return proto.AgentCommandResult{OK: true, Output: out}

	case "notify_user":
		// Acknowledge that the endpoint HAS the message, which is a
		// different thing from the person having answered it. Holding the
		// command channel open until somebody looks at their screen would
		// tie up a request for hours.
		if cmd.Notify == nil {
			return proto.AgentCommandResult{OK: false, Error: "notify_user needs a message"}
		}
		msg := *cmd.Notify
		msg.RunID, msg.ActionID = cmd.RunID, cmd.ActionID
		a.showNotification(ctx, &msg)
		return proto.AgentCommandResult{OK: true, Output: "notification shown"}

	case "ask_user":
		// Same acknowledgement rule as notify_user: the endpoint has the
		// questions, which is not the person having answered them.
		if cmd.Survey == nil {
			return proto.AgentCommandResult{OK: false, Error: "ask_user needs a survey"}
		}
		sv := *cmd.Survey
		sv.RunID, sv.ActionID = cmd.RunID, cmd.ActionID
		a.showSurvey(ctx, &sv)
		return proto.AgentCommandResult{OK: true, Output: "survey shown"}
	case "run_software":
		a.softwareMu.Lock()
		defer a.softwareMu.Unlock()
		if a.store != nil {
			pending, err := a.store.deployStates()
			if err != nil {
				return proto.AgentCommandResult{Error: err.Error()}
			}
			if len(pending) > 0 {
				return proto.AgentCommandResult{Error: "A managed software deployment is active or waiting"}
			}
		}

		// A software-package operation. Unlike apply_patches — which the
		// agent builds itself from a fixed template — this command text
		// comes from the server, authored by an operator holding
		// deploy.manage. That is deliberate and is the whole point of a
		// package, but it means the trust boundary is the control plane:
		// the agent will run what its own server tells it to, with the
		// rights it has, which is the same trust an installer already
		// requires. Nothing here accepts a command from the endpoint side.
		if strings.TrimSpace(cmd.Command) == "" {
			return proto.AgentCommandResult{OK: false, Error: "run_software needs a command"}
		}
		// Stage the payload first. A failure here stops the command
		// running at all: executing a package against a file that did not
		// arrive intact produces a confusing failure at best and a broken
		// endpoint at worst.
		workDir, cleanup, stageErr := stagePackageFiles(ctx, cmd.Files)
		if stageErr != nil {
			return proto.AgentCommandResult{OK: false, Error: stageErr.Error()}
		}
		defer cleanup()
		out, err := runSoftwareCommandIn(ctx, cmd.Command, cmd.TimeoutSeconds, workDir)
		if err != nil {
			return proto.AgentCommandResult{OK: false, Error: err.Error(), Output: out}
		}
		a.logger.Info("software command finished", "command", cmd.Command)
		// The installed-apps snapshot is now stale by definition, and the
		// console decides applicability from it — so republish rather than
		// leave every view claiming the software still isn't there.
		go a.collectAndPublishSensor(ctx, proto.SensorInstalledApps, func(ctx context.Context) (any, error) {
			return collectInstalledApps(ctx)
		})
		return proto.AgentCommandResult{OK: true, Output: out}
	case "run_enforce":
		// Desired state. The trust boundary is the same one a package
		// command already crosses — operator-authored code running with the
		// agent's rights — with one difference worth naming: this runs on a
		// timer with nobody watching. Which is why the agent never decides
		// for itself that something should be fixed; the server sends that
		// decision per setting.
		if cmd.Enforce == nil || len(cmd.Enforce.Settings) == 0 {
			return proto.AgentCommandResult{OK: false, Error: "run_enforce needs a policy with settings"}
		}
		results := runEnforce(ctx, cmd.Enforce)
		fixed := 0
		for _, r := range results {
			if r.State == "remediated" {
				fixed++
			}
		}
		a.logger.Info("enforce policy evaluated", "policy", cmd.Enforce.Name,
			"settings", len(results), "remediated", fixed)
		return proto.AgentCommandResult{OK: true, Enforced: results}
	case "reveal_scan":
		// Acknowledged, not awaited: a walk of a home directory can take
		// minutes, and the report travels back as a snapshot on the durable
		// path so it survives the agent losing the server mid-scan.
		if cmd.Reveal == nil || len(cmd.Reveal.Patterns) == 0 || len(cmd.Reveal.Roots) == 0 {
			return proto.AgentCommandResult{OK: false, Error: "reveal_scan needs roots and patterns"}
		}
		if _, err := reveal.Compile(cmd.Reveal.Patterns); err != nil {
			return proto.AgentCommandResult{OK: false, Error: err.Error()}
		}
		job := *cmd.Reveal
		go a.runRevealScan(ctx, job)
		return proto.AgentCommandResult{OK: true, Output: "scan started"}
	case "run_compliance":
		if len(cmd.Checks) == 0 {
			return proto.AgentCommandResult{OK: false, Error: "no checks supplied"}
		}
		results := collectCompliance(ctx, cmd.Checks)
		a.logger.Info("compliance policy evaluated", "checks", len(results))
		return proto.AgentCommandResult{OK: true, Results: results}
	default:
		return proto.AgentCommandResult{OK: false, Error: "unknown command: " + cmd.Cmd}
	}
}
