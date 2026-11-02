package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Recovery when an update takes the agent down for good.
//
// The updater rolls back a build that does not start (selfupdate_apply.go),
// but only while the updater itself survives: a reboot in the middle of the
// swap, an updater that antivirus kills or blocks, or a build that commits
// and then crash-loops leaves nothing on the machine to put things right,
// and the console has no other way in.
//
// So the agent keeps a last-known-good copy of itself, beside the binary
// in the install directory, taken only after a build has run for
// lkgHealthyAfter. It also registers a small job with the OS scheduler
// (a systemd timer, cron, a launchd job or a scheduled task) that runs that
// copy with --recover every recoverInterval. The copy checks the heartbeat
// the running agent writes; if it is stale, no update is in progress and
// the service is still installed and enabled, it restarts the service, and
// if the installed build is not the known-good one, it puts that back first.
//
// Two lines it never crosses. It does nothing for a service an
// administrator disabled, which is how the agent is kept down on purpose.
// And it lives inside the install directory, so an uninstall that removes
// the directory removes every way it could bring the agent back; finding
// the service gone, it unregisters its own job.

const (
	heartbeatFile     = "heartbeat"
	lkgStateFile      = "last-known-good.json"
	recoverLogFile    = "recover.log"
	lkgHealthyAfter   = 10 * time.Minute
	recoverInterval   = 10 * time.Minute
	recoverStaleAfter = 15 * time.Minute
	// recoverRecheck is how long a stale heartbeat is given to move before
	// anything is done: a machine just woken from sleep has a running agent
	// whose last beat is hours old, and it writes the next within a minute.
	recoverRecheck = 90 * time.Second
)

// heartbeatEvery is a variable so a test can run the heartbeat quickly.
var heartbeatEvery = time.Minute

func writeHeartbeat(dir string) {
	_ = os.WriteFile(filepath.Join(dir, heartbeatFile), []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
}

// beatWhileRunning keeps the heartbeat fresh from the moment the process
// runs, before and regardless of the control plane. keepRecoveryReady's
// beat starts only once NATS is reached, and the recovery job reads a
// stale beat as "not running". Without this, an agent cut off from the
// broker -- by an outage, or by whoever can block its traffic -- looked
// dead, and one within lkgHealthyAfter of an update was rolled back to the
// previous build with no downgrade authorization.
//
// It never beats at once, so a build that crash-loops still looks dead and
// is still restored. It also stays quiet while an update is pending: a new
// build that cannot reach the control plane is the updater's to roll back
// (commitDeadline).
func (a *Agent) beatWhileRunning(ctx context.Context) {
	dir := a.dataDir()
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, pending := updateInProgress(dir); !pending {
			writeHeartbeat(dir)
		}
	}
}

// lkgPath is where the known-good copy of exe lives:
// /opt/mustra-agent/mustra-agent.lkg, C:\…\mustra-agent.lkg.exe.
func lkgPath(exe string) string {
	base := strings.TrimSuffix(exe, exeSuffix())
	return base + ".lkg" + exeSuffix()
}

// lkgState records which build the known-good copy is.
type lkgState struct {
	Version string    `json:"version"`
	SHA256  string    `json:"sha256"`
	At      time.Time `json:"at"`
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// keepRecoveryReady runs for the life of the agent: a heartbeat every
// minute, and once this build has run for lkgHealthyAfter, the known-good
// copy refreshed to it and the recovery job registered. It does nothing
// for an agent not running as the installed service (a developer's
// `go run`, a test).
func (a *Agent) keepRecoveryReady(ctx context.Context) {
	dir := a.dataDir()
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	beat := func() { writeHeartbeat(dir) }
	beat()
	started := time.Now()
	ready := false
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		beat()
		if ready || time.Since(started) < lkgHealthyAfter {
			continue
		}
		ready = true
		if installed, _ := agentServiceRegistered(); !installed || !isInstalledAgent(exe) {
			continue
		}
		if err := refreshLastKnownGood(exe, dir, a.info.Version); err != nil {
			a.logger.Warn("could not keep a last-known-good copy of the agent", "error", err)
			continue
		}
		if err := installRecoveryJob(lkgPath(exe), exe, dir); err != nil {
			a.logger.Warn("could not register the agent recovery job", "error", err)
		}
	}
}

// isInstalledAgent says exe is the installed agent rather than a copy run
// from somewhere else: the recovery copy itself, an updater, a dev build.
func isInstalledAgent(exe string) bool {
	name := strings.TrimSuffix(filepath.Base(exe), exeSuffix())
	return name == "mustra-agent"
}

// refreshLastKnownGood copies exe over the known-good copy when they
// differ. Written beside it and renamed, so a crash mid-copy never leaves
// a half-written known-good binary.
func refreshLastKnownGood(exe, dataDir, version string) error {
	sum, err := fileSHA256(exe)
	if err != nil {
		return err
	}
	dst := lkgPath(exe)
	if cur, err := fileSHA256(dst); err == nil && cur == sum {
		return nil
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	if err := copyExecutable(exe, tmp); err != nil {
		return err
	}
	if err := renameWithRetry(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	st, _ := json.Marshal(lkgState{Version: version, SHA256: sum, At: time.Now().UTC()})
	return os.WriteFile(filepath.Join(dataDir, lkgStateFile), st, 0o600)
}

// recoverFacts is what the recovery copy sees on the machine.
type recoverFacts struct {
	ServiceInstalled bool
	ServiceEnabled   bool
	UpdateInProgress bool
	// HeartbeatAge is how old the agent's last beat is; HeartbeatKnown is
	// false when there is none at all.
	HeartbeatAge   time.Duration
	HeartbeatKnown bool
	ExeExists      bool
	ExeIsLKG       bool
}

type recoverAction string

const (
	recoverNothing      recoverAction = "nothing"
	recoverUnregister   recoverAction = "unregister" // the agent was uninstalled
	recoverRestart      recoverAction = "restart"    // the right build, not running
	recoverRestoreLKG   recoverAction = "restore"    // the wrong build, not running
	recoverStaleRecheck recoverAction = "recheck"    // stale: look again shortly
)

// decideRecovery is the whole policy, kept free of the OS so every case is
// tested. firstLook is true on the first observation of a run; a stale
// heartbeat is only acted on when it is still stale on the second.
func decideRecovery(f recoverFacts, firstLook bool) (recoverAction, string) {
	switch {
	case !f.ServiceInstalled:
		return recoverUnregister, "the agent service is not installed"
	case !f.ServiceEnabled:
		return recoverNothing, "the agent service is disabled, so it is down on purpose"
	case f.UpdateInProgress:
		return recoverNothing, "an update is being applied"
	case f.HeartbeatKnown && f.HeartbeatAge < recoverStaleAfter:
		return recoverNothing, "the agent is running"
	case firstLook && f.ExeExists:
		return recoverStaleRecheck, "the heartbeat is stale; checking again"
	case !f.ExeExists:
		return recoverRestoreLKG, "the agent binary is missing"
	case !f.ExeIsLKG:
		return recoverRestoreLKG, "the installed build is not running and is not the last known good one"
	default:
		return recoverRestart, "the agent is not running"
	}
}

// The service-manager calls Recover makes, as variables so a test can run
// the whole recovery against a temporary directory.
var (
	recoverServiceRegistered = agentServiceRegistered
	recoverStopService       = stopAgentService
	recoverStartService      = restartAgentService
	recoverUnregisterJob     = uninstallRecoveryJob
	recoverWait              = time.Sleep
	recoverSelf              = os.Executable
)

// Recover is the recovery job's whole run: "mustra-agent.lkg --recover
// <data dir> --recover-exe <installed binary>", started by the OS
// scheduler, running from the known-good copy.
func Recover(dataDir, exe string, logger *slog.Logger) error {
	self, _ := recoverSelf()
	logf := func(format string, args ...any) {
		line := time.Now().UTC().Format(time.RFC3339) + " " + fmt.Sprintf(format, args...)
		logger.Info(line)
		appendBounded(filepath.Join(dataDir, recoverLogFile), line+"\n", 64<<10)
	}
	look := func() recoverFacts {
		var f recoverFacts
		f.ServiceInstalled, f.ServiceEnabled = recoverServiceRegistered()
		_, f.UpdateInProgress = updateInProgress(dataDir)
		if fi, err := os.Stat(filepath.Join(dataDir, heartbeatFile)); err == nil {
			f.HeartbeatKnown, f.HeartbeatAge = true, time.Since(fi.ModTime())
		}
		if _, err := os.Stat(exe); err == nil {
			f.ExeExists = true
			a, errA := fileSHA256(exe)
			b, errB := fileSHA256(self)
			f.ExeIsLKG = errA == nil && errB == nil && a == b
		}
		return f
	}
	action, why := decideRecovery(look(), true)
	if action == recoverStaleRecheck {
		recoverWait(recoverRecheck)
		action, why = decideRecovery(look(), false)
	}
	switch action {
	case recoverNothing:
		return nil
	case recoverUnregister:
		logf("%s; removing the recovery job", why)
		return recoverUnregisterJob()
	case recoverRestart:
		logf("%s; restarting the service", why)
		_ = recoverStopService(dataDir)
		return recoverStartService(dataDir)
	case recoverRestoreLKG:
		var st lkgState
		if raw, err := os.ReadFile(filepath.Join(dataDir, lkgStateFile)); err == nil {
			_ = json.Unmarshal(raw, &st)
		}
		logf("%s; restoring the last known good build %s", why, firstNonEmpty(st.Version, "(unknown version)"))
		_ = recoverStopService(dataDir)
		_ = os.Remove(exe + ".failed")
		_ = renameWithRetry(exe, exe+".failed")
		if err := copyExecutable(self, exe); err != nil {
			logf("restoring failed: %v", err)
			if _, err2 := os.Stat(exe); err2 != nil {
				_ = renameWithRetry(exe+".failed", exe)
			}
			return err
		}
		res, _ := json.Marshal(updateResult{OK: false, Version: st.Version,
			Detail: "the agent stopped running after an update (" + why + "); the recovery job restored the last known good build " + st.Version,
			At:     time.Now().UTC()})
		_ = os.WriteFile(filepath.Join(dataDir, updateResultFile), res, 0o600)
		return recoverStartService(dataDir)
	}
	return nil
}

// appendBounded appends line to path, starting the file over once it
// passes max bytes, so a job that runs every ten minutes for years cannot
// fill the disk.
func appendBounded(path, line string, max int64) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > max {
		_ = os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}
