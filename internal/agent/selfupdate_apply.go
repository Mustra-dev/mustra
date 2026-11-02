package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/updatesig"
)

// Verified self-update, done in Go.
//
// The old path ran whatever "curl <console>/install.sh | bash" the server
// handed back, built from a console URL anyone could poison with a Host
// header. Now:
//
//  1. The offer's manifest must verify under the key this agent pinned at
//     enrollment, name this platform, and be newer than what runs here —
//     or carry a signed downgrade authorization naming this agent.
//  2. The binary is downloaded beside the current one and must match the
//     manifest's size and SHA-256 exactly. The URL itself is not trusted;
//     the signature is.
//  3. A detached helper (a copy of this binary run with --apply-update)
//     swaps the files atomically by rename, restarts the service, and waits
//     for the new build to start and reach the control plane. If it does
//     not within the deadline, the helper puts the previous binary back and
//     restarts that.
//
// No shell, no script and no server-chosen command is involved.

const (
	updateStateFile  = "update-pending.json"
	updateCommitFile = "update-commit.json"
	updateResultFile = "update-result.json"
	// updateLockFile is held by the one updater allowed to run. Two
	// updaters on the same paths once raced: the second moved the freshly
	// installed binary aside as its "previous", found its staged build
	// already consumed, and the first deleted that "previous" on commit,
	// leaving no agent binary at all.
	updateLockFile = "update.lock"
	// updateStale is when a lock or pending update is abandoned: past the
	// commit deadline with room for the download and a slow restart.
	updateStale = commitDeadline + 7*time.Minute
	// agentPIDFile is written by every agent at startup, for the updater
	// on a host with no service manager it can ask to restart the agent.
	agentPIDFile = "agent.pid"
	// maxAgentBinary bounds the download; agent builds are ~15-25 MB.
	maxAgentBinary = 256 << 20
	// commitDeadline is how long the new build has to start and register.
	commitDeadline = 3 * time.Minute
)

// updateState is what the agent hands the helper.
type updateState struct {
	Exe      string    `json:"exe"`
	New      string    `json:"new"`
	Previous string    `json:"previous"`
	Version  string    `json:"version"`
	From     string    `json:"from"`
	DataDir  string    `json:"data_dir"`
	Started  time.Time `json:"started"`
}

// updateResult is what the helper leaves for the agent to report.
type updateResult struct {
	OK      bool      `json:"ok"`
	Version string    `json:"version"`
	Detail  string    `json:"detail"`
	At      time.Time `json:"at"`
}

// updateHTTPClient fetches binaries. A plain client: the binary is
// authenticated by its signed digest, not by the connection it came over.
var updateHTTPClient = &http.Client{Timeout: 10 * time.Minute}

// stagingUpdate keeps a second update command (a double click, or a bulk
// update overlapping a single one) from staging over the first.
var stagingUpdate sync.Mutex

// updateInProgress reports a pending update that is not yet stale, so a
// second request is refused instead of racing the first.
func updateInProgress(dir string) (string, bool) {
	if fi, err := os.Stat(filepath.Join(dir, updateLockFile)); err == nil && time.Since(fi.ModTime()) < updateStale {
		return "", true
	}
	raw, err := os.ReadFile(filepath.Join(dir, updateStateFile))
	if err != nil {
		return "", false
	}
	var st updateState
	if json.Unmarshal(raw, &st) != nil || time.Since(st.Started) >= updateStale {
		return "", false
	}
	return st.Version, true
}

// acquireUpdateLock makes this updater the only one. A lock older than
// updateStale belongs to an updater that died, and is taken over.
func acquireUpdateLock(dir string) (release func(), ok bool) {
	path := filepath.Join(dir, updateLockFile)
	for i := 0; i < 2; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { _ = os.Remove(path) }, true
		}
		fi, serr := os.Stat(path)
		if serr != nil || time.Since(fi.ModTime()) < updateStale {
			return nil, false
		}
		_ = os.Remove(path)
	}
	return nil, false
}

// startVerifiedUpdate verifies an offer, stages the binary and launches the
// helper. It returns once the helper is running; the outcome is reported
// by the next agent to start (reportUpdateResult).
func (a *Agent) startVerifiedUpdate(ctx context.Context, offer *proto.UpdateOffer) (string, error) {
	if offer == nil {
		return "", errors.New("the server offered no signed update; it may not hold a signing key, or this platform has no build")
	}
	pub := a.updateKey()
	if pub == nil {
		return "", errors.New("this agent has no pinned update signing key; re-enroll it to receive signed updates")
	}
	if !stagingUpdate.TryLock() {
		return "", errors.New("an update is already being staged on this endpoint")
	}
	// Released here, or by the background retry it is handed to.
	unlock := true
	defer func() {
		if unlock {
			stagingUpdate.Unlock()
		}
	}()
	if v, busy := updateInProgress(a.dataDir()); busy {
		if v != "" {
			return "", fmt.Errorf("an update to %s is already being applied on this endpoint", v)
		}
		return "", errors.New("an update is already being applied on this endpoint")
	}
	m := offer.Manifest
	if err := m.Check(pub, updatesig.Expectation{OS: runtime.GOOS, Arch: runtime.GOARCH, AgentID: a.agentID,
		CurrentVersion: a.info.Version, Now: time.Now()}); err != nil {
		return "", fmt.Errorf("refusing the update: %w", err)
	}
	exe, err := updateExecutable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	staged := exe + ".new"
	if err := downloadVerified(ctx, offer.BinaryURL, staged, m); err != nil {
		_ = os.Remove(staged)
		if !isTransientDownload(err) {
			return "", err
		}
		// The console is waiting on this reply for 30 seconds, so the
		// retries cannot happen inside it. A fleet-wide push through the
		// tunnel timed endpoints out on the TLS handshake; a second push
		// fixed them, so this does the second push itself.
		unlock = false
		go func() {
			defer stagingUpdate.Unlock()
			if err := downloadWithRetry(ctx, offer.BinaryURL, staged, m, updateRetryDelays, sleepCtx); err != nil {
				_ = os.Remove(staged)
				a.logger.Error("agent update download failed after retries", "version", m.Version, "error", err)
				return
			}
			if _, err := a.installStaged(ctx, exe, staged, m, pub); err != nil {
				a.logger.Error("agent update failed after its download was retried", "version", m.Version, "error", err)
			}
		}()
		return fmt.Sprintf("the download failed (%v); retrying in the background for up to %s", err, totalDelay(updateRetryDelays).Round(time.Minute)), nil
	}
	return a.installStaged(ctx, exe, staged, m, pub)
}

// updateExecutable is the installed binary an update replaces; a variable
// so a test can point it at a temporary file.
var updateExecutable = os.Executable

// installStaged hands a downloaded, verified build to whatever installs it:
// the detached updater, or under the Home Assistant add-on, its supervisor.
func (a *Agent) installStaged(ctx context.Context, exe, staged string, m updatesig.Manifest, pub ed25519.PublicKey) (string, error) {
	if updateByRestart() {
		return a.stageForRestart(exe, staged, m, pub)
	}
	return a.applyStagedUpdate(ctx, exe, staged, m, pub)
}

// stageForRestart leaves the verified build beside the installed one as
// <exe>.verified and exits. The add-on's run.sh renames it into place
// before starting the agent again, so what the add-on installs is exactly
// what the signed manifest names. It used to exit straight after checking
// the manifest, and run.sh installed whatever the server's install.sh
// fetched, checked only against a checksum from the same server.
func (a *Agent) stageForRestart(exe, staged string, m updatesig.Manifest, pub ed25519.PublicKey) (string, error) {
	verified := exe + verifiedSuffix
	if err := renameWithRetry(staged, verified); err != nil {
		_ = os.Remove(staged)
		return "", fmt.Errorf("stage the verified build: %w", err)
	}
	a.logger.Info("verified update staged; restarting so the add-on installs it", "from", a.info.Version, "to", m.Version,
		"key_id", updatesig.KeyID(pub))
	exitForUpdate()
	return "updating to " + m.Version + " (verified; the add-on installs it on restart)", nil
}

// verifiedSuffix names the build stageForRestart leaves for run.sh.
const verifiedSuffix = ".verified"

// applyStagedUpdate hands a downloaded, verified build to the detached
// updater.
func (a *Agent) applyStagedUpdate(ctx context.Context, exe, staged string, m updatesig.Manifest, pub ed25519.PublicKey) (string, error) {
	st := updateState{Exe: exe, New: staged, Previous: exe + ".previous", Version: m.Version, From: a.info.Version,
		DataDir: a.dataDir(), Started: time.Now().UTC()}
	statePath := filepath.Join(a.dataDir(), updateStateFile)
	raw, _ := json.Marshal(st)
	if err := writeSecretFile(statePath, raw); err != nil {
		return "", err
	}
	_ = os.Remove(filepath.Join(a.dataDir(), updateCommitFile))
	// The helper runs from its own copy: the file it replaces is the one
	// this process was started from.
	helper := filepath.Join(a.dataDir(), "mustra-agent-updater"+exeSuffix())
	if err := copyExecutable(exe, helper); err != nil {
		return "", fmt.Errorf("stage the updater: %w", err)
	}
	if err := spawnDetachedHelper(ctx, helper, statePath); err != nil {
		_ = os.Remove(staged)
		_ = os.Remove(statePath)
		return "", fmt.Errorf("start the updater: %w", err)
	}
	if err := confirmHelperStarted(a.dataDir(), statePath, staged, helper, helperStartWait); err != nil {
		a.logger.Error("agent update not applied: the updater did not start", "version", m.Version, "error", err)
		return "", err
	}
	a.logger.Info("verified update staged; the updater is applying it", "from", a.info.Version, "to", m.Version,
		"key_id", updatesig.KeyID(pub))
	return "updating to " + m.Version, nil
}

// helperStartWait is how long the agent waits to see the updater take its
// lock. The console waits 30 seconds for the whole reply, download
// included, and the helper takes the lock as its first act.
var helperStartWait = 10 * time.Second

// confirmHelperStarted waits for the detached updater to take its lock.
// Launching it only proves the launcher ran: on a Windows workstation
// Defender's ransomware ASR rule refused the unsigned helper, the agent
// answered "updating", and the pending state then refused every retry for
// ten minutes as "already being applied". If the lock never appears, the
// staged update is withdrawn (an updater that starts later finds no state
// and exits) and the reason goes back to the console.
func confirmHelperStarted(dataDir, statePath, staged, helper string, wait time.Duration) error {
	lock := filepath.Join(dataDir, updateLockFile)
	result := filepath.Join(dataDir, updateResultFile)
	deadline := time.Now().Add(wait)
	for {
		if _, err := os.Stat(lock); err == nil {
			return nil
		}
		// Finished already, one way or the other.
		if _, err := os.Stat(result); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = os.Remove(statePath)
	_ = os.Remove(staged)
	msg := fmt.Sprintf("the updater did not start within %s, so nothing was changed", wait)
	if runtime.GOOS == "windows" {
		msg += "; Microsoft Defender attack surface reduction rules can block it (event 1121 in Microsoft-Windows-Windows Defender/Operational): " +
			"exclude " + helper + " and the agent's own executable"
	}
	return errors.New(msg)
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// downloadVerified fetches url to dest and checks it against the manifest.
func downloadVerified(ctx context.Context, rawURL, dest string, m updatesig.Manifest) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("unusable download URL %q", rawURL)
	}
	if m.Size <= 0 || m.Size > maxAgentBinary {
		return fmt.Errorf("manifest size %d is out of range", m.Size)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return transientDownload(fmt.Errorf("download the update: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("download the update: HTTP %d", resp.StatusCode)
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
			return transientDownload(err)
		}
		return err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, m.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return transientDownload(fmt.Errorf("download the update: %w", err))
	}
	if n != m.Size {
		err := fmt.Errorf("the download is %d bytes, the signed manifest says %d; nothing was changed", n, m.Size)
		if n < m.Size {
			// Cut short: the connection, not the file.
			return transientDownload(err)
		}
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(m.SHA256) {
		return fmt.Errorf("the download's digest %s does not match the signed manifest; nothing was changed", got)
	}
	if err := os.Chmod(dest, 0o755); err != nil {
		return err
	}
	stableCodeIdentity(dest)
	return nil
}

// macCodeIdentifier is the signing identifier the PPPC profile's Full Disk
// Access rule matches (install.sh signs with the same one).
const macCodeIdentifier = "dev.mustra.agent"

// stableCodeIdentity re-signs a verified macOS build with the identifier the
// Full Disk Access profile names. The Go linker's ad-hoc signature is keyed
// on a hash that changes with every build, so a build swapped in without
// this loses Full Disk Access until someone re-runs the installer. It runs
// only after the signed-manifest digest check, and is best effort like the
// installer's step: if it fails the update still applies, and the agent's
// own Full Disk Access check reports the result.
func stableCodeIdentity(path string) {
	if runtime.GOOS != "darwin" {
		return
	}
	_ = exec.Command("/usr/bin/xattr", "-d", "com.apple.quarantine", path).Run()
	_ = exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", macCodeIdentifier, path).Run()
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

// recordPID notes this process for the updater (see agentPIDFile).
func (a *Agent) recordPID() {
	_ = os.WriteFile(filepath.Join(a.dataDir(), agentPIDFile), []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600)
}

// commitPendingUpdate tells a waiting helper that this build started and
// registered, and reports how the last update went.
func (a *Agent) commitPendingUpdate() {
	dir := a.dataDir()
	if raw, err := os.ReadFile(filepath.Join(dir, updateStateFile)); err == nil {
		var st updateState
		if json.Unmarshal(raw, &st) == nil && st.Version == a.info.Version {
			c, _ := json.Marshal(map[string]any{"version": a.info.Version, "at": time.Now().UTC()})
			if err := os.WriteFile(filepath.Join(dir, updateCommitFile), c, 0o600); err != nil {
				a.logger.Warn("could not confirm the update to the updater", "error", err)
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, updateResultFile)); err == nil {
		var res updateResult
		if json.Unmarshal(raw, &res) == nil {
			if res.OK {
				a.logger.Info("self-update completed", "version", res.Version, "detail", res.Detail)
			} else {
				a.logger.Error("self-update failed and was rolled back", "version", res.Version, "detail", res.Detail)
			}
		}
		_ = os.Remove(filepath.Join(dir, updateResultFile))
	}
}

// ApplyUpdate is the helper's whole job, run as "mustra-agent
// --apply-update <state>" outside the agent's service.
func ApplyUpdate(statePath string, logger *slog.Logger) error {
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return err
	}
	var st updateState
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	finish := func(ok bool, detail string) error {
		res, _ := json.Marshal(updateResult{OK: ok, Version: st.Version, Detail: detail, At: time.Now().UTC()})
		_ = os.WriteFile(filepath.Join(st.DataDir, updateResultFile), res, 0o600)
		_ = os.Remove(statePath)
		_ = os.Remove(filepath.Join(st.DataDir, updateCommitFile))
		if ok {
			logger.Info("update applied", "version", st.Version)
			return nil
		}
		logger.Error("update not applied", "version", st.Version, "detail", detail)
		return errors.New(detail)
	}
	release, ok := acquireUpdateLock(st.DataDir)
	if !ok {
		// Another updater owns these files. Touch nothing, not even the
		// state file: it may be the other updater's.
		logger.Warn("another update is already being applied; this one is skipped", "version", st.Version)
		return errors.New("another update is already being applied")
	}
	defer release()
	// Give the agent time to send its "started" reply.
	time.Sleep(2 * time.Second)

	// Nothing is moved unless the build to install is actually there.
	if _, err := os.Stat(st.New); err != nil {
		return finish(false, "the staged build is missing, so nothing was changed: "+err.Error())
	}

	if err := stopAgentService(st.DataDir); err != nil {
		logger.Warn("stopping the agent service", "error", err)
	}
	_ = os.Remove(st.Previous)
	if err := renameWithRetry(st.Exe, st.Previous); err != nil {
		_ = startAgentService(st.DataDir)
		return finish(false, "could not move the running binary aside: "+err.Error())
	}
	if err := renameWithRetry(st.New, st.Exe); err != nil {
		_ = renameWithRetry(st.Previous, st.Exe)
		_ = startAgentService(st.DataDir)
		return finish(false, "could not move the new binary into place: "+err.Error())
	}
	if err := startAgentService(st.DataDir); err != nil {
		logger.Warn("starting the agent service", "error", err)
	}
	deadline := time.Now().Add(commitDeadline)
	for time.Now().Before(deadline) {
		if c, err := os.ReadFile(filepath.Join(st.DataDir, updateCommitFile)); err == nil {
			var commit struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(c, &commit) == nil && commit.Version == st.Version {
				_ = os.Remove(st.Previous)
				return finish(true, "from "+st.From)
			}
		}
		time.Sleep(2 * time.Second)
	}
	// The new build never confirmed. Put the old one back.
	_ = stopAgentService(st.DataDir)
	_ = os.Remove(st.Exe + ".failed")
	_ = renameWithRetry(st.Exe, st.Exe+".failed")
	if err := renameWithRetry(st.Previous, st.Exe); err != nil {
		_ = startAgentService(st.DataDir)
		return finish(false, "the new build did not start, and restoring the previous one failed: "+err.Error())
	}
	_ = startAgentService(st.DataDir)
	_ = os.Remove(st.Exe + ".failed")
	return finish(false, fmt.Sprintf("%s did not start and reach the control plane within %s; rolled back to %s", st.Version, commitDeadline, st.From))
}

// renameWithRetry tolerates the sharing violations Windows reports while a
// stopped service's image, or an antivirus scan of the new file, still
// holds a handle — the file-lock behaviour the installer already works
// around by stopping the service first.
func renameWithRetry(from, to string) error {
	var err error
	for i := 0; i < 30; i++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}

// updateRetryDelays are the waits before each background retry of an
// update download that failed on the network: about eight minutes in all,
// each jittered (see jitter) so a fleet that failed together does not
// retry together.
var updateRetryDelays = []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute}

// errTransientDownload marks a download failure worth retrying: the
// network, the server or a cut-short body, not what was downloaded.
type errTransientDownload struct{ err error }

func (e errTransientDownload) Error() string { return e.err.Error() }
func (e errTransientDownload) Unwrap() error { return e.err }

func transientDownload(err error) error { return errTransientDownload{err} }

func isTransientDownload(err error) bool {
	var t errTransientDownload
	return errors.As(err, &t)
}

// downloadWithRetry retries a transient download failure after each of
// delays, jittered. A failure that is not transient (a digest mismatch, a
// 404) ends it at once.
func downloadWithRetry(ctx context.Context, rawURL, dest string, m updatesig.Manifest, delays []time.Duration,
	sleep func(context.Context, time.Duration) error) error {
	var err error
	for _, d := range delays {
		if serr := sleep(ctx, jitter(d)); serr != nil {
			return serr
		}
		if err = downloadVerified(ctx, rawURL, dest, m); err == nil || !isTransientDownload(err) {
			return err
		}
		_ = os.Remove(dest)
	}
	return err
}

// jitter is a random duration in [d/2, d).
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	return d/2 + time.Duration(mrand.Int64N(int64(d/2)))
}

func totalDelay(ds []time.Duration) time.Duration {
	var t time.Duration
	for _, d := range ds {
		t += d
	}
	return t
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
