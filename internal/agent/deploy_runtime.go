package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/shirou/gopsutil/v4/host"
)

type deployRunner struct {
	a       *Agent
	st      *deployState
	log     *deploylog.Log
	mu      sync.Mutex
	err     error
	secrets []string
}
type deployWait struct{ status, message string }
type deployStop struct{ status, message string }

func (e deployStop) Error() string { return e.message }

func (e deployWait) Error() string { return e.message }
func (r *deployRunner) event(pkg, step, stage, status, message string) {
	r.writeEvent(pkg, step, stage, status, message, nil)
}
func (r *deployRunner) writeEvent(pkg, step, stage, status, message string, code *int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, secret := range r.secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
			for _, line := range strings.FieldsFunc(secret, func(c rune) bool { return c == '\n' || c == '\r' }) {
				message = strings.ReplaceAll(message, line, "[redacted]")
			}
		}
	}
	ev := proto.DeployEvent{ExitCode: code, ID: idgen.New("evt-"), JobID: r.st.Job.ID, RunID: r.st.Job.RunID, AgentID: r.st.Job.AgentID, PackageID: pkg, StepID: step, Stage: stage, Status: status, Message: message, Timestamp: time.Now().UTC()}
	if settings, err := r.a.store.loadDeploySettings(); err == nil && settings != nil {
		if err = r.log.SetSettings(settings.EndpointLogs); err != nil {
			r.err = err
			return
		}
	}
	raw, e := json.Marshal(ev)
	if e == nil {
		_, e = r.log.Write(append(raw, '\n'))
	}
	if e != nil {
		r.err = e
		return
	}
	envelope := proto.AgentActionResult{AgentID: ev.AgentID, RunID: ev.RunID, ActionID: ev.JobID, Kind: "software_" + r.st.Job.Operation, DeployEvent: &ev}
	raw, e = json.Marshal(envelope)
	if e == nil {
		e = r.a.store.Enqueue(BufferedMessage{Subject: bnats.AgentActionResult(ev.AgentID), Payload: raw, Queued: time.Now()})
	}
	if e != nil {
		r.err = e
	}
}
func (a *Agent) runDeployLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var lastMaintenance time.Time
	for {
		if time.Since(lastMaintenance) > time.Minute {
			if settings, e := a.store.loadDeploySettings(); e == nil && settings != nil {
				if _, e := deploylog.Open(filepath.Join(filepath.Dir(a.cfg.DataDir), "deploy", "logs"), settings.EndpointLogs); e != nil {
					a.logger.Warn("retain deployment logs", "error", e)
				}
			}
			lastMaintenance = time.Now()
		}
		states, e := a.store.deployStates()
		if e != nil {
			a.logger.Error("read deployment journal", "error", e)
		}
		slices.SortFunc(states, func(a, b deployState) int { return a.Job.CreatedAt.Compare(b.Job.CreatedAt) })
		for i := range states {
			st := &states[i]
			if ctx.Err() != nil {
				return
			}
			if st.Job.AgentID != a.agentID {
				continue
			}
			if settings, e := a.store.loadDeploySettings(); e == nil && settings != nil {
				st.Job.Settings = *settings
			}
			logs, e := deploylog.Open(filepath.Join(filepath.Dir(a.cfg.DataDir), "deploy", "logs"), st.Job.Settings.EndpointLogs)
			if e != nil {
				a.logger.Error("open deployment log", "error", e)
				continue
			}
			r := &deployRunner{a: a, st: st, log: logs}
			for _, p := range st.Job.Packages {
				r.secrets = append(r.secrets, p.Secrets...)
				for _, f := range p.Files {
					r.secrets = append(r.secrets, f.URL)
				}
			}
			if st.ActiveStep != "" {
				r.finish("interrupted", "Agent restarted while step "+st.ActiveStep+" was running; inspect installer state before retrying")
				continue
			}
			jobCtx, cancel := context.WithCancel(ctx)
			a.deployMu.Lock()
			a.deployActive = st.Job.ID
			a.deployCancel = cancel
			a.deployMu.Unlock()
			a.softwareMu.Lock()
			e = r.run(jobCtx)
			a.softwareMu.Unlock()
			cancel()
			a.deployMu.Lock()
			a.deployActive = ""
			a.deployCancel = nil
			a.deployMu.Unlock()
			if ctx.Err() != nil {
				return
			}
			if e != nil {
				var wait deployWait
				if errors.As(e, &wait) {
					st.Status = wait.status
					r.event("", "", wait.status, wait.status, wait.message)
					_ = a.store.saveDeploy(st)
				} else {
					status := "failed"
					var stop deployStop
					if errors.As(e, &stop) {
						status = stop.status
					}
					if errors.Is(e, context.DeadlineExceeded) {
						status = "timed_out"
					}
					if errors.Is(e, context.Canceled) || st.Cancel {
						status = "cancelled"
					}
					r.finish(status, e.Error())
				}
			} else {
				detail := "All required actions and validation completed"
				if st.Job.Operation == "run" {
					detail = "Action success criteria passed"
				}
				r.finish("succeeded", detail)
			}
			// Waiting jobs retain the endpoint lock logically: no other software run
			// may race an installer awaiting reboot or a user session.
			if !deploy.Terminal(st.Status) {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (r *deployRunner) finish(status, detail string) {
	r.event("", "", "complete", status, detail)
	if r.err != nil {
		r.a.logger.Error("persist deployment outcome evidence", "error", r.err)
		return
	}
	r.st.Status = status
	r.st.ActiveStep = ""
	if e := r.a.store.saveDeploy(r.st); e != nil {
		r.a.logger.Error("persist deployment outcome", "error", e)
		return
	}
	if r.st.Workspace != "" {
		_ = os.RemoveAll(r.st.Workspace)
	}
}
func (r *deployRunner) checkpoint() error {
	if e := r.a.store.saveDeploy(r.st); e != nil {
		return e
	}
	if r.st.Cancel {
		return context.Canceled
	}
	if r.err != nil {
		return fmt.Errorf("deployment evidence could not be persisted: %w", r.err)
	}
	if !r.st.Job.ExpiresAt.IsZero() && time.Now().After(r.st.Job.ExpiresAt) {
		return deployStop{"expired", "Deployment expired before further work could begin"}
	}
	return nil
}
func (r *deployRunner) run(ctx context.Context) error {
	if e := r.checkpoint(); e != nil {
		return e
	}
	if r.st.RebootAt > 0 {
		boot, e := host.BootTimeWithContext(ctx)
		if e != nil {
			return e
		}
		if boot == r.st.RebootAt {
			return deployWait{"reboot_required", "Waiting for the required reboot"}
		}
		r.st.RebootAt = 0
		if e = r.checkpoint(); e != nil {
			return e
		}
	}
	for _, p := range r.st.Job.Packages {
		key := p.PackageID + ":complete"
		if r.st.Done[key] {
			continue
		}
		a, ok := p.Variant.Actions[p.Operation]
		if !ok {
			return fmt.Errorf("operation %s missing for %s", p.Operation, p.Name)
		}
		if p.Variant.OS != runtime.GOOS || len(p.Variant.Arch) > 0 && !slices.Contains(p.Variant.Arch, runtime.GOARCH) {
			return fmt.Errorf("job platform does not match endpoint")
		}
		if a.Identity == "user" {
			wanted := a.Username
			if p.Operation == "run" && r.st.ExecutionUser != "" {
				wanted = r.st.ExecutionUser
			}
			name, e := deployUser(wanted)
			if e != nil {
				return deployWait{"waiting_user", "Waiting for user session: " + e.Error()}
			}
			if p.Operation == "run" {
				r.st.ExecutionUser = name
				a.Username = name
				p.Variant.Actions[p.Operation] = a
				if e = r.checkpoint(); e != nil {
					return e
				}
			}
		}
		if p.Operation == "run" && !r.st.Done[p.PackageID+":identity"] {
			r.event(p.PackageID, "", "identity", "running", fmt.Sprintf("Execution identity: %s %s; variant: %s; revision: %s", a.Identity, a.Username, p.Variant.ID, p.RevisionID))
			r.st.Done[p.PackageID+":identity"] = true
		}
		startedKey := p.PackageID + ":started"
		if !r.st.Done[startedKey] && p.Operation != "run" {
			for _, check := range []*proto.DeployCheck{p.Variant.Requirements, a.Requirements} {
				ok, e := r.check(ctx, p, check)
				if e != nil {
					return e
				}
				if !ok {
					if p.PackageID == r.st.Job.PackageID {
						return deployStop{"skipped", "Endpoint does not meet package requirements"}
					}
					return fmt.Errorf("dependency %s requirements are not satisfied", p.Name)
				}
			}

			present, e := r.check(ctx, p, p.Variant.Detection)
			if e != nil {
				return e
			}
			satisfied := present
			if present && p.Operation != "remove" {
				satisfied, e = r.check(ctx, p, a.Validation)
				if e != nil {
					return fmt.Errorf("desired-state check: %w", e)
				}
			}
			if ((p.Operation == "install" || p.Operation == "update") && satisfied) || (p.Operation == "remove" && !present) {
				r.event(p.PackageID, "", "validated", "running", "Desired state is already satisfied; skipping action")
				r.st.Done[key] = true
				if e = r.checkpoint(); e != nil {
					return e
				}
				continue
			}

			r.st.Done[startedKey] = true
			if e = r.checkpoint(); e != nil {
				return e
			}
		}
		r.event(p.PackageID, "", "action", "running", p.Operation+" "+p.Name)
		if e := r.steps(ctx, p, a, a.Steps); e != nil {
			return e
		}
		if a.ValidateAfterReboot && !r.st.Done[p.PackageID+":reboot"] {
			boot, e := host.BootTimeWithContext(ctx)
			if e != nil {
				return e
			}
			r.st.RebootAt = boot
			r.st.Done[p.PackageID+":reboot"] = true
			if e = r.checkpoint(); e != nil {
				return e
			}
			if r.st.Job.AllowReboot {
				if e = deployReboot(ctx); e != nil {
					return e
				}
			}
			return deployWait{"reboot_required", "Action completed; validation will run after reboot"}
		}
		if a.Validation != nil {
			if e := r.verify(ctx, p, a); e != nil {
				return e
			}
		}
		r.st.Done[key] = true
		if e := r.checkpoint(); e != nil {
			return e
		}
		if p.Operation == "run" {
			r.event(p.PackageID, "", "action_complete", "running", "Action success criteria passed")
		} else {
			r.event(p.PackageID, "", "validated", "running", "Validation passed")
		}
	}
	return nil
}

func (r *deployRunner) stage(ctx context.Context, p proto.DeployPackagePlan, a proto.DeployAction, step proto.DeployStep) (string, error) {
	if p.Operation == "run" {
		if r.st.DownloadDeadline.IsZero() {
			seconds := a.DownloadSeconds
			if seconds == 0 {
				seconds = 1800
			}
			r.st.DownloadDeadline = time.Now().Add(time.Duration(seconds) * time.Second)
			if e := r.checkpoint(); e != nil {
				return "", e
			}
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, r.st.DownloadDeadline)
		defer cancel()
		if ctx.Err() != nil {
			return "", fmt.Errorf("download phase timed out: %w", ctx.Err())
		}
	}

	// An exclusively created, unpredictable workspace prevents another local
	// account from planting a symlink before a privileged job stages its files.
	if r.st.Workspace == "" {
		workspace, e := os.MkdirTemp("", "mustra-deploy-")
		if e != nil {
			return "", e
		}
		r.st.Workspace = workspace
		if e = r.checkpoint(); e != nil {
			os.RemoveAll(workspace)
			return "", e
		}
	}
	info, e := os.Lstat(r.st.Workspace)
	if e != nil {
		return "", e
	}
	if !info.IsDir() {
		return "", fmt.Errorf("deployment workspace is no longer a directory")
	}
	dir := filepath.Join(r.st.Workspace, p.PackageID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	if len(step.Files) > 0 && !a.RequireFiles {
		return "", fmt.Errorf("step requires files but downloads are disabled")
	}
	cache := filepath.Join(filepath.Dir(r.a.cfg.DataDir), "deploy", "cache")
	if e := os.MkdirAll(cache, 0700); e != nil {
		return "", e
	}
	for _, id := range step.Files {
		f, ok := p.Files[id]
		if !ok {
			return "", fmt.Errorf("required file %s is unavailable", id)
		}
		_, hashError := hex.DecodeString(f.SHA256)
		if hashError != nil || len(f.SHA256) != 64 || filepath.Base(f.Name) != f.Name || strings.ContainsAny(f.Name, "/\\") {
			return "", fmt.Errorf("invalid file reference")
		}
		path := filepath.Join(cache, f.SHA256)
		if !verifyCachedFile(path, f.SHA256) {
			r.event(p.PackageID, step.ID, "download", "waiting_download", "Downloading "+f.Name)
			tmp, e := os.CreateTemp(cache, ".download-")
			if e != nil {
				return "", e
			}
			name := tmp.Name()
			tmp.Close()
			os.Remove(name)
			e = downloadAndVerify(ctx, f, name)
			if e == nil {
				e = os.Rename(name, path)
			}
			os.Remove(name)
			if e != nil {
				if ctx.Err() != nil {
					return "", fmt.Errorf("download phase: %w", ctx.Err())
				}
				if strings.Contains(e.Error(), "content does not match") || strings.Contains(e.Error(), "payload size does not match") {
					return "", e
				}
				return "", deployWait{"waiting_download", fmt.Sprintf("Download %s unavailable: %v", f.Name, e)}
			}
		}
		src, e := os.Open(path)
		if e != nil {
			return "", e
		}
		dst, e := createFresh(filepath.Join(dir, f.Name), 0700)
		if e != nil {
			src.Close()
			return "", e
		}
		_, e = io.Copy(dst, src)
		src.Close()
		ce := dst.Close()
		if e != nil {
			return "", e
		}
		if ce != nil {
			return "", ce
		}
		now := time.Now()
		os.Chtimes(path, now, now)
	}
	if p.Operation == "run" && step.Script != nil && step.Script.Language == "go" {
		file := filepath.Join(dir, ".mustra-"+step.ID+".bin")
		if runtime.GOOS == "windows" {
			file += ".exe"
		}
		if e := stageGoSensor(ctx, step.Script.Artifact, file); e != nil {
			if ctx.Err() != nil {
				return "", fmt.Errorf("download phase: %w", ctx.Err())
			}
			return "", e
		}
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("download phase: %w", ctx.Err())
	}
	pruneDeployCache(cache, int64(r.st.Job.Settings.CacheMB)*1000000)
	return dir, nil
}
func (r *deployRunner) command(ctx context.Context, p proto.DeployPackagePlan, a proto.DeployAction, step proto.DeployStep, dir string) (code int, err error) {
	s := step.Script
	if s == nil {
		return -1, fmt.Errorf("missing script")
	}
	budget := s.TimeoutSeconds
	if budget <= 0 {
		budget = 900
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(budget)*time.Second)
	defer cancel()
	defer func() {
		if cctx.Err() != nil {
			err = fmt.Errorf("execution phase: %w", cctx.Err())
		}
	}()
	filename := filepath.Join(dir, ".mustra-"+step.ID)
	var cmd *exec.Cmd
	switch s.Language {
	case "shell":
		filename += ".sh"
		cmd = exec.CommandContext(cctx, "/bin/sh", filename)
	case "powershell":
		filename += ".ps1"
		cmd = exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", filename)
	case "batch":
		filename += ".cmd"
		cmd = exec.CommandContext(cctx, "cmd.exe", "/D", "/C", filename)
	case "python":
		filename += ".py"
		python, e := privatePython()
		if e != nil {
			return -1, e
		}
		cmd = exec.CommandContext(cctx, python, "-I", "-S", "-X", "utf8", filename)
	case "go":
		filename += ".bin"
		if runtime.GOOS == "windows" {
			filename += ".exe"
		}
		if p.Operation != "run" {
			if e := stageGoSensor(cctx, s.Artifact, filename); e != nil {
				return -1, e
			}
		}
		cmd = exec.CommandContext(cctx, filename)
	default:
		return -1, fmt.Errorf("unsupported language %s", s.Language)
	}
	if s.Language != "go" {
		source := s.Source
		if s.Language == "powershell" {
			source = "\xef\xbb\xbf" + source + "\nif ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }\n"
		}
		if e := writeFresh(filename, []byte(source), 0700); e != nil {
			return -1, e
		}
	}
	cmd.Dir = dir
	cmd.Env = append(childEnv(), "MUSTRA_PACKAGE_DIR="+dir, "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "HOMEBREW_NO_AUTO_UPDATE=1")
	for name, value := range p.Parameters {
		cmd.Env = append(cmd.Env, "MUSTRA_PARAM_"+name+"="+value)
	}
	after, cleanup, e := configureSensorProcess(cmd)
	if e != nil {
		return -1, e
	}
	defer cleanup()
	if a.Identity == "user" {
		defer cleanupDeployUser(cmd)
		if e = configureDeployUser(cctx, cmd, a.Username, dir); e != nil {
			return -1, e
		}
	}
	// Every output line is a durable outbox write, which takes seconds when
	// the disk is busy (a fleet-wide run on shared storage). Written from
	// the pipe copy, that held the copy past WaitDelay and failed commands
	// that had exited 0. The queue lets the pipe drain at once; the lines
	// are written after, in order, however long that takes.
	q := newEmitQueue()
	defer q.close()
	stdout := &actionOutput{emit: func(line string) { q.add(func() { r.event(p.PackageID, step.ID, "stdout", "running", line) }) }}
	stderr := &actionOutput{emit: func(line string) { q.add(func() { r.event(p.PackageID, step.ID, "stderr", "running", line) }) }}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	if e = cmd.Start(); e != nil {
		return -1, e
	}
	if e = after(); e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return -1, e
	}
	e = cmd.Wait()
	stdout.flush()
	stderr.flush()
	q.close()
	code = cmd.ProcessState.ExitCode()
	r.writeEvent(p.PackageID, step.ID, "execution_result", "running", fmt.Sprintf("Command exited with code %d", code), &code)
	if cctx.Err() != nil {
		return code, fmt.Errorf("execution phase: %w", cctx.Err())
	}
	if e != nil {
		var exit *exec.ExitError
		if !errors.As(e, &exit) {
			return code, e
		}
	}
	if p.Operation == "run" && a.SuccessMode == "sensor" && code >= 0 {
		return code, nil
	}
	success := step.SuccessCodes
	if len(success) == 0 {
		success = []int{0}
	}
	if slices.Contains(success, code) || slices.Contains(step.RebootCodes, code) {
		return code, nil
	}
	if e == nil {
		e = fmt.Errorf("command exited %d", code)
	}
	return code, e
}
func (r *deployRunner) collectLog(p proto.DeployPackagePlan, step, path string) {
	f, e := os.Open(path)
	if e != nil {
		r.event(p.PackageID, step, "installer_log", "running", fmt.Sprintf("Cannot collect %s: %v", path, e))
		return
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 1032768))
	if e != nil {
		return
	}
	// Redact before chunking so a secret crossing a chunk boundary cannot leak.
	text := string(data)
	for _, secret := range r.secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	data = []byte(text)
	if len(data) > 1000000 {
		data = data[:1000000]
		r.event(p.PackageID, step, "installer_log", "running", "Installer log truncated after 1 MB")
	}
	for len(data) > 0 {
		n := min(len(data), 8192)
		r.event(p.PackageID, step, "installer_log", "running", path+"\n"+string(data[:n]))
		data = data[n:]
	}
}

// createFresh creates path as a new file, replacing whatever was there. The
// package directory is handed to the logged-in user for user-identity steps,
// so by the next step or retry anything in it may be the user's: a link to a
// root-owned file would make an ordinary create-and-truncate write through
// it. Removing first never follows a link, and O_EXCL refuses to open
// anything that reappears in between instead of following it.
func createFresh(path string, perm os.FileMode) (*os.File, error) {
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
}

// writeFresh is os.WriteFile through createFresh.
func writeFresh(path string, data []byte, perm os.FileMode) error {
	f, e := createFresh(path, perm)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if ce := f.Close(); e == nil {
		e = ce
	}
	return e
}
