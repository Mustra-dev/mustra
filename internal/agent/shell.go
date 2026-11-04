package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// The endpoint half of the live shell.
//
// This runs whatever the control plane sends it, as root. That is the same
// authority a software package already carries, and it is worth being
// explicit that it is not a new class of capability — but it is a far more
// *convenient* one, so the accountability lives on the server: every
// command is recorded with who ran it before the agent ever sees it.
//
// The agent's own contributions are the two things a server cannot do for
// it: bound the runtime so a hung command doesn't pin a goroutine forever,
// and bound the output so `cat /dev/urandom` doesn't try to ship a gigabyte
// through NATS.

const (
	maxShellOutput  = 256 << 10 // 256 KB is a generous screenful; beyond that, redirect to a file
	defaultShellTTL = 60 * time.Second
	maxShellTTL     = 10 * time.Minute
)

func (a *Agent) subscribeShell(ctx context.Context) (*gonats.Subscription, error) {
	return a.nc.Subscribe(bnats.Shell(a.agentID), func(msg *gonats.Msg) {
		var req proto.ShellRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respondShell(msg, proto.ShellReply{Error: "malformed shell request"})
			return
		}
		if a.noRemoteCode {
			a.logger.Warn("refused a shell command: inventory-and-patching mode")
			respondShell(msg, proto.ShellReply{Error: errNoRemoteCode.Error()})
			return
		}
		if strings.TrimSpace(req.Command) == "" {
			respondShell(msg, proto.ShellReply{Error: "empty command"})
			return
		}
		reply := a.runShellCommand(ctx, req)
		a.logger.Info("shell command executed", "session", req.SessionID,
			"command", req.Command, "exit_code", reply.ExitCode)
		respondShell(msg, reply)
	})
}

func respondShell(msg *gonats.Msg, reply proto.ShellReply) {
	payload, err := json.Marshal(reply)
	if err != nil {
		return
	}
	_ = msg.Respond(payload)
}

func (a *Agent) runShellCommand(ctx context.Context, req proto.ShellRequest) proto.ShellReply {
	ttl := defaultShellTTL
	if req.TimeoutSec > 0 {
		ttl = time.Duration(req.TimeoutSec) * time.Second
		if ttl > maxShellTTL {
			ttl = maxShellTTL
		}
	}
	ctx, cancel := context.WithTimeout(ctx, ttl)
	defer cancel()

	cwd := req.WorkingDir
	if cwd == "" {
		cwd = "/"
	}

	// `cd` handled in-process: a subshell's chdir dies with the subshell,
	// so passing it through would make every `cd` silently do nothing —
	// the single most confusing possible behaviour in a shell.
	if target, ok := parseCd(req.Command); ok {
		next := target
		if !filepath.IsAbs(next) {
			next = filepath.Join(cwd, next)
		}
		info, err := os.Stat(next)
		if err != nil {
			return proto.ShellReply{Output: "cd: " + err.Error(), ExitCode: 1, WorkingDir: cwd}
		}
		if !info.IsDir() {
			return proto.ShellReply{Output: "cd: not a directory: " + next, ExitCode: 1, WorkingDir: cwd}
		}
		return proto.ShellReply{Output: next, WorkingDir: filepath.Clean(next)}
	}

	cmd := shellCommand(ctx, req.Command)
	cmd.Dir = cwd
	cmd.Env = append(childEnv(), "DEBIAN_FRONTEND=noninteractive", "TERM=dumb")

	out, err := cmd.CombinedOutput()
	reply := proto.ShellReply{WorkingDir: cwd}
	if len(out) > maxShellOutput {
		out = out[:maxShellOutput]
		reply.Truncated = true
	}
	reply.Output = string(out)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			reply.ExitCode = exitErr.ExitCode()
		} else {
			reply.ExitCode = -1
			reply.Error = err.Error()
		}
		if ctx.Err() == context.DeadlineExceeded {
			reply.Error = "command timed out after " + ttl.String()
		}
	}
	return reply
}

// parseCd recognizes a bare `cd`, which has to be handled by the session
// rather than by a subshell that immediately exits.
func parseCd(command string) (string, bool) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "cd" {
		home := os.Getenv("HOME")
		if home == "" {
			home = "/root"
		}
		return home, true
	}
	rest, ok := strings.CutPrefix(trimmed, "cd ")
	if !ok {
		return "", false
	}
	// Only a plain `cd <path>` — anything chained or piped goes to the
	// shell, where its semantics are whatever the shell says they are.
	if strings.ContainsAny(rest, "|&;<>") {
		return "", false
	}
	return strings.Trim(strings.TrimSpace(rest), `"'`), true
}

var _ = runtime.GOOS
