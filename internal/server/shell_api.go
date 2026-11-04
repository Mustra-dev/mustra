package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Live shell.
//
// The capability is not new — a software package already runs arbitrary
// commands as root on any endpoint — but it is far more convenient, and
// convenience is what turns a capability into a habit. So the whole design
// here is about accountability rather than about the shell itself:
//
//   - a session is an explicit object with an owner, not an ambient ability
//   - every command is written to the log *before* it is sent, so one that
//     hangs or kills the agent still leaves a trace
//   - it requires deploy.manage, the same permission as pushing software,
//     because it is the same power with a faster path to it
//
// Deliberately request/reply per command rather than a streamed PTY. A PTY
// is nicer to use and much harder to audit — every keystroke becomes a
// frame and "what did this person actually run" stops being answerable.

// openShellRequest is the body of POST /api/shell/sessions.
type openShellRequest struct {
	AgentID string `json:"agent_id" api:"required"`
	// Reason is why this session needs to exist. A Jump Gate policy
	// can require it; without one it is optional and still recorded.
	Reason string `json:"reason"`
}

// openShellResponse is what POST /api/shell/sessions answers.
type openShellResponse struct {
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Hostname   string     `json:"hostname"`
	SessionID  string     `json:"session_id"`
	WorkingDir string     `json:"working_dir"`
}

func (s *Server) handleOpenShell(w http.ResponseWriter, r *http.Request) {
	var body openShellRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var target *store.AgentRecord
	for i := range agents {
		if agents[i].AgentID == body.AgentID {
			target = &agents[i]
			break
		}
	}
	if target == nil {
		http.Error(w, "no such endpoint", http.StatusNotFound)
		return
	}
	// A shell is the most direct action there is, so management rights and
	// the shell action group apply before the session exists rather than
	// per command.
	if !s.checkTargets(w, r, "shell", []string{target.AgentID}) {
		return
	}
	// Jump Gate: a reason, somebody else agreeing, and a clock — whichever
	// of those the policy covering this endpoint asks for.
	allowed, grantID, expires := s.jumpGate(w, r, target.AgentID, target.Hostname, body.Reason)
	if !allowed {
		return
	}
	if !target.Online {
		http.Error(w, "that endpoint is offline", http.StatusConflict)
		return
	}

	who := auth.CurrentUser(r.Context()).Username
	sess := store.ShellSession{
		ID: idgen.New("sh-"), AgentID: body.AgentID, OpenedBy: who, WorkingDir: "/",
		OpenedByID: shellPrincipal(r.Context()),
	}
	if err := s.store.CreateShellSession(r.Context(), sess); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Why the session exists and what allowed it, recorded with it: a
	// transcript that cannot answer "why" is only half an audit trail.
	if err := s.store.SetSessionAccess(r.Context(), sess.ID, strings.TrimSpace(body.Reason), grantID, expires); err != nil {
		s.logger.Warn("recording session access failed", "session", sess.ID, "error", err)
	}
	s.logger.Info("shell session opened", "session", sess.ID,
		"agent_id", body.AgentID, "hostname", target.Hostname, "by", who, "grant", grantID)
	s.audit(r.Context(), auditEvent{
		Action: "shell.open", Actor: who, Target: target.Hostname,
		AgentID: body.AgentID, Severity: "notice",
		Detail: map[string]any{"session_id": sess.ID, "grant_id": grantID, "reason": body.Reason},
	})
	out := openShellResponse{SessionID: sess.ID, Hostname: target.Hostname, WorkingDir: "/"}
	if expires != nil {
		out.ExpiresAt = expires
	}
	writeJSONResponse(w, out)
}

// shellExecRequest is the body of POST /api/shell/sessions/{id}/exec.
type shellExecRequest struct {
	Command  string `json:"command" api:"required"`
	Takeover bool   `json:"takeover"`
}

func (s *Server) handleShellExec(w http.ResponseWriter, r *http.Request) {
	var body shellExecRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	command := strings.TrimSpace(body.Command)
	if command == "" {
		http.Error(w, "empty command", http.StatusBadRequest)
		return
	}

	sess, err := s.store.GetShellSession(r.Context(), r.PathValue("id"))
	if err != nil || sess == nil {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	if sess.ClosedAt != nil {
		http.Error(w, "that session is closed", http.StatusConflict)
		return
	}
	// A session belongs to whoever opened it: their Jump Gate grant, their
	// management rights, their reason. Anybody else with deploy.manage
	// could otherwise list sessions and run commands in one opened for an
	// endpoint they are not allowed near. An administrator may take a
	// session over, explicitly, and that is audited as such.
	takeover, ok := s.authorizeShellSession(w, r, sess, body.Takeover)
	if !ok {
		return
	}
	// Management rights and the shell action group are re-checked for
	// every command, not only at open: either may have narrowed since.
	if !s.checkTargets(w, r, "shell", []string{sess.AgentID}) {
		return
	}
	// The window is the clock's to answer, not a background job's: a
	// session whose grant has run out must refuse the next command even
	// if the sweeper has not come round yet.
	if sess.ExpiresAt != nil && time.Now().After(*sess.ExpiresAt) {
		_ = s.store.CloseShellSession(r.Context(), sess.ID)
		http.Error(w, "this session's access window has expired", http.StatusForbidden)
		return
	}

	// Logged before it is sent. A command that hangs the agent or takes it
	// down would otherwise leave no trace at all, and that is the one
	// anybody investigating would most want to find.
	who := auth.CurrentUser(r.Context()).Username
	// Fail closed: a root command that could not be written to the
	// transcript and the audit log is not sent.
	logID, err := s.store.RecordShellCommand(r.Context(), sess.ID, sess.AgentID, who, command)
	if err != nil {
		s.logger.Error("recording shell command failed; not sending it", "error", err)
		http.Error(w, "the command could not be recorded, so it was not sent", http.StatusServiceUnavailable)
		return
	}
	s.logger.Info("shell command", "session", sess.ID, "agent_id", sess.AgentID,
		"by", who, "command", command)
	// Root commands on an endpoint are the highest-signal thing in the
	// whole log, so they carry a raised severity — a SIEM filtering on
	// notice-and-above should see every one.
	if err := s.auditStrict(r.Context(), auditEvent{
		Action: "shell.exec", Actor: who, Target: sess.Hostname,
		AgentID: sess.AgentID, Severity: map[bool]string{true: "warning", false: "notice"}[takeover],
		Detail: map[string]any{"session_id": sess.ID, "command": command, "takeover": takeover, "opened_by": sess.OpenedBy},
	}); err != nil {
		_ = s.store.FinishShellCommand(r.Context(), logID, "not sent: audit log unavailable", -1)
		http.Error(w, "the command could not be recorded in the audit log, so it was not sent", http.StatusServiceUnavailable)
		return
	}

	reply, err := s.sendShellCommand(r.Context(), sess.AgentID, proto.ShellRequest{
		SessionID: sess.ID, Command: command, WorkingDir: sess.WorkingDir, TimeoutSec: 60,
	})
	if err != nil {
		_ = s.store.FinishShellCommand(r.Context(), logID, "error: "+err.Error(), -1)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	reply.ExitCode = shellExitCode(reply)
	if logID > 0 {
		_ = s.store.FinishShellCommand(r.Context(), logID, shellLogOutput(reply), reply.ExitCode)
	}
	if reply.WorkingDir != "" && reply.WorkingDir != sess.WorkingDir {
		_ = s.store.SetShellWorkingDir(r.Context(), sess.ID, reply.WorkingDir)
	}
	writeJSONResponse(w, reply)
}

// shellExitCode keeps a command the agent would not run from reading as a
// success in the transcript and the audit log: such a reply has an error and no
// exit code of its own.
func shellExitCode(reply proto.ShellReply) int {
	if reply.Error != "" && reply.ExitCode == 0 {
		return -1
	}
	return reply.ExitCode
}

func shellLogOutput(reply proto.ShellReply) string {
	if reply.Error == "" {
		return reply.Output
	}
	if reply.Output == "" {
		return "error: " + reply.Error
	}
	return reply.Output + "\nerror: " + reply.Error
}

func (s *Server) sendShellCommand(ctx context.Context, agentID string, req proto.ShellRequest) (proto.ShellReply, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return proto.ShellReply{}, err
	}
	// A little longer than the agent's own timeout, so an agent that times
	// a command out gets to say so rather than the server giving up first
	// and reporting a less useful error.
	rctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Shell(agentID), payload)
	if err != nil {
		return proto.ShellReply{}, err
	}
	var reply proto.ShellReply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return proto.ShellReply{}, err
	}
	return reply, nil
}

// shellPrincipal is the stable identity a shell session is bound to.
// Every API token authenticates as the same synthetic user, so a token is
// identified by its own id instead.
func shellPrincipal(ctx context.Context) string {
	if t, ok := auth.Token(ctx); ok {
		return "tok:" + t.ID
	}
	if u := auth.CurrentUser(ctx); u != nil {
		return u.ID
	}
	return ""
}

// authorizeShellSession decides whether the caller may act on sess. The
// opener may; an administrator may when asking to take it over (reported
// as takeover, and audited); nobody else may. Sessions from before openers
// were recorded by id are linked by the schema migration where the
// username still resolves; one that does not has no owner, and only an
// administrator's takeover can use it.
func (s *Server) authorizeShellSession(w http.ResponseWriter, r *http.Request, sess *store.ShellSession, takeover bool) (bool, bool) {
	ctx := r.Context()
	u := auth.CurrentUser(ctx)
	if me := shellPrincipal(ctx); sess.OpenedByID != "" && sess.OpenedByID == me {
		return false, true
	}
	_, isToken := auth.Token(ctx)
	if u != nil && u.IsAdmin && !isToken && takeover {
		if err := s.auditStrict(ctx, auditEvent{
			Action: "shell.takeover", Actor: u.Username, Target: sess.Hostname, AgentID: sess.AgentID,
			Severity: "warning", Detail: map[string]any{"session_id": sess.ID, "opened_by": sess.OpenedBy},
		}); err != nil {
			http.Error(w, "the takeover could not be recorded in the audit log, so it was refused", http.StatusServiceUnavailable)
			return false, false
		}
		return true, true
	}
	s.audit(ctx, auditEvent{Action: "shell.denied", Actor: u.Username, Target: sess.Hostname, AgentID: sess.AgentID,
		Outcome: "denied", Severity: "warning", Detail: map[string]any{"session_id": sess.ID, "opened_by": sess.OpenedBy}})
	msg := "this session belongs to " + sess.OpenedBy + "; open your own session"
	if u != nil && u.IsAdmin && !isToken {
		msg += ", or take it over explicitly (\"takeover\": true), which is audited"
	}
	http.Error(w, msg, http.StatusForbidden)
	return false, false
}

func (s *Server) handleCloseShell(w http.ResponseWriter, r *http.Request) {
	sess, err := s.store.GetShellSession(r.Context(), r.PathValue("id"))
	if err != nil || sess == nil {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	takeover := r.URL.Query().Get("takeover") == "1"
	if _, ok := s.authorizeShellSession(w, r, sess, takeover); !ok {
		return
	}
	s.audit(r.Context(), auditEvent{Action: "shell.close", Actor: auth.CurrentUser(r.Context()).Username,
		Target: sess.Hostname, AgentID: sess.AgentID, Severity: "info", Detail: map[string]any{"session_id": sess.ID}})
	if err := s.store.CloseShellSession(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listShellSessionsResponse is what GET /api/shell/sessions answers.
type listShellSessionsResponse struct {
	Sessions []store.ShellSession `json:"sessions"`
}

func (s *Server) handleListShellSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListShellSessions(r.Context(), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sessions == nil {
		sessions = []store.ShellSession{}
	}
	writeJSONResponse(w, listShellSessionsResponse{Sessions: sessions})
}

// shellAuditResponse is what GET /api/shell/audit answers.
type shellAuditResponse struct {
	Commands []store.ShellCommand `json:"commands"`
}

// handleShellAudit serves the command log — the whole reason this feature
// is defensible. Readable by anyone who can open a shell, deliberately: an
// audit log only one person can read is not much of an audit log.
func (s *Server) handleShellAudit(w http.ResponseWriter, r *http.Request) {
	commands, err := s.store.ListShellCommands(r.Context(), r.URL.Query().Get("session_id"), 300)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if commands == nil {
		commands = []store.ShellCommand{}
	}
	writeJSONResponse(w, shellAuditResponse{Commands: commands})
}
