package server

// Shadowing a Windows session: seeing what the signed-in person sees,
// with their permission.
//
// Remote Desktop to a Windows workstation takes the console over: the
// person using it is signed out the moment the operator connects, which
// is the wrong tool for "show me what you are seeing". Remote Desktop
// Services has the right one built in. A shadow connection
// (mstsc /shadow) attaches to a session that is already signed in, and
// Windows asks the person in that session whether to allow it, viewing
// or control, before anything is shown. Nobody is signed out, no account
// is made, and the person can end it.
//
// Mustra's part is what it is for every other way in: deciding who may
// reach what (management rights, the shell action group, Jump Gate),
// finding the session (the users sensor reports each Windows session's
// id and state), and recording the connection. The connection itself is
// the operator's own Remote Desktop client, so this answers with the
// command rather than a URL; no provider is involved and none is needed.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
)

// shadowSession is one Windows session the endpoint reported.
type shadowSession struct {
	SessionID int    `json:"session_id"`
	User      string `json:"user"`
	Terminal  string `json:"terminal,omitempty"`
	State     string `json:"state,omitempty"`
}

// shadowCommand is the Remote Desktop client invocation. /prompt makes
// the client ask for the operator's credentials rather than reusing any
// it has saved for the host; /control asks for control, and without it
// the session is only viewed. Windows then asks the person signed in.
func shadowCommand(addr string, sessionID int, control bool) string {
	cmd := fmt.Sprintf("mstsc.exe /v:%s /shadow:%d /prompt", addr, sessionID)
	if control {
		cmd += " /control"
	}
	return cmd
}

// shadowSessions reads the Windows sessions the endpoint last reported.
// agentTooOld is true when the report has no session ids at all: an
// agent before 0.57.42 does not send them.
func (s *Server) shadowSessions(r *http.Request, agentID string) (sessions []shadowSession, reportedAt *time.Time, agentTooOld bool, err error) {
	rec, err := s.store.GetSensorData(r.Context(), agentID, string(proto.SensorUsers))
	if err != nil || rec == nil {
		return nil, nil, false, err
	}
	var users []proto.LoggedInUser
	if err := json.Unmarshal(rec.Data, &users); err != nil {
		return nil, nil, false, nil
	}
	at := rec.CollectedAt
	withID := 0
	for _, u := range users {
		if u.SessionID > 0 {
			withID++
		}
		sessions = append(sessions, shadowSession{SessionID: u.SessionID, User: u.User, Terminal: u.Terminal, State: u.State})
	}
	return sessions, &at, len(users) > 0 && withID == 0, nil
}

// pickShadowSession chooses the session to shadow: the one asked for, or
// the active one (the console first).
func pickShadowSession(sessions []shadowSession, want int) (shadowSession, bool) {
	if want > 0 {
		for _, ss := range sessions {
			if ss.SessionID == want {
				return ss, true
			}
		}
		return shadowSession{}, false
	}
	var pick shadowSession
	for _, ss := range sessions {
		if ss.SessionID <= 0 || !strings.EqualFold(ss.State, "active") {
			continue
		}
		if pick.SessionID == 0 || strings.EqualFold(ss.Terminal, "console") {
			pick = ss
		}
	}
	return pick, pick.SessionID > 0
}

// openShadow answers POST /api/remote/sessions for protocol "shadow".
func (s *Server) openShadow(w http.ResponseWriter, r *http.Request, body openRemoteRequest) {
	target := s.agentByID(r.Context(), body.AgentID)
	if target == nil {
		http.Error(w, "no such endpoint", http.StatusNotFound)
		return
	}
	if target.OS != "windows" || target.Platform == "haos" {
		http.Error(w, fmt.Sprintf("shadowing is for Windows sessions; %s is not a Windows endpoint", target.Hostname), http.StatusBadRequest)
		return
	}
	if body.SessionID < 0 {
		http.Error(w, "session_id must be a Windows session number", http.StatusBadRequest)
		return
	}
	if !s.checkTargets(w, r, "shell", []string{target.AgentID}) {
		return
	}
	allowed, grantID, expires := s.jumpGate(w, r, target.AgentID, target.Hostname, body.Reason)
	if !allowed {
		return
	}
	sessions, reportedAt, tooOld, err := s.shadowSessions(r, target.AgentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tooOld && body.SessionID == 0 {
		http.Error(w, fmt.Sprintf("%s's agent (%s) does not report Windows session ids; update it, or give the session id (quser on the endpoint lists them)",
			target.Hostname, firstNonEmptyString(target.AgentVersion, "unknown version")), http.StatusConflict)
		return
	}
	pick, ok := pickShadowSession(sessions, body.SessionID)
	switch {
	case !ok && body.SessionID > 0:
		// Named explicitly: trusted, since quser's numbering is the
		// operator's to read, and the endpoint's report may be stale.
		pick = shadowSession{SessionID: body.SessionID}
	case !ok:
		http.Error(w, fmt.Sprintf("nobody is signed in on %s as of its last report, and a shadow needs a signed-in session", target.Hostname), http.StatusConflict)
		return
	}
	addr := remoteAddress(*target)
	who := auth.CurrentUser(r.Context()).Username
	cmd := shadowCommand(addr, pick.SessionID, body.Control)
	s.audit(r.Context(), auditEvent{
		Action: "remote.open", Actor: who, Target: target.Hostname, AgentID: target.AgentID, Severity: "notice",
		Detail: map[string]any{"protocol": "shadow", "address": addr, "provider": "shadow", "grant_id": grantID, "reason": body.Reason,
			"session_id": pick.SessionID, "session_user": pick.User, "control": body.Control},
	})
	others := make([]shadowSession, 0, len(sessions))
	for _, ss := range sessions {
		if ss.SessionID > 0 && ss.SessionID != pick.SessionID {
			others = append(others, ss)
		}
	}
	out := openRemoteResponse{Provider: "shadow", Address: addr, Command: cmd, SessionID: pick.SessionID,
		SessionUser: pick.User, Control: body.Control, Sessions: others, ReportedAt: reportedAt}
	if expires != nil {
		out.ExpiresAt = expires
	}
	writeJSONResponse(w, out)
}
