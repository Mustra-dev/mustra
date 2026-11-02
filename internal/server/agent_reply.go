package server

import (
	"context"
	"strings"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
)

// Answering an agent's request.
//
// The reply subject of a request is chosen by whoever sent it, and
// nats-server does not check it against the requester's permissions: it is
// the responder that publishes there, with the responder's rights. The
// server's connection may publish almost anywhere, so a msg.Respond to an
// unchecked reply let an agent — allowed to publish only on its own
// subjects — have the server publish for it: onto beacon.agent.<another
// agent>.facts (stored in the AGENTS stream and attributed to that agent
// from the subject), into the JetStream API, or into another connection's
// inbox. Every answer to an agent-originated request therefore goes
// through respondToAgent / respondToEnroll, which publish only into an
// inbox the requester's identity owns.

// replyKind says which identity a request arrived under, and so which
// inboxes its reply may go to.
type replyKind int

const (
	// replyAgent: a per-agent subject (beacon.<x>.<id>), published by the
	// enrolled agent <id> or, while legacy is accepted and <id> has never
	// enrolled, by a shared-credential holder.
	replyAgent replyKind = iota
	// replyLegacy: an identity-free legacy subject (beacon.register),
	// published only by shared-credential holders.
	replyLegacy
	// replyEnroll: an enrolment subject, published by a connection whose
	// inbox is _INBOX_ENROLL_<nonce>.
	replyEnroll
)

// legacyInboxPrefix is the default nats.go inbox, which every agent on the
// shared credential (and every agent that predates enrolment) uses.
const legacyInboxPrefix = "_INBOX."

// validReplySubject rejects what is not a plain, literal subject: a
// wildcard or whitespace has no business in an inbox.
func validReplySubject(reply string) bool {
	if reply == "" || strings.ContainsAny(reply, " \t\r\n*>") {
		return false
	}
	for _, tok := range strings.Split(reply, ".") {
		if tok == "" {
			return false
		}
	}
	return true
}

// hasInboxPrefix reports whether reply is prefix followed by at least one
// more token.
func hasInboxPrefix(reply, prefix string) bool {
	return strings.HasPrefix(reply, prefix) && len(reply) > len(prefix)
}

// agentReplyAllowed decides whether the server may publish its answer to
// msg.Reply for a request of the given kind from agentID. It logs a refusal
// at warn, since a well-behaved agent never produces one.
func (s *Server) agentReplyAllowed(ctx context.Context, msg *gonats.Msg, kind replyKind, agentID string) bool {
	reply := msg.Reply
	ok := false
	if validReplySubject(reply) {
		switch kind {
		case replyAgent:
			switch {
			case bnats.ValidAgentID(agentID) && hasInboxPrefix(reply, bnats.AgentInboxPrefix(agentID)+"."):
				ok = true
			case hasInboxPrefix(reply, legacyInboxPrefix):
				ok = s.legacyReplyAccepted(ctx, agentID)
			}
		case replyLegacy:
			ok = hasInboxPrefix(reply, legacyInboxPrefix) && s.legacySubjectsAccepted(ctx)
		case replyEnroll:
			ok = bnats.IsEnrollInbox(reply)
		}
	}
	if !ok && s.logger != nil {
		s.logger.Warn("dropping an agent request whose reply subject is not the requester's own inbox",
			"subject", msg.Subject, "reply", reply, "agent_id", agentID)
	}
	return ok
}

// legacyReplyAccepted reports whether a request on agentID's per-agent
// subject may be answered on the shared "_INBOX." namespace: only from a
// shared-credential holder, so only while legacy is accepted and only for
// an identity that has never enrolled. An enrolled agent always uses its
// own prefix, so "_INBOX." under its ID is somebody else's doing.
func (s *Server) legacyReplyAccepted(ctx context.Context, agentID string) bool {
	if !s.legacySubjectsAccepted(ctx) {
		return false
	}
	if !s.identityEnforced() {
		return true
	}
	enrolled, err := s.store.AgentHasCredential(ctx, agentID)
	if err != nil {
		s.logger.Warn("credential lookup failed; refusing a legacy reply", "agent_id", agentID, "error", err)
		return false
	}
	return !enrolled
}

// respondToAgent is the only way the server answers an agent's request:
// it publishes payload to msg.Reply when that is the requester's own inbox
// and drops it otherwise. It reports whether the reply was sent.
func (s *Server) respondToAgent(ctx context.Context, msg *gonats.Msg, kind replyKind, agentID string, payload []byte) bool {
	if !s.agentReplyAllowed(ctx, msg, kind, agentID) {
		return false
	}
	if err := msg.Respond(payload); err != nil {
		if s.logger != nil {
			s.logger.Warn("respond to agent request failed", "subject", msg.Subject, "agent_id", agentID, "error", err)
		}
		return false
	}
	return true
}
