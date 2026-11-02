package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/updatesig"
)

// Issuing agent credentials over the bus.
//
// Both subjects are reachable only by an enrolment connection the auth
// callout admitted (natsauth_callout.go): EnrollToken with a valid
// enrollment token, EnrollLegacy with the shared password while it is
// allowed. Each such connection reads replies on an inbox no other
// connection may subscribe to, because the reply carries the secret.

func newAgentSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) respondEnroll(ctx context.Context, msg *gonats.Msg, resp proto.EnrollResponse) {
	if payload, err := json.Marshal(resp); err == nil {
		s.respondToAgent(ctx, msg, replyEnroll, "", payload)
	}
}

func (s *Server) enrollResponse(agentID, secret string) proto.EnrollResponse {
	resp := proto.EnrollResponse{OK: true, AgentID: agentID, Secret: secret}
	if s.trust != nil && s.trust.signPub != nil {
		resp.UpdateSigningKey = updatesig.EncodePublicKey(s.trust.signPub)
	}
	return resp
}

func (s *Server) subscribeEnrollToken(ctx context.Context) (*gonats.Subscription, error) {
	return s.nc.Subscribe(bnats.EnrollToken(), func(msg *gonats.Msg) {
		// Checked before the token is spent: a request whose answer could
		// not be delivered to the requester must not use up an enrolment.
		if !s.agentReplyAllowed(ctx, msg, replyEnroll, "") {
			return
		}
		var req proto.EnrollRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil || req.Token == "" {
			s.respondEnroll(ctx, msg, proto.EnrollResponse{Error: "malformed enrolment request"})
			return
		}
		// The prior ID an agent offers is not used: anyone holding a token
		// could name any agent's ID (see EnrollWithToken). A token always
		// issues a fresh identity.
		secret := newAgentSecret()
		agentID, tok, err := s.store.EnrollWithToken(ctx, hashToken(req.Token), "", newID("agt-"), hashToken(secret))
		if err != nil {
			if !errors.Is(err, store.ErrTokenUnusable) {
				s.logger.Error("enrolment failed", "error", err)
			}
			s.respondEnroll(ctx, msg, proto.EnrollResponse{Error: "enrollment token is not valid"})
			return
		}
		s.audit(ctx, auditEvent{
			Action: "agent.enroll", Actor: "token:" + tok.ID, Target: firstNonEmptyString(req.Info.Hostname, agentID),
			AgentID: agentID, Severity: "notice",
			Detail: map[string]any{"via": "token", "token": tok.Label, "offered_prior_identity": bnats.ValidAgentID(req.PriorAgentID),
				"os": req.Info.OS},
		})
		s.logger.Info("agent enrolled", "agent_id", agentID, "hostname", req.Info.Hostname, "token_id", tok.ID)
		s.respondEnroll(ctx, msg, s.enrollResponse(agentID, secret))
	})
}

func (s *Server) subscribeEnrollLegacy(ctx context.Context) (*gonats.Subscription, error) {
	return s.nc.Subscribe(bnats.EnrollLegacy(), func(msg *gonats.Msg) {
		if !s.agentReplyAllowed(ctx, msg, replyEnroll, "") {
			return
		}
		// Re-checked here as well as in the callout: an enrolment
		// connection admitted a minute before the toggle was switched off
		// must not still get an identity out of it.
		if s.identityEnforced() {
			s.respondEnroll(ctx, msg, proto.EnrollResponse{Error: "the legacy shared credential is no longer accepted; re-enroll with a token"})
			return
		}
		var req proto.EnrollRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			s.respondEnroll(ctx, msg, proto.EnrollResponse{Error: "malformed enrolment request"})
			return
		}
		prior := req.PriorAgentID
		if !bnats.ValidAgentID(prior) {
			prior = ""
		}
		secret := newAgentSecret()
		agentID, err := s.store.EnrollLegacy(ctx, prior, newID("agt-"), hashToken(secret))
		if errors.Is(err, store.ErrIdentityEnrolled) {
			// Either this endpoint lost its credential file, or somebody
			// holding the shared password is trying to take over an
			// identity that has already moved to its own credential.
			// Neither is answered with that identity.
			s.logger.Warn("legacy enrolment for an already-enrolled identity refused", "agent_id", prior,
				"hostname", req.Info.Hostname)
			s.respondEnroll(ctx, msg, proto.EnrollResponse{Error: "this identity is already enrolled; re-enroll the endpoint with a token"})
			return
		}
		if err != nil {
			s.logger.Error("legacy enrolment failed", "error", err)
			s.respondEnroll(ctx, msg, proto.EnrollResponse{Error: "enrolment failed"})
			return
		}
		s.audit(ctx, auditEvent{
			Action: "agent.enroll", Actor: "legacy-credential", Target: firstNonEmptyString(req.Info.Hostname, agentID),
			AgentID: agentID, Severity: "notice", Detail: map[string]any{"via": "legacy", "os": req.Info.OS},
		})
		s.logger.Info("agent moved from the shared credential to its own", "agent_id", agentID, "hostname", req.Info.Hostname)
		s.respondEnroll(ctx, msg, s.enrollResponse(agentID, secret))
	})
}
