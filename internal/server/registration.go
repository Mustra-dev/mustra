package server

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"strings"
	"sync"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// Registration binds an inventory row to an identity.
//
// An enrolled agent registers on beacon.register.<its id>, a subject the
// broker lets only that agent publish on, so the ID comes from the subject
// and the body cannot claim another. The old beacon.register carries no
// identity at all — whoever publishes there names any ID they like — so it
// is accepted only from agents still on the legacy shared credential, only
// while that is allowed, and never for an ID that has its own credential.
// Request/reply on core NATS: a lost registration is retried by the agent.

// subscribeRegister answers the legacy, identity-free subject.
func (s *Server) subscribeRegister(ctx context.Context) (*gonats.Subscription, error) {
	return s.nc.Subscribe(bnats.Register(), func(msg *gonats.Msg) {
		var req proto.RegisterRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			s.logger.Warn("discarding malformed register request", "error", err)
			return
		}
		if !s.legacySubjectsAccepted(ctx) {
			// The broker should not have admitted a publisher here at all
			// once legacy is off; drop rather than trust that.
			s.logger.Warn("legacy registration refused: the shared credential is not allowed", "agent_id", req.AgentID)
			return
		}
		// Before anything is written: the answer may only go to the
		// shared-credential inbox this subject's publishers use.
		if !s.agentReplyAllowed(ctx, msg, replyLegacy, req.AgentID) {
			return
		}
		agentID := req.AgentID
		if !bnats.ValidAgentID(agentID) {
			if agentID != "" {
				s.logger.Warn("legacy registration presented a malformed agent id; issuing a new one", "presented", agentID)
			}
			agentID = newID("agt-")
		}
		if s.identityEnforced() {
			enrolled, err := s.store.AgentHasCredential(ctx, agentID)
			if err != nil {
				s.logger.Error("credential lookup failed", "error", err)
				return
			}
			if enrolled {
				s.logger.Warn("legacy registration for an enrolled identity refused", "agent_id", agentID,
					"hostname", req.Info.Hostname)
				return
			}
			if err := s.store.RecordLegacySeen(ctx, agentID); err != nil {
				s.logger.Debug("record legacy registration failed", "agent_id", agentID, "error", err)
			}
		}
		s.completeRegistration(ctx, msg, replyLegacy, agentID, req.Info)
	})
}

// subscribeRegisterAgent answers the per-agent subject.
func (s *Server) subscribeRegisterAgent(ctx context.Context) (*gonats.Subscription, error) {
	// Registrations of different agents are independent, and a fleet
	// reconnecting together registers together: decided in parallel, like
	// the auth callout that admitted them (boundedHandler).
	return s.nc.Subscribe(bnats.RegisterAgentWildcard(), boundedHandler(registerWorkers, func(msg *gonats.Msg) {
		agentID := strings.TrimPrefix(msg.Subject, bnats.Register()+".")
		if !bnats.ValidAgentID(agentID) {
			return
		}
		if !s.agentReplyAllowed(ctx, msg, replyAgent, agentID) {
			return
		}
		var req proto.RegisterRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			s.logger.Warn("discarding malformed register request", "error", err)
			return
		}
		if req.AgentID != "" && req.AgentID != agentID {
			s.logger.Warn("registration body names a different agent than its subject; using the subject",
				"subject_agent", agentID, "claimed", req.AgentID)
		}
		// One agent's registrations stay in order (a retry can overlap a
		// slow first attempt); only different agents run side by side.
		mu := &registerStripes[stripeOf(agentID)]
		mu.Lock()
		defer mu.Unlock()
		s.completeRegistration(ctx, msg, replyAgent, agentID, req.Info)
	}))
}

// registerWorkers bounds concurrent registrations; each holds a database
// connection for two writes.
const registerWorkers = 8

var registerStripes [64]sync.Mutex

func stripeOf(agentID string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(agentID))
	return int(h.Sum32() % uint32(len(registerStripes)))
}

func (s *Server) completeRegistration(ctx context.Context, msg *gonats.Msg, kind replyKind, agentID string, info proto.AgentInfo) {
	info.Site = sanitizeSite(info.Site)
	if err := s.store.UpsertOnRegister(ctx, agentID, info); err != nil {
		s.logger.Error("upsert on register failed", "error", err, "agent_id", agentID)
		return
	}
	// Version transitions are what make a rollout observable; recorded
	// here because registration is the first thing a freshly upgraded
	// agent does.
	if err := s.store.RecordAgentVersion(ctx, agentID, info.Version); err != nil {
		s.logger.Warn("record agent version failed", "agent_id", agentID, "error", err)
	}
	// An agent registers once per start, so whatever it was still running
	// died with the previous process: say so instead of "installing" forever.
	if lost, err := s.store.InterruptAgentActions(ctx, agentID); err != nil {
		s.logger.Warn("closing interrupted actions failed", "agent_id", agentID, "error", err)
	} else if len(lost) > 0 {
		kinds := make([]string, 0, len(lost))
		for _, a := range lost {
			kinds = append(kinds, a.Kind)
		}
		s.logger.Info("actions interrupted by an agent restart", "agent_id", agentID, "hostname", info.Hostname, "count", len(lost))
		s.audit(ctx, auditEvent{Action: "agent.actions_interrupted", Actor: "system", Target: info.Hostname, AgentID: agentID, Severity: "notice",
			Detail: map[string]any{"actions": kinds}})
		for _, a := range lost {
			// Runs also carry notices and surveys, which are not "completed".
			if a.Kind == "patch_apply" {
				s.announceRunCompleted(ctx, a.RunID)
			}
		}
	}
	payload, err := json.Marshal(proto.RegisterResponse{AgentID: agentID})
	if err != nil {
		s.logger.Error("marshal register response failed", "error", err)
		return
	}
	if !s.respondToAgent(ctx, msg, kind, agentID, payload) {
		return
	}
	s.logger.Info("agent registered", "agent_id", agentID, "hostname", info.Hostname, "os", info.OS, "site", info.Site)
	s.refreshAgentHub(ctx)
}
