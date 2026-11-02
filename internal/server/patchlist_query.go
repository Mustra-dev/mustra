package server

import (
	"context"
	"encoding/json"
	"strings"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// subscribePatchListQueries answers an agent's "what repos should I scope
// my patch scan/apply to" request — the agent-initiated counterpart to
// subscribeRegister, since this is driven by the agent's own sensor timer
// rather than something the server pushes. One wildcard subscription
// covers every agent; the agent ID comes off the end of the subject.
func (s *Server) subscribePatchListQueries(ctx context.Context) (*gonats.Subscription, error) {
	return s.nc.Subscribe(bnats.PatchListQueryWildcard(), func(msg *gonats.Msg) {
		agentID := strings.TrimPrefix(msg.Subject, "beacon.patchlist.")
		if agentID == "" || agentID == msg.Subject {
			return
		}
		if !s.agentReplyAllowed(ctx, msg, replyAgent, agentID) {
			return
		}

		platform, site, err := s.store.GetAgentPlatformSite(ctx, agentID)
		if err != nil {
			// Unknown agent, or a transient DB hiccup — either way, reply
			// empty (native repos) rather than leaving the agent hanging
			// until its request times out.
			s.logger.Warn("patch list query for unresolvable agent", "agent_id", agentID, "error", err)
			s.respondPatchList(ctx, msg, agentID, proto.PatchListReply{})
			return
		}

		pl, err := s.store.ResolvePatchListForAgent(ctx, agentID, platform, site)
		if err != nil {
			s.logger.Warn("resolve patch list failed", "agent_id", agentID, "error", err)
			s.respondPatchList(ctx, msg, agentID, proto.PatchListReply{})
			return
		}
		if pl == nil {
			s.respondPatchList(ctx, msg, agentID, proto.PatchListReply{})
			return
		}
		repos := splitRepoLines(pl.Repos)
		s.respondPatchList(ctx, msg, agentID, proto.PatchListReply{OSFamily: pl.OSFamily, Repos: repos})
	})
}

func (s *Server) respondPatchList(ctx context.Context, msg *gonats.Msg, agentID string, reply proto.PatchListReply) {
	payload, err := json.Marshal(reply)
	if err != nil {
		return
	}
	s.respondToAgent(ctx, msg, replyAgent, agentID, payload)
}

// splitRepoLines turns the newline-separated repos field into a clean
// slice — blank lines and stray whitespace dropped, since these are
// hand-edited in a textarea.
func splitRepoLines(raw string) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}
