package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

// Updating agents from the console.
//
// Until this existed an agent could only be updated by somebody standing at
// the machine, clicking Update in its own Self Service window. That is fine
// for a laptop whose owner is looking at it and useless for the rest of a
// fleet, so every rollout came down to ssh, and the endpoints without ssh --
// the Windows desktop, the Mac -- were updated by hand or not at all.
//
// The command carries no installer and no URL. It tells the endpoint to ask
// the server the same question the Self Service button asks, so the version
// comparison, the downgrade guard and the console URL stay in one place
// rather than being reimplemented here and drifting.
//
// It must also never become an ordinary "run this command" dispatch. The
// updater stops the very service that would be running it: launched as a
// child of the agent it dies halfway, leaving an endpoint with no agent and
// no way to be told anything. The agent's own spawnDetachedUpdater is what
// makes this safe, and going through the command channel is what reaches it.

type agentUpdateOutcome struct {
	Hostname string `json:"hostname"`
	AgentID  string `json:"agent_id"`
	OS       string `json:"os"`
	From     string `json:"from"`
	Started  bool   `json:"started"`
	Detail   string `json:"detail,omitempty"`
}

// updateAgent asks one endpoint to update itself and reports what it said.
//
// With downgrade set, the command carries the update itself, under a
// manifest signed for this one agent that authorizes moving it back to the
// build this server serves. The agent refuses an older build on any other
// terms, so this is the only way an endpoint goes backwards, and it is an
// explicit operator act, audited as such.
func (s *Server) updateAgent(ctx context.Context, a store.AgentRecord) agentUpdateOutcome {
	return s.updateAgentWith(ctx, a, false)
}

// updateResend is how long an endpoint that was just asked to update is
// left alone. Two overlapping "update all" requests (a double click, or a
// click while an API call ran) each asked the same agent, and agents
// before 0.57.4 ran two updaters that between them deleted the binary.
const updateResend = 3 * time.Minute

func (s *Server) updateAgentWith(ctx context.Context, a store.AgentRecord, downgrade bool) agentUpdateOutcome {
	out := agentUpdateOutcome{Hostname: a.Hostname, AgentID: a.AgentID, OS: a.OS, From: a.AgentVersion}
	now := time.Now()
	if prev, loaded := s.updateSent.LoadOrStore(a.AgentID, now); loaded {
		if since := now.Sub(prev.(time.Time)); since < updateResend {
			out.Detail = fmt.Sprintf("already asked to update %s ago; it may still be applying", since.Round(time.Second))
			return out
		}
		s.updateSent.Store(a.AgentID, now)
	}
	sent := false
	defer func() {
		// Only a request the agent accepted holds the slot; a failure can
		// be retried at once.
		if !sent {
			s.updateSent.CompareAndDelete(a.AgentID, now)
		}
	}()
	cmd := proto.AgentCommand{Cmd: "update_agent"}
	if downgrade {
		offer, err := s.updateOfferFor(ctx, a.OS, a.Arch, a.AgentID)
		if err != nil {
			out.Detail = err.Error()
			return out
		}
		cmd.Update = offer
	}
	payload, err := json.Marshal(cmd)
	if err != nil {
		out.Detail = err.Error()
		return out
	}
	// Short: the agent answers as soon as it has *started* the detached
	// updater, not when the update finishes. Waiting for the latter would
	// mean waiting for a service that is about to restart from under the
	// reply.
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(a.AgentID), payload)
	if errors.Is(err, nats.ErrNoResponders) {
		// Nothing is subscribed for this agent right now. Usually it is
		// mid-restart -- often from an update already asked for -- and the
		// console still shows it online until the next heartbeat is missed.
		out.Detail = "not connected right now; it may be restarting from an update already in progress"
		return out
	}
	if err != nil {
		out.Detail = "did not respond: " + err.Error()
		return out
	}
	var result proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		out.Detail = "unreadable reply: " + err.Error()
		return out
	}
	// An agent too old to know the command answers "unknown command", which
	// is worth saying plainly: it is the one case the operator can fix only
	// by reaching the machine some other way.
	if !result.OK {
		out.Detail = result.Error
		return out
	}
	sent = true
	out.Started, out.Detail = true, result.Output
	return out
}

// updateAgentsResponse is what POST /api/agents/update-outdated and POST
// /api/agents/{id}/update answer.
type updateAgentsResponse struct {
	Asked   int                  `json:"asked"`
	Results []agentUpdateOutcome `json:"results"`
	Serving string               `json:"serving"`
	Started int                  `json:"started"`
}

func (s *Server) handleUpdateAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	serving := version.Agent()
	id := r.PathValue("id")
	downgrade := id != "" && r.URL.Query().Get("allow_downgrade") == "1"
	var targets []store.AgentRecord
	for _, a := range agents {
		if !a.Online {
			continue
		}
		if id != "" {
			if a.AgentID == id {
				targets = append(targets, a)
			}
			continue
		}
		// Fleet-wide means every endpoint actually behind. Asking a current
		// one to update is not harmful -- the server refuses it -- but it
		// fills the result with noise the operator has to read past.
		if versionIsNewer(serving, a.AgentVersion) {
			targets = append(targets, a)
		}
	}
	if id != "" && len(targets) == 0 {
		http.Error(w, "no such endpoint, or it is offline", http.StatusNotFound)
		return
	}

	results := make([]agentUpdateOutcome, len(targets))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target store.AgentRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = s.updateAgentWith(r.Context(), target, downgrade)
		}(i, target)
	}
	wg.Wait()

	started := 0
	for _, res := range results {
		if res.Started {
			started++
		}
	}
	s.audit(r.Context(), auditEvent{
		Action: "agent.update", Actor: auth.CurrentUser(r.Context()).Username,
		Target: firstNonEmptyString(id, "outdated endpoints"), Severity: "notice",
		Detail: map[string]any{"to": serving, "asked": len(targets), "started": started, "downgrade": downgrade},
	})
	writeJSONResponse(w, updateAgentsResponse{
		Serving: serving, Asked: len(targets), Started: started, Results: results,
	})
}

func firstNonEmptyString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
