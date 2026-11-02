package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// End-user notifications: sending a message to the people at the endpoints.
//
// Sending one creates a deployment, exactly like pushing a patch or a
// package. That is not tidiness for its own sake — "who did we tell, and
// what did they say" is the same question as "who did we patch, and did it
// work", and answering it in a second place with a second shape means two
// things to look at when somebody asks why a machine rebooted.

// maxEUNButtons is a rendering limit rather than a data one: the Self
// Service window lays the choices out in a row, and a person handed nine
// buttons is being asked to read rather than to answer.
const maxEUNButtons = 6

// cleanEUNButtons validates operator-defined buttons and returns them
// trimmed, or an error naming what is wrong in the words the person editing
// the message would use.
//
// The rules exist because a notification is the one screen in this product
// aimed at somebody who did not choose to use it. A message with no way to
// dismiss it is not a strict configuration, it is a window a person cannot
// close.
func cleanEUNButtons(m store.EUNMessage) ([]proto.EUNButton, error) {
	if len(m.Buttons) == 0 {
		return []proto.EUNButton{}, nil
	}
	if len(m.Buttons) > maxEUNButtons {
		return nil, fmt.Errorf("a notification may have at most %d buttons", maxEUNButtons)
	}
	out := make([]proto.EUNButton, 0, len(m.Buttons))
	primaries, dismissals := 0, 0
	for _, b := range m.Buttons {
		b.Label = strings.TrimSpace(b.Label)
		if b.Label == "" {
			return nil, fmt.Errorf("every button needs a label")
		}
		if len([]rune(b.Label)) > 40 {
			return nil, fmt.Errorf("button labels are limited to 40 characters: %q", b.Label)
		}
		switch b.Action {
		case proto.EUNActionAcknowledged:
			dismissals++
			b.Minutes = 0
		case proto.EUNActionRestartNow:
			if m.Kind != store.EUNRestart {
				return nil, fmt.Errorf("%q restarts the machine, so it only belongs on a restart message", b.Label)
			}
			dismissals++
			b.Minutes = 0
		case proto.EUNActionPostponed:
			if m.Kind != store.EUNRestart || !m.AllowPostpone {
				return nil, fmt.Errorf("%q postpones, which needs a restart message with postponement allowed", b.Label)
			}
			if b.Minutes <= 0 {
				return nil, fmt.Errorf("%q needs to say how long it postpones for", b.Label)
			}
		default:
			return nil, fmt.Errorf("unknown button action %q", b.Action)
		}
		if b.Primary {
			primaries++
		}
		out = append(out, b)
	}
	if dismissals == 0 {
		return nil, fmt.Errorf("at least one button has to dismiss the message, or nobody can close it")
	}
	if primaries > 1 {
		return nil, fmt.Errorf("only one button can be the primary one")
	}
	return out, nil
}

// eunToProto is the one place a stored message becomes a wire notification.
// It was written twice, in the send handler and in the playbook step, and a
// field added to one of them reached endpoints from one path and not the
// other.
func eunToProto(msg store.EUNMessage) proto.EndUserNotification {
	return proto.EndUserNotification{
		ID: msg.ID, Kind: msg.Kind, Title: msg.Title, Body: msg.Body,
		Deadline: msg.DeadlineAt, AllowPostpone: msg.AllowPostpone,
		CountdownMinutes: msg.CountdownMinutes, GentleMinutes: msg.GentleMinutes,
		PostponeMinutes: msg.PostponeMinutes, Buttons: msg.Buttons,
	}
}

// listEUNResponse is what GET /api/eun answers.
type listEUNResponse struct {
	Messages []store.EUNMessage `json:"messages"`
}

func (s *Server) handleListEUN(w http.ResponseWriter, r *http.Request) {
	msgs, err := s.store.ListEUNMessages(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if msgs == nil {
		msgs = []store.EUNMessage{}
	}
	writeJSONResponse(w, listEUNResponse{Messages: msgs})
}

func (s *Server) handleUpsertEUN(w http.ResponseWriter, r *http.Request) {
	var body store.EUNMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// The path decides which record is written: a POST creates one under an
	// ID minted here, whatever the body says, and a PUT updates the one it
	// names and keeps its creator. A body ID once let a create rewrite an
	// existing message and store the body's created_by as its creator.
	if id := r.PathValue("id"); id != "" {
		old, err := s.store.GetEUNMessage(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if old == nil {
			http.Error(w, "no such notification", http.StatusNotFound)
			return
		}
		body.ID, body.CreatedBy = id, old.CreatedBy
	} else {
		body.ID = idgen.New("eun-")
		body.CreatedBy = auth.CurrentUser(r.Context()).Username
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Title = strings.TrimSpace(body.Title)
	if body.Name == "" || body.Title == "" {
		http.Error(w, "a name and a title are required", http.StatusBadRequest)
		return
	}
	if body.Kind != store.EUNRestart {
		body.Kind = store.EUNNotice
	}
	// A notice has nothing to postpone — it is not asking for anything — so
	// carrying restart machinery on one would only ever confuse the person
	// editing it.
	if body.Kind == store.EUNNotice {
		body.AllowPostpone = false
		body.PostponeMinutes = nil
	}
	if body.CountdownMinutes <= 0 {
		body.CountdownMinutes = 15
	}
	if body.GentleMinutes <= 0 {
		body.GentleMinutes = 60
	}
	cleaned := make([]int, 0, len(body.PostponeMinutes))
	for _, m := range body.PostponeMinutes {
		if m > 0 {
			cleaned = append(cleaned, m)
		}
	}
	body.PostponeMinutes = cleaned

	buttons, err := cleanEUNButtons(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body.Buttons = buttons

	out, err := s.store.UpsertEUNMessage(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "eun.save", Actor: auth.CurrentUser(r.Context()).Username,
		Target: out.Name, Severity: "notice", Detail: map[string]any{"kind": out.Kind},
	})
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteEUN(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteEUNMessage(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type eunSendRequest struct {
	AgentIDs []string `json:"agent_ids"` // empty means every online endpoint
}

// sendEUNResponse is what POST /api/eun/{id}/send answers.
type sendEUNResponse struct {
	Message string `json:"message"`
	RunID   string `json:"run_id"`
	Targets int    `json:"targets"`
}

// handleSendEUN delivers a message to the target and records it as a
// deployment, so the answers land in the same place as every other endpoint
// outcome.
func (s *Server) handleSendEUN(w http.ResponseWriter, r *http.Request) {
	msg, err := s.store.GetEUNMessage(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if msg == nil {
		http.Error(w, "no such message", http.StatusNotFound)
		return
	}
	var req eunSendRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
	}

	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	want := map[string]bool{}
	for _, id := range req.AgentIDs {
		want[id] = true
	}
	var targets []store.AgentRecord
	for _, a := range agents {
		if len(want) > 0 && !want[a.AgentID] {
			continue
		}
		// Offline endpoints are skipped rather than queued: a notice is
		// about something happening now, and one that arrives whenever the
		// laptop next wakes is worse than none.
		if !a.Online {
			continue
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		http.Error(w, "no online endpoints match that target", http.StatusBadRequest)
		return
	}

	who := auth.CurrentUser(r.Context()).Username
	runID := idgen.New("run-")
	desc := "end-user notification: " + msg.Name
	if err := s.store.RecordPatchJobRun(r.Context(), store.PatchJobRun{
		ID: runID, TargetDesc: desc, AgentCount: len(targets),
		ScheduleName: msg.Title, TriggeredBy: who,
	}); err != nil {
		s.logger.Warn("record notification run failed", "error", err)
	}

	go s.deliverEUN(context.WithoutCancel(r.Context()), *msg, targets, runID, who)

	s.audit(r.Context(), auditEvent{
		Action: "eun.send", Actor: who, Target: msg.Name, Severity: "notice",
		Detail: map[string]any{"run_id": runID, "endpoints": len(targets), "kind": msg.Kind},
	})
	writeJSONResponse(w, sendEUNResponse{
		RunID: runID, Targets: len(targets),
		Message: "sent to " + strconv.Itoa(len(targets)) + " endpoint(s)",
	})
}

func (s *Server) deliverEUN(ctx context.Context, msg store.EUNMessage,
	targets []store.AgentRecord, runID, who string) {

	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(agentID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			actionID := idgen.New("act-")
			if err := s.store.StartAgentAction(ctx, store.AgentAction{
				ID: actionID, RunID: runID, AgentID: agentID, Kind: "end_user_notification",
				Summary: msg.Title, RequestedBy: who,
			}); err != nil {
				s.logger.Warn("record notification action failed", "agent_id", agentID, "error", err)
			}

			n := eunToProto(msg)
			payload, err := json.Marshal(proto.AgentCommand{
				Cmd: "notify_user", Notify: &n, RunID: runID, ActionID: actionID,
			})
			if err != nil {
				return
			}

			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			reply, err := s.nc.RequestWithContext(rctx, bnats.Cmd(agentID), payload)
			if err != nil {
				_ = s.store.FinishAgentAction(ctx, agentID, actionID, "failed", "did not respond: "+err.Error())
				return
			}
			var res proto.AgentCommandResult
			if err := json.Unmarshal(reply.Data, &res); err != nil || !res.OK {
				detail := "malformed response"
				if res.Error != "" {
					detail = res.Error
				}
				_ = s.store.FinishAgentAction(ctx, agentID, actionID, "failed", detail)
				return
			}
			// Deliberately left open. The endpoint HAS the message; the
			// person has not answered it. Closing here would record
			// "delivered" as if it were "read", which is the same mistake
			// that made every patch apply look instantly successful.
		}(target.AgentID)
	}
	wg.Wait()
}
