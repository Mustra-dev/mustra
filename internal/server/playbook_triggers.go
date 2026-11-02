package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// What starts a playbook, other than a clock: a Guide item being raised, or
// an outside system posting to a URL.
//
// The whole difficulty here is restraint. A trigger is a loaded gun pointed
// at the fleet by something that is not a person, so every question is
// "what happens on the worst day", not "does it fire".

const (
	// triggerMinCooldown is the floor under a trigger's own cooldown. A
	// vulnerability feed refresh raises hundreds of Guide items in the same
	// second; without a cooldown that is hundreds of attempts to launch the
	// same playbook, and the one that gets through is arbitrary.
	triggerMinCooldown = 60
	// approvalDefaultHours bounds a gate nobody decides. An approval that
	// sat for three days is not an approval of today's fleet.
	approvalDefaultHours = 24
	approvalMaxHours     = 168
)

// playbooksSource is the Guide source playbooks themselves publish under.
// An event trigger never fires on it, because a playbook that raises a
// notification which starts a playbook is a loop that runs until somebody
// notices — and the fleet is what it runs on while nobody does.
const playbooksSource = "Playbooks"

// --- event triggers ---------------------------------------------------

// fireEventTriggers is called after a Guide notification is raised. It is
// deliberately best-effort and never blocks the notification: a trigger
// that cannot start must not stop the operator being told.
func (s *Server) fireEventTriggers(ctx context.Context, n store.Notification) {
	if n.Source == playbooksSource {
		return
	}
	triggers, err := s.store.ListPlaybookTriggers(ctx)
	if err != nil {
		s.logger.Warn("could not read playbook triggers", "error", err)
		return
	}
	for _, t := range triggers {
		if t.Kind != store.TriggerEvent || !t.Enabled || !eventMatches(t, n) {
			continue
		}
		detail := fmt.Sprintf("%s: %s", n.Source, n.Title)
		claimed, err := s.store.ClaimPlaybookTrigger(ctx, t.ID, detail)
		if err != nil {
			s.logger.Warn("could not claim a playbook trigger", "trigger", t.ID, "error", err)
			continue
		}
		if !claimed {
			// Inside its cooldown, or another event won the race. Both are
			// the trigger working, not failing.
			continue
		}
		s.startTriggeredPlaybook(ctx, t, detail)
	}
}

// eventMatches decides whether a Guide item is the thing this trigger
// watches for. Every empty field means "any" — which makes a trigger with
// nothing set fire on everything, so the console makes that explicit
// rather than letting somebody arrive at it by leaving fields blank.
func eventMatches(t store.PlaybookTrigger, n store.Notification) bool {
	if t.Source != "" && !strings.EqualFold(t.Source, n.Source) {
		return false
	}
	if t.Severity != "" && !strings.EqualFold(t.Severity, n.Severity) {
		return false
	}
	if t.TitleMatch != "" && !strings.Contains(strings.ToLower(n.Title), strings.ToLower(t.TitleMatch)) {
		return false
	}
	return true
}

// startTriggeredPlaybook launches the playbook a trigger points at. The
// actor recorded is the trigger, not a person: "who ran this" must not
// name somebody who was asleep.
func (s *Server) startTriggeredPlaybook(ctx context.Context, t store.PlaybookTrigger, detail string) {
	pb, err := s.store.GetPlaybook(ctx, t.PlaybookID)
	if err != nil || pb == nil {
		s.logger.Warn("playbook trigger points at a playbook that is gone", "trigger", t.ID)
		return
	}
	if !pb.Enabled {
		s.logger.Info("playbook trigger skipped: the playbook is disabled",
			"trigger", t.ID, "playbook", pb.Name)
		return
	}
	who := "trigger:" + t.Kind
	runID, targets, err := s.launchPlaybook(ctx, *pb, who)
	if err != nil {
		s.logger.Warn("triggered playbook did not start", "playbook", pb.Name, "error", err)
		return
	}
	s.logger.Info("playbook started by a trigger", "playbook", pb.Name, "run_id", runID,
		"endpoints", targets, "kind", t.Kind, "because", detail)
	s.audit(ctx, auditEvent{
		Action: "playbook.triggered", Actor: who, Target: pb.Name, Severity: "notice",
		Detail: map[string]any{"run_id": runID, "trigger_id": t.ID, "because": detail, "endpoints": targets},
	})
}

// --- webhook triggers -------------------------------------------------

// handlePlaybookWebhook is the one route in this file outside the
// authenticated mux, because an outside system cannot sign in. The token in
// the path is the entire credential, so it is long, generated here, and
// shown once.
//
// Every answer that is not "it fired" is byte-for-byte identical: 200 with
// {"accepted": false}. A caller must not be able to tell a token that does
// not exist from a real one that is inside its cooldown, because that
// difference is an oracle for guessing tokens — and a guesser who can tell
// "wrong" from "right but too soon" has been told the token is right.
//
// The first version of this returned 202 for a bad token and 200 for a good
// one, which is exactly the tell this comment claims not to give. It was
// found by firing a made-up token at it and reading the status code, not by
// reading the code.
func (s *Server) handlePlaybookWebhook(w http.ResponseWriter, r *http.Request) {
	declined := func() {
		writeJSONResponse(w, map[string]any{"accepted": false})
	}
	t, err := s.store.GetPlaybookTriggerByToken(r.Context(), r.PathValue("token"))
	if err != nil {
		s.logger.Warn("playbook webhook lookup failed", "error", err)
		declined()
		return
	}
	if t == nil || !t.Enabled || t.Kind != store.TriggerWebhook {
		s.logger.Warn("playbook webhook rejected", "remote", clientIPOf(r))
		declined()
		return
	}
	detail := "webhook from " + clientIPOf(r)
	claimed, err := s.store.ClaimPlaybookTrigger(r.Context(), t.ID, detail)
	if err != nil || !claimed {
		declined()
		return
	}
	go s.startTriggeredPlaybook(context.WithoutCancel(r.Context()), *t, detail)
	writeJSONResponse(w, map[string]any{"accepted": true})
}

// X-Forwarded-For is believed only from MUSTRA_TRUSTED_PROXIES: any client
// can send the header, and an audit row naming an address the caller chose
// is worse than one naming the proxy.
func clientIPOf(r *http.Request) string { return auth.ClientIP(r) }

// --- trigger CRUD -----------------------------------------------------

// listPlaybookTriggersResponse is what GET /api/playbook-triggers answers.
type listPlaybookTriggersResponse struct {
	MinCooldown int                     `json:"min_cooldown"`
	Triggers    []store.PlaybookTrigger `json:"triggers"`
}

func (s *Server) handleListPlaybookTriggers(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListPlaybookTriggers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The token is shown once, at creation. Afterwards the list says only
	// that one exists — a secret that stays readable in a console is a
	// secret in every browser history and screen share it ever appears in.
	for i := range list {
		list[i].HasToken = list[i].Token != ""
		list[i].Token = ""
	}
	writeJSONResponse(w, listPlaybookTriggersResponse{Triggers: list, MinCooldown: triggerMinCooldown})
}

func (s *Server) handleUpsertPlaybookTrigger(w http.ResponseWriter, r *http.Request) {
	var in store.PlaybookTrigger
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// Only what a person sets is taken from the body. The rest (the ID,
	// the token above all, the firing history) is the server's: a client
	// that could send a token could choose its own webhook URL.
	t := store.PlaybookTrigger{
		PlaybookID: in.PlaybookID, Kind: in.Kind, Enabled: in.Enabled, Source: in.Source,
		Severity: in.Severity, TitleMatch: in.TitleMatch, MinIntervalSeconds: in.MinIntervalSeconds,
		CreatedBy: auth.CurrentUser(r.Context()).Username,
	}
	if t.PlaybookID == "" {
		http.Error(w, "a trigger needs a playbook", http.StatusBadRequest)
		return
	}
	pb, err := s.store.GetPlaybook(r.Context(), t.PlaybookID)
	if err != nil || pb == nil {
		http.Error(w, "no such playbook", http.StatusBadRequest)
		return
	}
	switch t.Kind {
	case store.TriggerEvent, store.TriggerWebhook:
	default:
		http.Error(w, "a trigger is either an event or a webhook", http.StatusBadRequest)
		return
	}
	if t.MinIntervalSeconds < triggerMinCooldown {
		t.MinIntervalSeconds = triggerMinCooldown
	}
	// A webhook trigger needs a token when it is created, and when an
	// update makes it a webhook. It is minted here for every webhook save;
	// an update that keeps its token discards it.
	token := ""
	if t.Kind == store.TriggerWebhook {
		if token = randomToken(); token == "" {
			http.Error(w, "could not generate a webhook token", http.StatusInternalServerError)
			return
		}
	}
	// A POST creates under an ID minted here; a PUT updates the trigger it
	// names, which must exist.
	var out *store.PlaybookTrigger
	issued := false
	if id := r.PathValue("id"); id == "" {
		t.ID, t.Token = idgen.New("pbt-"), token
		out, err = s.store.CreatePlaybookTrigger(r.Context(), t)
		issued = token != ""
	} else {
		t.ID = id
		out, issued, err = s.store.UpdatePlaybookTrigger(r.Context(), t, token)
		if err == nil && out == nil {
			http.Error(w, "no such trigger", http.StatusNotFound)
			return
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "playbook.trigger_save", Actor: t.CreatedBy, Target: pb.Name, Severity: "notice",
		Detail: map[string]any{"kind": out.Kind, "source": out.Source, "severity": out.Severity, "token_issued": issued},
	})
	// Only ever here, and only in the answer that issued it.
	out.HasToken = out.Token != ""
	out.Token = ""
	if issued {
		out.Token = token
	}
	writeJSONResponse(w, out)
}

func (s *Server) handleDeletePlaybookTrigger(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeletePlaybookTrigger(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "playbook.trigger_delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: r.PathValue("id"), Severity: "notice",
	})
	w.WriteHeader(http.StatusNoContent)
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// A token that is not random is not a credential. Failing the
		// creation is the only honest response.
		return ""
	}
	return hex.EncodeToString(b)
}

// --- approval gates ---------------------------------------------------

// parkForApproval stops this endpoint at the gate and makes sure the run's
// single pending decision exists and knows about it.
func (s *Server) parkForApproval(ctx context.Context, runID string, step playbookStep,
	index int, target store.AgentRecord, who string, row store.PlaybookStepResult) {

	hours := step.ApprovalHours
	if hours <= 0 {
		hours = approvalDefaultHours
	}
	if hours > approvalMaxHours {
		hours = approvalMaxHours
	}
	expires := time.Now().Add(time.Duration(hours) * time.Hour)
	reason := strings.TrimSpace(step.ApprovalReason)
	if reason == "" {
		reason = "This playbook stops here until somebody approves the rest."
	}
	if err := s.store.CreatePlaybookPause(ctx, store.PlaybookPause{
		RunID: runID, StepIndex: index, StepName: step.label(index),
		Reason: reason, RequestedBy: who, ExpiresAt: &expires,
	}); err != nil {
		s.logger.Warn("playbook: could not park for approval", "run_id", runID, "error", err)
	}
	if err := s.store.AddPausedAgent(ctx, runID, target.AgentID); err != nil {
		s.logger.Warn("playbook: could not record a parked endpoint", "run_id", runID, "error", err)
	}
	if err := s.store.StartPlaybookStep(ctx, row); err != nil {
		s.logger.Warn("playbook: could not record the gate", "run_id", runID, "error", err)
	}
	_ = s.store.FinishPlaybookStep(ctx, runID, target.AgentID, index, "waiting", "waiting for approval")
}

// listPlaybookPausesResponse is what GET /api/playbook-approvals answers.
type listPlaybookPausesResponse struct {
	Pauses []store.PlaybookPause `json:"pauses"`
}

func (s *Server) handleListPlaybookPauses(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListPlaybookPauses(r.Context(), r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listPlaybookPausesResponse{Pauses: list})
}

// decidePlaybookPauseRequest is the body of POST /api/playbook-approvals/{id}.
type decidePlaybookPauseRequest struct {
	Approve bool   `json:"approve"`
	Note    string `json:"note"`
}

// decidePlaybookPauseResponse is what POST /api/playbook-approvals/{id}
// answers.
type decidePlaybookPauseResponse struct {
	Endpoints int    `json:"endpoints"`
	State     string `json:"state"`
}

// handleDecidePlaybookPause approves or rejects a parked run.
//
// No self-approval: the person who started the run cannot wave it through,
// which is the only thing that makes a gate different from a confirmation
// dialog. A run started by a trigger has no person behind it, so anybody
// with the permission may decide it.
func (s *Server) handleDecidePlaybookPause(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	var req decidePlaybookPauseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	pause, err := s.store.GetPlaybookPause(r.Context(), runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pause == nil {
		http.Error(w, "no such parked run", http.StatusNotFound)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	if pause.RequestedBy == who {
		http.Error(w, "the person who started a run cannot approve it", http.StatusForbidden)
		return
	}
	state := "rejected"
	if req.Approve {
		state = "approved"
	}
	decided, err := s.store.DecidePlaybookPause(r.Context(), runID, state, who, req.Note)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !decided {
		http.Error(w, "that run has already been decided", http.StatusConflict)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "playbook.approval_" + state, Actor: who, Target: pause.PlaybookRun, Severity: "notice",
		Detail: map[string]any{"run_id": runID, "step": pause.StepName, "endpoints": len(pause.AgentIDs)},
	})
	go s.resumePlaybookRun(context.WithoutCancel(r.Context()), runID)
	writeJSONResponse(w, decidePlaybookPauseResponse{State: state, Endpoints: len(pause.AgentIDs)})
}

// resumePlaybookRun picks a decided run back up.
//
// Everything it needs comes from the database — the run's frozen steps, the
// endpoints that were waiting, where they stopped — because the decision
// may arrive tomorrow, after a restart, with no goroutine left to wake.
func (s *Server) resumePlaybookRun(ctx context.Context, runID string) {
	pause, err := s.store.GetPlaybookPause(ctx, runID)
	if err != nil || pause == nil {
		return
	}
	run, err := s.store.GetPlaybookRun(ctx, runID)
	if err != nil || run == nil {
		s.logger.Warn("cannot resume a run that is gone", "run_id", runID)
		return
	}
	var steps []playbookStep
	if err := json.Unmarshal(run.Steps, &steps); err != nil {
		s.logger.Warn("cannot resume: the run's steps are unreadable", "run_id", runID, "error", err)
		return
	}

	if pause.State != "approved" {
		// Rejected or expired. Everything after the gate is recorded as
		// skipped with the reason, rather than left absent: "why did nobody
		// get the reboot" is answered by a row, not by a gap.
		why := "the approval was rejected"
		if pause.State == "expired" {
			why = "nobody decided the approval in time"
		}
		agents, _ := s.store.ListAgents(ctx, s.staleAfter())
		byID := map[string]store.AgentRecord{}
		for _, a := range agents {
			byID[a.AgentID] = a
		}
		for _, id := range pause.AgentIDs {
			a := byID[id]
			_ = s.store.FinishPlaybookStep(ctx, runID, id, pause.StepIndex, "failed", why)
			for j := pause.StepIndex + 1; j < len(steps); j++ {
				_ = s.store.RecordSkippedPlaybookStep(ctx, store.PlaybookStepResult{
					RunID: runID, AgentID: id, Hostname: a.Hostname,
					StepIndex: j, StepName: steps[j].label(j), Kind: steps[j].Kind,
				}, why)
			}
		}
		_ = s.store.FinishPlaybookRun(ctx, runID, "failed")
		s.logger.Info("playbook run closed without approval", "run_id", runID, "state", pause.State)
		return
	}

	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		s.logger.Warn("cannot resume: could not read the fleet", "run_id", runID, "error", err)
		return
	}
	byID := map[string]store.AgentRecord{}
	for _, a := range agents {
		byID[a.AgentID] = a
	}

	s.logger.Info("playbook run resuming after approval", "run_id", runID,
		"from_step", pause.StepIndex+1, "endpoints", len(pause.AgentIDs), "by", pause.DecidedBy)

	var okCnt, badCnt int
	for _, id := range pause.AgentIDs {
		target, ok := byID[id]
		if !ok {
			// The endpoint went away while the gate was open. That is not a
			// failure of the playbook and it is not silence either.
			_ = s.store.FinishPlaybookStep(ctx, runID, id, pause.StepIndex, "skipped",
				"this endpoint was no longer in inventory when the approval came through")
			continue
		}
		_ = s.store.FinishPlaybookStep(ctx, runID, id, pause.StepIndex, "succeeded",
			"approved by "+pause.DecidedBy)
		done, waiting := s.walkPlaybook(ctx, runID, steps, target, pause.RequestedBy, pause.StepIndex+1)
		switch {
		case waiting:
			// A second gate further down the same playbook. It parks again,
			// which is the right answer: two gates means two decisions.
			return
		case done:
			okCnt++
		default:
			badCnt++
		}
	}
	status := playbookRunStatus(okCnt, badCnt)
	if err := s.store.FinishPlaybookRun(ctx, runID, status); err != nil {
		s.logger.Warn("playbook: could not finish a resumed run", "run_id", runID, "error", err)
	}
	s.logger.Info("playbook run finished after approval", "run_id", runID, "status", status)
}

// playbookPauseExpiryLoop closes gates nobody decided, and picks up any
// decision that was made while this process was not running.
func (s *Server) playbookPauseExpiryLoop(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		expired, err := s.store.ExpirePlaybookPauses(ctx)
		if err != nil {
			s.logger.Warn("expiring playbook approvals failed", "error", err)
			continue
		}
		for _, runID := range expired {
			s.logger.Info("playbook approval expired", "run_id", runID)
			s.resumePlaybookRun(ctx, runID)
		}
	}
}
