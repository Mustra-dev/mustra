package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
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

// Engage: surveys through the end-user notification channel, and a
// sentiment score computed from them.
//
// The score follows the same discipline as Confidence (see confidence.go):
// it declines to answer without enough answers, and it never hides the
// denominator. The failure mode a survey score invites is worse than the
// one a confidence score invites, because a bad number here is a claim
// about what people think. Four replies out of forty is the mood of four
// people, and the four who reply to an unprompted survey are rarely the
// indifferent ones.

const (
	// sentimentMinResponses is the point below which no score is given.
	sentimentMinResponses = 5
	// sentimentThinRate is the response rate below which a score is given
	// but flagged as unrepresentative rather than presented plainly.
	sentimentThinRate = 0.30
)

type surveySummary struct {
	store.Survey
	Counts store.SurveyCounts `json:"counts"`
	// Sentiment is 0–100, nil when there is not enough to say.
	Sentiment    *int     `json:"sentiment,omitempty"`
	Band         string   `json:"band"`
	Reason       string   `json:"reason"`
	ResponseRate *float64 `json:"response_rate,omitempty"`
	// RateBasis names what the rate actually measures, because for an
	// anonymous survey it cannot be the same thing. "endpoints" is distinct
	// machines that replied over machines asked; "replies" is replies over
	// machines asked, which can exceed 100% and says so.
	RateBasis string `json:"rate_basis,omitempty"`
	Scored    int    `json:"scored_answers"`
	// PerQuestion holds the breakdown, so a single number never has to be
	// taken on faith.
	PerQuestion []surveyQuestionResult `json:"per_question"`
}

type surveyQuestionResult struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"`
	Text    string         `json:"text"`
	Answers int            `json:"answers"`
	Average *float64       `json:"average,omitempty"`
	Counts  map[string]int `json:"counts,omitempty"`
	// Samples are free-text answers, which are shown and never scored.
	Samples []string `json:"samples,omitempty"`
}

// scoreSentiment reduces a survey's answers to one number, or declines.
//
// Only two question kinds can contribute. A rating maps 1–5 onto 0–100
// linearly. A choice contributes only when the operator said which options
// are positive; otherwise it is counted and displayed but not scored,
// because deciding on the fleet's behalf that "Other" means unhappy is how
// a measurement turns into an opinion. Free text is never scored at all:
// inferring sentiment from prose by counting words produces a number no
// one can check, and a number no one can check is the thing this is
// supposed to replace.
func scoreSentiment(sv store.Survey, responses []store.SurveyResponse, counts store.SurveyCounts) surveySummary {
	out := surveySummary{Survey: sv, Counts: counts}
	byID := map[string]proto.SurveyQuestion{}
	order := []string{}
	for _, q := range sv.Questions {
		byID[q.ID] = q
		order = append(order, q.ID)
	}
	res := map[string]*surveyQuestionResult{}
	for _, id := range order {
		q := byID[id]
		res[id] = &surveyQuestionResult{ID: q.ID, Kind: q.Kind, Text: q.Text, Counts: map[string]int{}}
	}

	var total float64
	scored := 0
	answered := 0
	for _, r := range responses {
		if r.Declined {
			continue
		}
		answered++
		for _, a := range r.Answers {
			qr := res[a.QuestionID]
			q, ok := byID[a.QuestionID]
			if !ok || qr == nil {
				continue // a question that has since been edited away
			}
			switch q.Kind {
			case proto.SurveyRating:
				if a.Rating < 1 || a.Rating > 5 {
					continue
				}
				qr.Answers++
				qr.Counts[strconv.Itoa(a.Rating)]++
				total += float64(a.Rating-1) / 4 * 100
				scored++
			case proto.SurveyChoice:
				if a.Choice == "" {
					continue
				}
				qr.Answers++
				qr.Counts[a.Choice]++
				if len(q.Positive) > 0 {
					v := 0.0
					for _, p := range q.Positive {
						if p == a.Choice {
							v = 100
							break
						}
					}
					total += v
					scored++
				}
			default:
				t := strings.TrimSpace(a.Text)
				if t == "" {
					continue
				}
				qr.Answers++
				if len(qr.Samples) < 25 {
					qr.Samples = append(qr.Samples, t)
				}
			}
		}
	}
	for _, id := range order {
		qr := res[id]
		if byID[id].Kind == proto.SurveyRating && qr.Answers > 0 {
			var sum float64
			for k, n := range qr.Counts {
				v, _ := strconv.Atoi(k)
				sum += float64(v * n)
			}
			avg := sum / float64(qr.Answers)
			qr.Average = &avg
		}
		if len(qr.Counts) == 0 {
			qr.Counts = nil
		}
		out.PerQuestion = append(out.PerQuestion, *qr)
	}
	out.Scored = scored

	if counts.Sent > 0 {
		// Distinct endpoints where they are known. Replies divided by
		// endpoints asked is not a rate: one machine asked twice and
		// answered twice read as 200% the first time it happened.
		rate := float64(counts.Responded) / float64(counts.Sent)
		out.RateBasis = "endpoints"
		if sv.Anonymous {
			rate = float64(counts.Answered+counts.Declined) / float64(counts.Sent)
			out.RateBasis = "replies"
		}
		out.ResponseRate = &rate
	}

	if answered < sentimentMinResponses {
		out.Band = "unknown"
		out.Reason = fmt.Sprintf("not enough answers: %d of %d needed before this is worth a number",
			answered, sentimentMinResponses)
		return out
	}
	if scored == 0 {
		out.Band = "unknown"
		out.Reason = "nothing here is scoreable: add a rating question, or mark which choices count as positive"
		return out
	}
	n := int(math.Round(total / float64(scored)))
	out.Sentiment = &n
	switch {
	case n >= 75:
		out.Band = "good"
	case n >= 50:
		out.Band = "mixed"
	default:
		out.Band = "poor"
	}
	out.Reason = fmt.Sprintf("%d answer(s) from %d of %d asked", answered, counts.Answered+counts.Declined, counts.Sent)
	if counts.Declined > 0 {
		out.Reason += fmt.Sprintf("; %d declined", counts.Declined)
	}
	// A decline is counted and never scored. Somebody who did not want to
	// answer has not told you they are unhappy, and treating silence as a
	// low rating is inventing data.
	if out.ResponseRate != nil && *out.ResponseRate < sentimentThinRate {
		out.Reason += fmt.Sprintf("; only %.0f%% replied, so read this as those people's view rather than the fleet's",
			*out.ResponseRate*100)
		out.Band += "_thin"
	}
	if out.RateBasis == "replies" {
		out.Reason += "; anonymous answers cannot be attributed, so this counts replies rather than machines"
	}
	return out
}

// askableQuestions is the survey as the person should see it: the same
// questions with Positive removed.
//
// Which options the operator counts as a good answer is scoring
// information, and shipping it to the endpoint puts it one local HTTP
// request away from the person being asked. A survey that tells you which
// button is the right one is not collecting an opinion, it is collecting
// agreement.
func askableQuestions(qs []proto.SurveyQuestion) []proto.SurveyQuestion {
	out := make([]proto.SurveyQuestion, len(qs))
	for i, q := range qs {
		q.Positive = nil
		out[i] = q
	}
	return out
}

// ---- HTTP ----

// listSurveysResponse is what GET /api/surveys answers.
type listSurveysResponse struct {
	MinResponses int             `json:"min_responses"`
	Surveys      []surveySummary `json:"surveys"`
}

func (s *Server) handleListSurveys(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListSurveys(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]surveySummary, 0, len(list))
	for _, sv := range list {
		counts, err := s.store.SurveyCounts(r.Context(), sv.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp, err := s.store.ListSurveyResponses(r.Context(), sv.ID, 2000)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, scoreSentiment(sv, resp, counts))
	}
	writeJSONResponse(w, listSurveysResponse{Surveys: out, MinResponses: sentimentMinResponses})
}

// surveyDetailResponse is what GET /api/surveys/{id} answers.
type surveyDetailResponse struct {
	Responses []store.SurveyResponse `json:"responses"`
	Summary   surveySummary          `json:"summary"`
}

func (s *Server) handleSurveyDetail(w http.ResponseWriter, r *http.Request) {
	sv, err := s.store.GetSurvey(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sv == nil {
		http.Error(w, "no such survey", http.StatusNotFound)
		return
	}
	counts, err := s.store.SurveyCounts(r.Context(), sv.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := s.store.ListSurveyResponses(r.Context(), sv.ID, 2000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary := scoreSentiment(*sv, resp, counts)
	// An anonymous survey's responses are returned without identity because
	// there is none stored — but the raw list is still withheld from the
	// default view, since a small fleet plus a timestamp is an identity.
	if sv.Anonymous {
		for i := range resp {
			resp[i].AgentID, resp[i].Hostname, resp[i].Respondent = "", "", ""
			resp[i].SubmittedAt = resp[i].SubmittedAt.Truncate(24 * time.Hour)
		}
	}
	writeJSONResponse(w, surveyDetailResponse{Summary: summary, Responses: resp})
}

func (s *Server) handleUpsertSurvey(w http.ResponseWriter, r *http.Request) {
	var sv store.Survey
	if err := json.NewDecoder(r.Body).Decode(&sv); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// The path decides which record is written: a POST creates one under an
	// ID minted here, whatever the body says, and a PUT updates the one it
	// names. A body ID once let a create rewrite an existing survey,
	// questions and anonymity included.
	if id := r.PathValue("id"); id != "" {
		old, err := s.store.GetSurvey(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if old == nil {
			http.Error(w, "no such survey", http.StatusNotFound)
			return
		}
		// Endpoints were asked under the promise the survey made when it
		// was sent. Dropping anonymity afterwards would store later
		// answers to an anonymous prompt with their endpoint and
		// respondent; adding it would mix named and unnamed answers in
		// one tally.
		if sv.Anonymous != old.Anonymous {
			counts, err := s.store.SurveyCounts(r.Context(), id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if counts.Sent > 0 || counts.Answered+counts.Declined > 0 {
				http.Error(w, "this survey has been sent, so whether it is anonymous can no longer change; copy it as a new survey to ask the other way", http.StatusConflict)
				return
			}
		}
		sv.ID = id
	} else {
		sv.ID = idgen.New("svy-")
	}
	sv.Name = strings.TrimSpace(sv.Name)
	sv.Title = strings.TrimSpace(sv.Title)
	if sv.Name == "" || sv.Title == "" {
		http.Error(w, "a survey needs a name and a title", http.StatusBadRequest)
		return
	}
	if problem := validateQuestions(sv.Questions); problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
		return
	}
	sv.CreatedBy = auth.CurrentUser(r.Context()).Username
	out, err := s.store.UpsertSurvey(r.Context(), sv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "survey.save", Actor: sv.CreatedBy, Target: out.Name, Severity: "notice",
		Detail: map[string]any{"questions": len(out.Questions), "anonymous": out.Anonymous},
	})
	writeJSONResponse(w, out)
}

// validateQuestions rejects a survey that cannot be answered before it is
// sent to anybody, rather than after. An empty option list on a choice
// question renders as a question with no way to answer it, which somebody
// then has to be told to ignore.
func validateQuestions(qs []proto.SurveyQuestion) string {
	if len(qs) == 0 {
		return "a survey needs at least one question"
	}
	if len(qs) > 12 {
		return "twelve questions is already more than most people will answer"
	}
	seen := map[string]bool{}
	for i := range qs {
		q := &qs[i]
		q.ID = strings.TrimSpace(q.ID)
		if q.ID == "" {
			q.ID = "q" + strconv.Itoa(i+1)
		}
		if seen[q.ID] {
			return "two questions share the id " + q.ID
		}
		seen[q.ID] = true
		if strings.TrimSpace(q.Text) == "" {
			return "every question needs to say something"
		}
		switch q.Kind {
		case proto.SurveyRating, proto.SurveyText:
		case proto.SurveyChoice:
			if len(q.Options) < 2 {
				return "a choice question needs at least two options: " + q.Text
			}
			opts := map[string]bool{}
			for _, o := range q.Options {
				opts[o] = true
			}
			for _, p := range q.Positive {
				if !opts[p] {
					return "a positive option that is not one of the options: " + p
				}
			}
		default:
			return "unknown question kind: " + q.Kind
		}
	}
	return ""
}

func (s *Server) handleDeleteSurvey(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSurvey(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "survey.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: r.PathValue("id"), Severity: "notice",
	})
	w.WriteHeader(http.StatusNoContent)
}

// sendSurveyRequest is the body of POST /api/surveys/{id}/send.
type sendSurveyRequest struct {
	AgentIDs []string `json:"agent_ids"`
	GroupID  string   `json:"group_id"`
}

// sendSurveyResponse is what POST /api/surveys/{id}/send answers.
type sendSurveyResponse struct {
	Message string `json:"message"`
	RunID   string `json:"run_id"`
	Targets int    `json:"targets"`
}

func (s *Server) handleSendSurvey(w http.ResponseWriter, r *http.Request) {
	sv, err := s.store.GetSurvey(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sv == nil {
		http.Error(w, "no such survey", http.StatusNotFound)
		return
	}
	var req sendSurveyRequest
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
	var inGroup map[string]bool
	if req.GroupID != "" {
		ids, err := s.groupMemberIDSet(r.Context(), req.GroupID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		inGroup = ids
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
		if inGroup != nil && !inGroup[a.AgentID] {
			continue
		}
		// Same rule as a notice: an offline endpoint is skipped, not
		// queued. A survey that surfaces whenever the laptop next wakes is
		// asking about something the person has stopped thinking about.
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
	if err := s.store.RecordPatchJobRun(r.Context(), store.PatchJobRun{
		ID: runID, TargetDesc: "survey: " + sv.Name, AgentCount: len(targets),
		ScheduleName: sv.Title, TriggeredBy: who,
	}); err != nil {
		s.logger.Warn("record survey run failed", "error", err)
	}
	go s.deliverSurvey(context.WithoutCancel(r.Context()), *sv, targets, runID, who)

	s.audit(r.Context(), auditEvent{
		Action: "survey.send", Actor: who, Target: sv.Name, Severity: "notice",
		Detail: map[string]any{"run_id": runID, "endpoints": len(targets), "anonymous": sv.Anonymous},
	})
	writeJSONResponse(w, sendSurveyResponse{
		RunID: runID, Targets: len(targets),
		Message: "asked " + strconv.Itoa(len(targets)) + " endpoint(s)",
	})
}

func (s *Server) deliverSurvey(ctx context.Context, sv store.Survey, targets []store.AgentRecord, runID, who string) {
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
				ID: actionID, RunID: runID, AgentID: agentID, Kind: "survey",
				Summary: "Survey: " + sv.Name, RequestedBy: who,
			}); err != nil {
				s.logger.Warn("record survey action failed", "agent_id", agentID, "error", err)
			}

			prompt := proto.SurveyPrompt{
				ID: sv.ID, Title: sv.Title, Intro: sv.Intro, Questions: askableQuestions(sv.Questions),
				Anonymous: sv.Anonymous, Deadline: sv.DeadlineAt,
			}
			payload, err := json.Marshal(proto.AgentCommand{
				Cmd: "ask_user", Survey: &prompt, RunID: runID, ActionID: actionID,
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
			// Only now is this endpoint part of the denominator. Recording
			// the send before the agent accepted it would count machines
			// that were never actually asked, and a response rate whose
			// bottom half is wrong is worse than none.
			if err := s.store.RecordSurveySend(ctx, sv.ID, agentID, runID); err != nil {
				s.logger.Warn("record survey send failed", "agent_id", agentID, "error", err)
			}
			// Left open, like a notification: the endpoint has the
			// questions; the person has not answered them.
		}(target.AgentID)
	}
	wg.Wait()
}

// recordSurveyAnswers is called from the action-result consumer.
func (s *Server) recordSurveyAnswers(ctx context.Context, res proto.AgentActionResult) error {
	a := res.Survey
	sv, err := s.store.GetSurvey(ctx, a.SurveyID)
	if err != nil {
		return err
	}
	if sv == nil {
		// The survey was deleted while somebody had it open. Dropping the
		// answer is right — there is nothing to attach it to — and it must
		// not be retried forever.
		s.logger.Warn("survey answers for an unknown survey", "survey_id", a.SurveyID)
		return nil
	}
	hostname := ""
	if !sv.Anonymous {
		if agents, err := s.store.ListAgents(ctx, s.staleAfter()); err == nil {
			for _, a := range agents {
				if a.AgentID == res.AgentID {
					hostname = a.Hostname
					break
				}
			}
		}
	}
	return s.store.RecordSurveyResponse(ctx, store.SurveyResponse{
		ID: idgen.New("sr-"), SurveyID: sv.ID, RunID: res.RunID,
		AgentID: res.AgentID, Hostname: hostname, Respondent: a.User,
		Answers: a.Answers, Declined: a.Declined,
	}, sv.Anonymous)
}
