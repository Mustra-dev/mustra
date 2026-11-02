package agent

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Asking the person at the endpoint something.
//
// This deliberately reuses the notification delivery model — Self Service
// window reliable, native toast best effort — and deliberately does not
// reuse the notification *answer* model. A notice is answered from a closed
// vocabulary the agent acts on; a survey is answered in the person's own
// terms and the agent does nothing with it but send it on.
//
// A survey and a notification are held separately so neither can evict the
// other. A restart prompt that disappears because somebody was asked how
// their week is going would be a genuinely bad trade.
type activeSurvey struct {
	mu      sync.RWMutex
	prompt  *proto.SurveyPrompt
	shownAt time.Time
}

func (a *activeSurvey) set(p *proto.SurveyPrompt) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prompt = p
	a.shownAt = time.Now()
}

func (a *activeSurvey) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prompt = nil
}

func (a *activeSurvey) get() *proto.SurveyPrompt {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.prompt
}

// visible reports whether the survey should still be shown. An expired one
// is dropped rather than answered late: "how was the maintenance window"
// asked a fortnight afterwards collects a worse answer than no answer.
func (a *activeSurvey) visible() *proto.SurveyPrompt {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.prompt == nil {
		return nil
	}
	if a.prompt.Deadline != nil && time.Now().After(*a.prompt.Deadline) {
		return nil
	}
	return a.prompt
}

func (a *Agent) showSurvey(ctx context.Context, p *proto.SurveyPrompt) {
	a.survey.set(p)
	go a.nativeToast(context.WithoutCancel(ctx), &proto.EndUserNotification{
		Kind: proto.EUNKindNotice, Title: p.Title,
		Body: "Open mustra Self Service to answer.",
	})
}

// surveyForWindow is what the Self Service window renders. The questions go
// over as they are; nothing about the answer is decided here.
func (a *Agent) surveyForWindow() map[string]any {
	p := a.survey.visible()
	if p == nil {
		return nil
	}
	out := map[string]any{
		"id": p.ID, "title": p.Title, "intro": p.Intro,
		"questions": p.Questions, "anonymous": p.Anonymous,
	}
	if p.Deadline != nil {
		out["deadline"] = p.Deadline.Format(time.RFC3339)
	}
	return out
}

// answerSurvey sends the answers on and clears the prompt. It returns a
// problem string, empty when accepted.
func (a *Agent) answerSurvey(ctx context.Context, ans proto.SurveyAnswers) string {
	p := a.survey.get()
	if p == nil {
		return "there is no survey to answer"
	}
	if !ans.Declined {
		given := map[string]bool{}
		for _, x := range ans.Answers {
			if x.Rating > 0 || x.Choice != "" || strings.TrimSpace(x.Text) != "" {
				given[x.QuestionID] = true
			}
		}
		for _, q := range p.Questions {
			if q.Required && !given[q.ID] {
				return "please answer: " + q.Text
			}
		}
	}
	ans.SurveyID = p.ID
	// An anonymous survey never carries a name off the endpoint. Stripping
	// it here rather than at the server is the point: the promise was made
	// on this screen, so it is kept before anything leaves this machine.
	if p.Anonymous {
		ans.User = ""
	} else if ans.User == "" {
		ans.User = localUser()
	}
	a.survey.clear()

	detail := "answered"
	if ans.Declined {
		detail = "declined"
	}
	a.reportActionResult(ctx, proto.AgentActionResult{
		RunID: p.RunID, ActionID: p.ActionID, Kind: "survey",
		OK: true, Detail: detail, Survey: &ans,
	})
	a.logger.Info("survey answered", "survey", p.ID, "detail", detail)
	return ""
}
