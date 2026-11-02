package server

import (
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func rating(qid string, n int) proto.SurveyAnswer {
	return proto.SurveyAnswer{QuestionID: qid, Rating: n}
}

func ratingSurvey() store.Survey {
	return store.Survey{
		ID: "svy-1", Name: "Check-in", Title: "How did it go?",
		Questions: []proto.SurveyQuestion{{ID: "q1", Kind: proto.SurveyRating, Text: "How did it go?"}},
	}
}

// The same rule Confidence follows: too few answers is not a low score, it
// is no score. Four replies is four people's mood, not a fleet's.
func TestSentimentDeclinesWithoutEnoughAnswers(t *testing.T) {
	var resp []store.SurveyResponse
	for i := 0; i < sentimentMinResponses-1; i++ {
		resp = append(resp, store.SurveyResponse{Answers: []proto.SurveyAnswer{rating("q1", 5)}})
	}
	got := scoreSentiment(ratingSurvey(), resp, store.SurveyCounts{Sent: 40, Answered: len(resp), Responded: len(resp)})
	if got.Sentiment != nil {
		t.Fatalf("scored %d answers, expected no score", len(resp))
	}
	if got.Band != "unknown" {
		t.Fatalf("band = %q, want unknown", got.Band)
	}
}

// A decline is counted and never scored. Treating "no thanks" as a low
// rating would invent an opinion the person deliberately withheld.
func TestDeclineIsNotANegativeRating(t *testing.T) {
	var resp []store.SurveyResponse
	for i := 0; i < sentimentMinResponses; i++ {
		resp = append(resp, store.SurveyResponse{Answers: []proto.SurveyAnswer{rating("q1", 5)}})
	}
	all5 := scoreSentiment(ratingSurvey(), resp, store.SurveyCounts{Sent: 20, Answered: len(resp), Responded: len(resp)})
	if all5.Sentiment == nil || *all5.Sentiment != 100 {
		t.Fatalf("five 5s scored %v, want 100", all5.Sentiment)
	}
	// Add ten declines. The score must not move.
	for i := 0; i < 10; i++ {
		resp = append(resp, store.SurveyResponse{Declined: true})
	}
	withNo := scoreSentiment(ratingSurvey(), resp, store.SurveyCounts{Sent: 20, Answered: sentimentMinResponses, Declined: 10, Responded: 15})
	if withNo.Sentiment == nil || *withNo.Sentiment != 100 {
		t.Fatalf("declines changed the score to %v", withNo.Sentiment)
	}
	if withNo.Counts.Declined != 10 {
		t.Fatalf("declines not counted: %+v", withNo.Counts)
	}
}

// A thin response rate is stated, not hidden behind the number.
func TestThinResponseRateIsFlagged(t *testing.T) {
	var resp []store.SurveyResponse
	for i := 0; i < sentimentMinResponses; i++ {
		resp = append(resp, store.SurveyResponse{Answers: []proto.SurveyAnswer{rating("q1", 4)}})
	}
	got := scoreSentiment(ratingSurvey(), resp, store.SurveyCounts{Sent: 100, Answered: len(resp), Responded: len(resp)})
	if got.Sentiment == nil {
		t.Fatal("expected a score")
	}
	if got.Band != "good_thin" {
		t.Fatalf("band = %q, want good_thin", got.Band)
	}
	if got.ResponseRate == nil || *got.ResponseRate > 0.10 {
		t.Fatalf("response rate = %v", got.ResponseRate)
	}
}

// Free text is collected and shown, never scored — a sentiment number
// inferred from prose is a guess nobody can check.
func TestFreeTextIsNeverScored(t *testing.T) {
	sv := store.Survey{ID: "svy-2", Name: "n", Title: "t", Questions: []proto.SurveyQuestion{
		{ID: "q1", Kind: proto.SurveyText, Text: "Anything else?"},
	}}
	var resp []store.SurveyResponse
	for i := 0; i < sentimentMinResponses+3; i++ {
		resp = append(resp, store.SurveyResponse{Answers: []proto.SurveyAnswer{
			{QuestionID: "q1", Text: "everything is terrible"},
		}})
	}
	got := scoreSentiment(sv, resp, store.SurveyCounts{Sent: 10, Answered: len(resp), Responded: len(resp)})
	if got.Sentiment != nil {
		t.Fatalf("free text produced a score of %d", *got.Sentiment)
	}
	if got.Scored != 0 {
		t.Fatalf("scored answers = %d, want 0", got.Scored)
	}
	if len(got.PerQuestion) != 1 || len(got.PerQuestion[0].Samples) != len(resp) {
		t.Fatalf("text answers not surfaced: %+v", got.PerQuestion)
	}
}

// An unmarked choice question is counted and displayed but not scored:
// deciding on the fleet's behalf that "Other" means unhappy is an opinion,
// not a measurement.
func TestChoiceScoresOnlyWhenPositiveIsDeclared(t *testing.T) {
	plain := store.Survey{ID: "s", Name: "n", Title: "t", Questions: []proto.SurveyQuestion{
		{ID: "q1", Kind: proto.SurveyChoice, Text: "Which?", Options: []string{"A", "B"}},
	}}
	marked := plain
	marked.Questions = []proto.SurveyQuestion{
		{ID: "q1", Kind: proto.SurveyChoice, Text: "Which?", Options: []string{"A", "B"}, Positive: []string{"A"}},
	}
	var resp []store.SurveyResponse
	for i := 0; i < sentimentMinResponses+5; i++ {
		choice := "A"
		if i%2 == 1 {
			choice = "B"
		}
		resp = append(resp, store.SurveyResponse{Answers: []proto.SurveyAnswer{{QuestionID: "q1", Choice: choice}}})
	}
	counts := store.SurveyCounts{Sent: 12, Answered: len(resp), Responded: len(resp)}
	if got := scoreSentiment(plain, resp, counts); got.Sentiment != nil {
		t.Fatalf("unmarked choice scored %d", *got.Sentiment)
	}
	got := scoreSentiment(marked, resp, counts)
	if got.Sentiment == nil {
		t.Fatal("marked choice produced no score")
	}
	if *got.Sentiment < 40 || *got.Sentiment > 60 {
		t.Fatalf("half-good answers scored %d, want about 50", *got.Sentiment)
	}
}

func TestValidateQuestions(t *testing.T) {
	cases := []struct {
		name string
		qs   []proto.SurveyQuestion
		bad  bool
	}{
		{"none", nil, true},
		{"choice with one option", []proto.SurveyQuestion{
			{Kind: proto.SurveyChoice, Text: "Which?", Options: []string{"A"}}}, true},
		{"positive not an option", []proto.SurveyQuestion{
			{Kind: proto.SurveyChoice, Text: "Which?", Options: []string{"A", "B"}, Positive: []string{"C"}}}, true},
		{"unknown kind", []proto.SurveyQuestion{{Kind: "vibes", Text: "?"}}, true},
		{"empty text", []proto.SurveyQuestion{{Kind: proto.SurveyRating, Text: "  "}}, true},
		{"fine", []proto.SurveyQuestion{
			{Kind: proto.SurveyRating, Text: "How did it go?"},
			{Kind: proto.SurveyChoice, Text: "Which?", Options: []string{"A", "B"}, Positive: []string{"A"}},
			{Kind: proto.SurveyText, Text: "Anything else?"}}, false},
	}
	for _, c := range cases {
		problem := validateQuestions(c.qs)
		if c.bad && problem == "" {
			t.Errorf("%s: accepted", c.name)
		}
		if !c.bad && problem != "" {
			t.Errorf("%s: rejected with %q", c.name, problem)
		}
	}
	// IDs are filled in where missing, so a question always has one to
	// attach an answer to.
	qs := []proto.SurveyQuestion{{Kind: proto.SurveyRating, Text: "a"}, {Kind: proto.SurveyRating, Text: "b"}}
	if problem := validateQuestions(qs); problem != "" {
		t.Fatalf("rejected: %s", problem)
	}
	if qs[0].ID == "" || qs[1].ID == "" || qs[0].ID == qs[1].ID {
		t.Fatalf("ids = %q, %q", qs[0].ID, qs[1].ID)
	}
}

// The endpoint is never told which answer the operator considers good. A
// survey that shows the person which button is the right one collects
// agreement, not an opinion — and the Self Service window serves this over
// local HTTP, so "the UI does not render it" is not a defence.
func TestPositiveOptionsNeverReachTheEndpoint(t *testing.T) {
	qs := []proto.SurveyQuestion{
		{ID: "q1", Kind: proto.SurveyChoice, Text: "Which?", Options: []string{"A", "B"}, Positive: []string{"A"}},
		{ID: "q2", Kind: proto.SurveyRating, Text: "How?"},
	}
	out := askableQuestions(qs)
	for _, q := range out {
		if len(q.Positive) != 0 {
			t.Fatalf("%s carried its positive options to the endpoint", q.ID)
		}
	}
	// And the operator's copy is untouched — scoring still needs it.
	if len(qs[0].Positive) != 1 {
		t.Fatal("askableQuestions mutated the stored survey")
	}
	if len(out) != len(qs) || out[0].Options[0] != "A" {
		t.Fatalf("questions mangled: %+v", out)
	}
}

// One endpoint asked once and answering twice is one machine, not two. The
// first live test of this produced a response rate of 200%, because
// replies were being divided by endpoints asked.
func TestResponseRateCountsMachinesNotReplies(t *testing.T) {
	resp := []store.SurveyResponse{
		{AgentID: "agt-1", Answers: []proto.SurveyAnswer{rating("q1", 4)}},
		{AgentID: "agt-1", Declined: true},
	}
	got := scoreSentiment(ratingSurvey(), resp, store.SurveyCounts{
		Sent: 1, Answered: 1, Declined: 1, Responded: 1,
	})
	if got.ResponseRate == nil || *got.ResponseRate != 1 {
		t.Fatalf("response rate = %v, want 1", got.ResponseRate)
	}
	if got.RateBasis != "endpoints" {
		t.Fatalf("rate basis = %q", got.RateBasis)
	}
}

// An anonymous survey records no endpoint, so a coverage rate genuinely
// cannot be computed. It reports what it can — replies per machine asked —
// and labels it, rather than dressing that up as the same measurement.
func TestAnonymousRateSaysWhatItIs(t *testing.T) {
	sv := ratingSurvey()
	sv.Anonymous = true
	var resp []store.SurveyResponse
	for i := 0; i < sentimentMinResponses; i++ {
		resp = append(resp, store.SurveyResponse{Answers: []proto.SurveyAnswer{rating("q1", 3)}})
	}
	got := scoreSentiment(sv, resp, store.SurveyCounts{Sent: 10, Answered: len(resp), Responded: 0})
	if got.RateBasis != "replies" {
		t.Fatalf("rate basis = %q, want replies", got.RateBasis)
	}
	if got.ResponseRate == nil || *got.ResponseRate != 0.5 {
		t.Fatalf("rate = %v, want 0.5", got.ResponseRate)
	}
	if !strings.Contains(got.Reason, "cannot be attributed") {
		t.Fatalf("reason does not say why: %q", got.Reason)
	}
}
