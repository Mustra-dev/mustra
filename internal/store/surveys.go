package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Engage surveys: asking the people who use the fleet how it is going,
// stored apart from end-user notifications because the answers are a
// different kind of thing — see the comment on the schema.

type Survey struct {
	ID        string                 `json:"id" api:"readonly"`
	Name      string                 `json:"name" api:"required"`
	Title     string                 `json:"title" api:"required"`
	Intro     string                 `json:"intro"`
	Questions []proto.SurveyQuestion `json:"questions" api:"required"`
	Anonymous bool                   `json:"anonymous"`
	// DeadlineAt is when it stops being worth asking. "How did the
	// migration go" collected three weeks later is a worse answer than no
	// answer, so an expired survey is dropped at the endpoint rather than
	// answered late.
	DeadlineAt *time.Time `json:"deadline_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at" api:"readonly"`
	UpdatedAt  time.Time  `json:"updated_at" api:"readonly"`
	CreatedBy  string     `json:"created_by" api:"readonly"`
}

type SurveyResponse struct {
	ID       string `json:"id"`
	SurveyID string `json:"survey_id"`
	RunID    string `json:"run_id"`
	// AgentID and Hostname are empty for an anonymous survey. The agent
	// strips the identity before sending, so there is nothing here to
	// forget to ignore.
	AgentID     string               `json:"agent_id,omitempty"`
	Hostname    string               `json:"hostname,omitempty"`
	Respondent  string               `json:"respondent,omitempty"`
	Answers     []proto.SurveyAnswer `json:"answers"`
	Declined    bool                 `json:"declined"`
	SubmittedAt time.Time            `json:"submitted_at"`
}

const surveyColumns = `id, name, title, intro, questions, anonymous, deadline_at, created_at, updated_at, created_by`

func scanSurvey(row pgx.Row) (*Survey, error) {
	var s Survey
	if err := row.Scan(&s.ID, &s.Name, &s.Title, &s.Intro, &s.Questions, &s.Anonymous,
		&s.DeadlineAt, &s.CreatedAt, &s.UpdatedAt, &s.CreatedBy); err != nil {
		return nil, err
	}
	if s.Questions == nil {
		s.Questions = []proto.SurveyQuestion{}
	}
	return &s, nil
}

func (s *Store) ListSurveys(ctx context.Context) ([]Survey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+surveyColumns+` FROM surveys ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list surveys: %w", err)
	}
	defer rows.Close()
	out := []Survey{}
	for rows.Next() {
		v, err := scanSurvey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan survey: %w", err)
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

func (s *Store) GetSurvey(ctx context.Context, id string) (*Survey, error) {
	v, err := scanSurvey(s.pool.QueryRow(ctx, `SELECT `+surveyColumns+` FROM surveys WHERE id = $1`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get survey: %w", err)
	}
	return v, nil
}

func (s *Store) UpsertSurvey(ctx context.Context, v Survey) (*Survey, error) {
	const q = `
INSERT INTO surveys (id, name, title, intro, questions, anonymous, deadline_at, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, title = EXCLUDED.title, intro = EXCLUDED.intro,
  questions = EXCLUDED.questions, anonymous = EXCLUDED.anonymous,
  deadline_at = EXCLUDED.deadline_at, updated_at = now()
RETURNING ` + surveyColumns
	// A nil slice reaches Postgres as NULL against a NOT NULL column, which
	// is the same trap RecordFacts hit with an agent that reported no
	// addresses: a survey saved with no questions yet would fail forever
	// rather than simply storing none.
	qs := v.Questions
	if qs == nil {
		qs = []proto.SurveyQuestion{}
	}
	out, err := scanSurvey(s.pool.QueryRow(ctx, q, v.ID, v.Name, v.Title, v.Intro, qs,
		v.Anonymous, v.DeadlineAt, v.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("upsert survey: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteSurvey(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM surveys WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete survey: %w", err)
	}
	return nil
}

// RecordSurveySend notes that this endpoint was asked. The primary key is
// (survey_id, agent_id), so asking the same machine twice updates when it
// was asked rather than inflating the denominator of the response rate.
func (s *Store) RecordSurveySend(ctx context.Context, surveyID, agentID, runID string) error {
	const q = `
INSERT INTO survey_sends (survey_id, agent_id, run_id, sent_at)
VALUES ($1,$2,$3, now())
ON CONFLICT (survey_id, agent_id) DO UPDATE SET run_id = EXCLUDED.run_id, sent_at = now()`
	if _, err := s.pool.Exec(ctx, q, surveyID, agentID, runID); err != nil {
		return fmt.Errorf("record survey send: %w", err)
	}
	return nil
}

// RecordSurveyResponse stores one answer set. agentID/hostname are written
// only when the survey is not anonymous; the caller has already had them
// stripped by the agent, and this refuses to re-attach them.
func (s *Store) RecordSurveyResponse(ctx context.Context, r SurveyResponse, anonymous bool) error {
	agentID := any(r.AgentID)
	host, who := r.Hostname, r.Respondent
	if anonymous || r.AgentID == "" {
		agentID, host, who = nil, "", ""
	}
	answers := r.Answers
	if answers == nil {
		answers = []proto.SurveyAnswer{}
	}
	const q = `
INSERT INTO survey_responses (id, survey_id, run_id, agent_id, hostname, respondent, answers, declined)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	if _, err := s.pool.Exec(ctx, q, r.ID, r.SurveyID, r.RunID, agentID, host, who, answers, r.Declined); err != nil {
		return fmt.Errorf("record survey response: %w", err)
	}
	return nil
}

func (s *Store) ListSurveyResponses(ctx context.Context, surveyID string, limit int) ([]SurveyResponse, error) {
	if limit <= 0 {
		limit = 500
	}
	const q = `
SELECT id, survey_id, run_id, coalesce(agent_id,''), hostname, respondent, answers, declined, submitted_at
FROM survey_responses WHERE survey_id = $1 ORDER BY submitted_at DESC LIMIT $2`
	rows, err := s.pool.Query(ctx, q, surveyID, limit)
	if err != nil {
		return nil, fmt.Errorf("list survey responses: %w", err)
	}
	defer rows.Close()
	out := []SurveyResponse{}
	for rows.Next() {
		var r SurveyResponse
		if err := rows.Scan(&r.ID, &r.SurveyID, &r.RunID, &r.AgentID, &r.Hostname,
			&r.Respondent, &r.Answers, &r.Declined, &r.SubmittedAt); err != nil {
			return nil, fmt.Errorf("scan survey response: %w", err)
		}
		if r.Answers == nil {
			r.Answers = []proto.SurveyAnswer{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SurveyCounts is the denominator work: how many were asked, how many
// answered, how many said no.
//
// Responded is separate from Answered+Declined on purpose. A survey can be
// asked of the same endpoint twice, and somebody can answer it twice, so
// the number of replies is not the number of machines that replied — and
// dividing replies by endpoints asked produced a response rate of 200% the
// first time that happened live. Responded counts distinct endpoints, which
// is the number a coverage rate needs.
//
// It is zero for an anonymous survey, where no endpoint is recorded at all.
// That is the honest consequence of the promise: a rate that cannot be
// computed is reported as one that cannot be computed.
type SurveyCounts struct {
	Sent      int `json:"sent"`
	Answered  int `json:"answered"`
	Declined  int `json:"declined"`
	Responded int `json:"responded"`
}

func (s *Store) SurveyCounts(ctx context.Context, surveyID string) (SurveyCounts, error) {
	var c SurveyCounts
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM survey_sends WHERE survey_id = $1`, surveyID).Scan(&c.Sent)
	if err != nil {
		return c, fmt.Errorf("survey sent count: %w", err)
	}
	err = s.pool.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE NOT declined), count(*) FILTER (WHERE declined),
       count(DISTINCT agent_id)
FROM survey_responses WHERE survey_id = $1`, surveyID).Scan(&c.Answered, &c.Declined, &c.Responded)
	if err != nil {
		return c, fmt.Errorf("survey response counts: %w", err)
	}
	return c, nil
}
