package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mustra-dev/mustra/internal/groups"
	"time"

	"github.com/jackc/pgx/v5"
)

// A saved question is a question worth asking again — the reusable half of
// Interact. Question history is every question anyone asked, which doubles
// as the audit log for "who looked at what".

type SavedQuestion struct {
	RecordSensor string          `json:"record_sensor,omitempty"`
	ID           string          `json:"id"`
	Name         string          `json:"name" api:"required"`
	Description  string          `json:"description"`
	Get          []string        `json:"get"`
	Where        json.RawMessage `json:"where"`
	MatchAll     bool            `json:"match_all"`
	CreatedAt    time.Time       `json:"created_at" api:"readonly"`
	CreatedBy    string          `json:"created_by" api:"readonly"`
}

func (s *Store) ListSavedQuestions(ctx context.Context) ([]SavedQuestion, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, name, description, get_fields, where_rules, match_all, created_at, created_by, record_sensor
FROM saved_questions ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list saved queries: %w", err)
	}
	defer rows.Close()
	var out []SavedQuestion
	for rows.Next() {
		var q SavedQuestion
		var where []byte
		if err := rows.Scan(&q.ID, &q.Name, &q.Description, &q.Get, &where,
			&q.MatchAll, &q.CreatedAt, &q.CreatedBy, &q.RecordSensor); err != nil {
			return nil, fmt.Errorf("scan saved query: %w", err)
		}
		q.Where = where
		out = append(out, q)
	}
	return out, rows.Err()
}

func (s *Store) GetSavedQuestion(ctx context.Context, id string) (*SavedQuestion, error) {
	var q SavedQuestion
	var where []byte
	err := s.pool.QueryRow(ctx, `
SELECT id, name, description, get_fields, where_rules, match_all, created_at, created_by, record_sensor
FROM saved_questions WHERE id = $1`, id).Scan(&q.ID, &q.Name, &q.Description,
		&q.Get, &where, &q.MatchAll, &q.CreatedAt, &q.CreatedBy, &q.RecordSensor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get saved query: %w", err)
	}
	q.Where = where
	return &q, nil
}

func (s *Store) UpsertSavedQuestion(ctx context.Context, q SavedQuestion) (*SavedQuestion, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var rules []groups.Rule
	if len(q.Where) > 0 {
		if err = json.Unmarshal(q.Where, &rules); err != nil {
			return nil, err
		}
	}
	if err = validateCustomReferences(ctx, tx, q.Get, rules, q.RecordSensor); err != nil {
		return nil, err
	}
	if len(q.Where) == 0 {
		q.Where = json.RawMessage("[]")
	}
	if q.Get == nil {
		q.Get = []string{}
	}
	const query = `
INSERT INTO saved_questions (id, name, description, get_fields, where_rules, match_all, created_by, record_sensor)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description,
  get_fields = EXCLUDED.get_fields, where_rules = EXCLUDED.where_rules,
  match_all = EXCLUDED.match_all, record_sensor=EXCLUDED.record_sensor
RETURNING id, name, description, get_fields, where_rules, match_all, created_at, created_by, record_sensor`
	var out SavedQuestion
	var where []byte
	if err := tx.QueryRow(ctx, query, q.ID, q.Name, q.Description, q.Get,
		[]byte(q.Where), q.MatchAll, q.CreatedBy, q.RecordSensor).Scan(&out.ID, &out.Name, &out.Description,
		&out.Get, &where, &out.MatchAll, &out.CreatedAt, &out.CreatedBy, &out.RecordSensor); err != nil {
		return nil, fmt.Errorf("upsert saved query: %w", err)
	}
	out.Where = where
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) DeleteSavedQuestion(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM saved_questions WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete saved query: %w", err)
	}
	return nil
}

type QuestionHistory struct {
	ID      string    `json:"id"`
	Text    string    `json:"text"`
	AskedBy string    `json:"asked_by"`
	AskedAt time.Time `json:"asked_at"`
	Matched int       `json:"matched"`
	Total   int       `json:"total"`
}

func (s *Store) RecordQuestion(ctx context.Context, q QuestionHistory) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO question_history (id, text, asked_by, matched, total) VALUES ($1,$2,$3,$4,$5)`,
		q.ID, q.Text, q.AskedBy, q.Matched, q.Total)
	if err != nil {
		return fmt.Errorf("record query: %w", err)
	}
	return nil
}

func (s *Store) ListQuestionHistory(ctx context.Context, limit int) ([]QuestionHistory, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, text, asked_by, asked_at, matched, total
FROM question_history ORDER BY asked_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list query history: %w", err)
	}
	defer rows.Close()
	var out []QuestionHistory
	for rows.Next() {
		var q QuestionHistory
		if err := rows.Scan(&q.ID, &q.Text, &q.AskedBy, &q.AskedAt, &q.Matched, &q.Total); err != nil {
			return nil, fmt.Errorf("scan question history: %w", err)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}
