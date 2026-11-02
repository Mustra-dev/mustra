package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ComplianceException takes one benchmark check out of the hardening score,
// for every endpoint or one group, with a reason and an optional end date.
type ComplianceException struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	GroupID   string     `json:"group_id"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

func (s *Store) ListComplianceExceptions(ctx context.Context) ([]ComplianceException, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, title, group_id, reason, expires_at, created_by, created_at
FROM compliance_exceptions ORDER BY title, created_at`)
	if err != nil {
		return nil, fmt.Errorf("list compliance exceptions: %w", err)
	}
	defer rows.Close()
	out := []ComplianceException{}
	for rows.Next() {
		var e ComplianceException
		if err := rows.Scan(&e.ID, &e.Title, &e.GroupID, &e.Reason, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan compliance exception: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CreateComplianceException returns the exception as stored, with the
// created_at the database gave it.
func (s *Store) CreateComplianceException(ctx context.Context, e ComplianceException) (ComplianceException, error) {
	err := s.pool.QueryRow(ctx, `
INSERT INTO compliance_exceptions (id, title, group_id, reason, expires_at, created_by)
VALUES ($1,$2,$3,$4,$5,$6)
RETURNING id, title, group_id, reason, expires_at, created_by, created_at`, e.ID, e.Title, e.GroupID, e.Reason, e.ExpiresAt, e.CreatedBy).
		Scan(&e.ID, &e.Title, &e.GroupID, &e.Reason, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt)
	if err != nil {
		return ComplianceException{}, fmt.Errorf("create compliance exception: %w", err)
	}
	return e, nil
}

// DeleteComplianceException returns the removed exception, or nil if there
// was none.
func (s *Store) DeleteComplianceException(ctx context.Context, id string) (*ComplianceException, error) {
	var e ComplianceException
	err := s.pool.QueryRow(ctx, `
DELETE FROM compliance_exceptions WHERE id = $1
RETURNING id, title, group_id, reason, expires_at, created_by, created_at`, id).
		Scan(&e.ID, &e.Title, &e.GroupID, &e.Reason, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("delete compliance exception: %w", err)
	}
	return &e, nil
}
