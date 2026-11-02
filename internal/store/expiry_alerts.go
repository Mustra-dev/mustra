package store

import (
	"context"
	"fmt"
	"time"
)

// ExpiryAlert is one threshold an item was announced at.
type ExpiryAlert struct {
	ItemKey   string    `json:"item_key"`
	ExpiresAt time.Time `json:"expires_at"`
	Threshold int       `json:"threshold"`
	Title     string    `json:"title"`
	DaysLeft  int       `json:"days_left"`
	SentAt    time.Time `json:"sent_at"`
}

// SentExpiryThresholds returns, per item, the thresholds already sent for
// its current expiry ("key|expires" → threshold → true).
func (s *Store) SentExpiryThresholds(ctx context.Context) (map[string]map[int]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT item_key, expires_at, threshold FROM expiry_alerts`)
	if err != nil {
		return nil, fmt.Errorf("sent expiry thresholds: %w", err)
	}
	defer rows.Close()
	out := map[string]map[int]bool{}
	for rows.Next() {
		var key string
		var exp time.Time
		var th int
		if err := rows.Scan(&key, &exp, &th); err != nil {
			return nil, err
		}
		k := key + "|" + exp.UTC().Format(time.RFC3339)
		if out[k] == nil {
			out[k] = map[int]bool{}
		}
		out[k][th] = true
	}
	return out, rows.Err()
}

// RecordExpiryAlerts marks thresholds sent for an item's expiry.
func (s *Store) RecordExpiryAlerts(ctx context.Context, key string, expires time.Time, thresholds []int, title string, daysLeft int) error {
	for _, th := range thresholds {
		if _, err := s.pool.Exec(ctx, `INSERT INTO expiry_alerts (item_key, expires_at, threshold, title, days_left)
VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, key, expires.UTC(), th, title, daysLeft); err != nil {
			return fmt.Errorf("record expiry alert: %w", err)
		}
	}
	// Old expiries' rows are history after a year.
	_, _ = s.pool.Exec(ctx, `DELETE FROM expiry_alerts WHERE sent_at < now() - interval '400 days'`)
	return nil
}

// RecentExpiryAlerts lists the latest alert per item and expiry, newest
// first: the tightest threshold reached and when it was sent.
func (s *Store) RecentExpiryAlerts(ctx context.Context, limit int) ([]ExpiryAlert, error) {
	rows, err := s.pool.Query(ctx, `SELECT item_key, expires_at, min(threshold), max(title), min(days_left), max(sent_at)
FROM expiry_alerts GROUP BY item_key, expires_at ORDER BY max(sent_at) DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("recent expiry alerts: %w", err)
	}
	defer rows.Close()
	out := []ExpiryAlert{}
	for rows.Next() {
		var a ExpiryAlert
		if err := rows.Scan(&a.ItemKey, &a.ExpiresAt, &a.Threshold, &a.Title, &a.DaysLeft, &a.SentAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
