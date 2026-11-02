package store

import (
	"context"
	"fmt"
	"time"
)

// Console notifications: things the operator needs told, as opposed to
// things the log happens to contain.
//
// The distinction matters. A deployment that half-failed overnight is
// already in the audit log, but an audit log answers questions somebody
// thought to ask; nobody reads one hoping to be surprised. A notification is
// the other direction — it goes looking for the operator.

type Notification struct {
	ID        string    `json:"id"`
	Severity  string    `json:"severity"` // info | warning | critical
	Title     string    `json:"title"`
	Body      string    `json:"body,omitempty"`
	Source    string    `json:"source,omitempty"`
	Link      string    `json:"link,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Read      bool      `json:"read"`
}

func (s *Store) CreateNotification(ctx context.Context, n Notification) error {
	const q = `
INSERT INTO notifications (id, severity, title, body, source, link)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (id) DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, n.ID, n.Severity, n.Title, n.Body, n.Source, n.Link); err != nil {
		return fmt.Errorf("create notification: %w", err)
	}
	return nil
}

// ListNotifications returns recent notifications with this user's own read
// state joined in. Read state is per user because two operators watching the
// same fleet each need their own idea of what they have seen — a shared flag
// means whoever looks first silently clears it for everyone else.
func (s *Store) ListNotifications(ctx context.Context, userID string, limit int) ([]Notification, int, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
SELECT n.id, n.severity, n.title, n.body, n.source, n.link, n.created_at,
       (r.user_id IS NOT NULL) AS read
FROM notifications n
LEFT JOIN notification_reads r ON r.notification_id = n.id AND r.user_id = $1
ORDER BY n.created_at DESC
LIMIT $2`
	rows, err := s.pool.Query(ctx, q, userID, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("list notifications: %w", err)
	}
	defer rows.Close()

	var out []Notification
	unread := 0
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.Severity, &n.Title, &n.Body, &n.Source,
			&n.Link, &n.CreatedAt, &n.Read); err != nil {
			return nil, 0, fmt.Errorf("scan notification: %w", err)
		}
		if !n.Read {
			unread++
		}
		out = append(out, n)
	}
	return out, unread, rows.Err()
}

// UnreadNotificationCount is the badge. Split from ListNotifications because
// the badge is polled and the list is not — fetching fifty rows to render one
// number is the kind of thing that only shows up as load much later.
func (s *Store) UnreadNotificationCount(ctx context.Context, userID string) (int, error) {
	const q = `
SELECT count(*) FROM notifications n
LEFT JOIN notification_reads r ON r.notification_id = n.id AND r.user_id = $1
WHERE r.user_id IS NULL`
	var n int
	if err := s.pool.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("unread notification count: %w", err)
	}
	return n, nil
}

func (s *Store) MarkNotificationRead(ctx context.Context, userID, notificationID string) error {
	const q = `
INSERT INTO notification_reads (notification_id, user_id) VALUES ($1,$2)
ON CONFLICT DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, notificationID, userID); err != nil {
		return fmt.Errorf("mark notification read: %w", err)
	}
	return nil
}

func (s *Store) MarkAllNotificationsRead(ctx context.Context, userID string) error {
	const q = `
INSERT INTO notification_reads (notification_id, user_id)
SELECT n.id, $1 FROM notifications n
ON CONFLICT DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("mark all notifications read: %w", err)
	}
	return nil
}

// PruneNotifications drops anything older than the cutoff. A notification
// nobody acted on three months ago is not going to be acted on now, and an
// unbounded tray becomes something people stop opening.
func (s *Store) PruneNotifications(ctx context.Context, olderThan time.Duration) error {
	const q = `DELETE FROM notifications WHERE created_at < now() - $1::interval`
	if _, err := s.pool.Exec(ctx, q, olderThan); err != nil {
		return fmt.Errorf("prune notifications: %w", err)
	}
	return nil
}
