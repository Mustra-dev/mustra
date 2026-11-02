package store

import (
	"context"
	"time"
)

// BackupAlerts returns the guests currently alerted as overdue.
func (s *Store) BackupAlerts(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx, `SELECT guest_key, since FROM backup_alerts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var k string
		var t time.Time
		if err := rows.Scan(&k, &t); err != nil {
			return nil, err
		}
		out[k] = t
	}
	return out, rows.Err()
}

func (s *Store) SetBackupAlert(ctx context.Context, key string, on bool) error {
	var err error
	if on {
		_, err = s.pool.Exec(ctx, `INSERT INTO backup_alerts (guest_key) VALUES ($1) ON CONFLICT DO NOTHING`, key)
	} else {
		_, err = s.pool.Exec(ctx, `DELETE FROM backup_alerts WHERE guest_key = $1`, key)
	}
	return err
}

// WarrantyAlerted returns the warranty end date each endpoint was last
// warned about.
func (s *Store) WarrantyAlerted(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, warranty_end FROM warranty_alerts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var a, d string
		if err := rows.Scan(&a, &d); err != nil {
			return nil, err
		}
		out[a] = d
	}
	return out, rows.Err()
}

func (s *Store) SetWarrantyAlerted(ctx context.Context, agentID, end string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO warranty_alerts (agent_id, warranty_end) VALUES ($1,$2)
		ON CONFLICT (agent_id) DO UPDATE SET warranty_end = $2`, agentID, end)
	return err
}
