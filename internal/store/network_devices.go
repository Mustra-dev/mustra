package store

import (
	"context"
	"fmt"
	"time"
)

// NetworkDevice is what the server remembers about one device seen in
// endpoints' neighbour tables.
type NetworkDevice struct {
	MAC       string     `json:"mac"`
	IP        string     `json:"ip"`
	Name      string     `json:"name"`
	NameAt    *time.Time `json:"-"`
	Vendor    string     `json:"vendor"`
	SeenBy    []string   `json:"seen_by"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	Label     string     `json:"label"`
	Ignored   bool       `json:"ignored"`
	Alerted   bool       `json:"-"`
	Baseline  bool       `json:"-"` // recorded by the first pass
}

const networkDeviceColumns = `mac, ip, name, name_at, vendor, seen_by, first_seen, last_seen, label, ignored, alerted, baseline`

// ObserveNetworkDevices records one discovery pass. A device not seen
// before gets first_seen now; the returned MACs are those new devices.
func (s *Store) ObserveNetworkDevices(ctx context.Context, seen []NetworkDevice) ([]string, error) {
	var created []string
	for _, d := range seen {
		var inserted bool
		err := s.pool.QueryRow(ctx, `INSERT INTO network_devices (mac, ip, vendor, seen_by, last_seen)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (mac) DO UPDATE SET ip = EXCLUDED.ip, vendor = EXCLUDED.vendor, seen_by = EXCLUDED.seen_by,
				last_seen = GREATEST(network_devices.last_seen, EXCLUDED.last_seen)
			RETURNING (xmax = 0)`, d.MAC, d.IP, d.Vendor, d.SeenBy, d.LastSeen).Scan(&inserted)
		if err != nil {
			return created, fmt.Errorf("observe network device: %w", err)
		}
		if inserted {
			created = append(created, d.MAC)
		}
	}
	return created, nil
}

func (s *Store) ListNetworkDevices(ctx context.Context) ([]NetworkDevice, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+networkDeviceColumns+` FROM network_devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("list network devices: %w", err)
	}
	defer rows.Close()
	out := []NetworkDevice{}
	for rows.Next() {
		var d NetworkDevice
		if err := rows.Scan(&d.MAC, &d.IP, &d.Name, &d.NameAt, &d.Vendor, &d.SeenBy, &d.FirstSeen, &d.LastSeen, &d.Label, &d.Ignored, &d.Alerted, &d.Baseline); err != nil {
			return nil, fmt.Errorf("scan network device: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) CountNetworkDevices(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM network_devices`).Scan(&n)
	return n, err
}

// SetNetworkDeviceName records a reverse-DNS answer, empty included, so
// the lookup is not repeated until it is due again.
func (s *Store) SetNetworkDeviceName(ctx context.Context, mac, name string) error {
	_, err := s.pool.Exec(ctx, `UPDATE network_devices SET name = $2, name_at = now() WHERE mac = $1`, mac, name)
	return err
}

// MarkNetworkBaseline records devices as present before discovery began.
func (s *Store) MarkNetworkBaseline(ctx context.Context, macs []string) error {
	_, err := s.pool.Exec(ctx, `UPDATE network_devices SET alerted = true, baseline = true WHERE mac = ANY($1)`, macs)
	return err
}

func (s *Store) SetNetworkDeviceAlerted(ctx context.Context, macs []string) error {
	_, err := s.pool.Exec(ctx, `UPDATE network_devices SET alerted = true WHERE mac = ANY($1)`, macs)
	return err
}

// UpdateNetworkDevice sets the operator's label and ignore flag; it
// reports false when no such device is known.
func (s *Store) UpdateNetworkDevice(ctx context.Context, mac string, label *string, ignored *bool) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE network_devices SET label = COALESCE($2, label), ignored = COALESCE($3, ignored) WHERE mac = $1`, mac, label, ignored)
	if err != nil {
		return false, fmt.Errorf("update network device: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ResetNetworkDeviceNames makes every name due for lookup again.
func (s *Store) ResetNetworkDeviceNames(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE network_devices SET name_at = NULL`)
	return err
}
