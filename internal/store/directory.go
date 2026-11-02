package store

import (
	"context"
	"fmt"
	"time"
)

// DirectoryObject is one user, group or computer from the domain, as of the
// last sync. SID is the identity: it is what a Windows endpoint reports in
// its local_admins sensor, so a match needs no name normalisation.
type DirectoryObject struct {
	SID              string     `json:"sid"`
	Kind             string     `json:"kind"` // user | group | computer
	Name             string     `json:"name"`
	DisplayName      string     `json:"display_name,omitempty"`
	DN               string     `json:"dn,omitempty"`
	Domain           string     `json:"domain,omitempty"`
	Enabled          bool       `json:"enabled"`
	AdminCount       bool       `json:"admin_count"`
	DomainController bool       `json:"domain_controller,omitempty"`
	DNSHostName      string     `json:"dns_host_name,omitempty"`
	OperatingSystem  string     `json:"operating_system,omitempty"`
	Description      string     `json:"description,omitempty"`
	LastLogon        *time.Time `json:"last_logon,omitempty"`
	SyncedAt         time.Time  `json:"synced_at"`
}

// DirectoryMember is one direct membership edge. Nesting is resolved by
// whoever reads the table, not stored, so a sync never has to compute a
// closure and a group's own members are always exactly what AD says.
type DirectoryMember struct {
	GroupSID  string `json:"group_sid"`
	MemberSID string `json:"member_sid"`
}

// ReplaceDirectory swaps the whole cache for a fresh sync in one
// transaction. All or nothing: a sync that fails halfway leaves the
// previous picture in place rather than a directory with no groups.
func (s *Store) ReplaceDirectory(ctx context.Context, objects []DirectoryObject, members []DirectoryMember) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM directory_members`); err != nil {
		return fmt.Errorf("clear directory members: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM directory_objects`); err != nil {
		return fmt.Errorf("clear directory objects: %w", err)
	}
	now := time.Now()
	for _, o := range objects {
		if _, err := tx.Exec(ctx, `INSERT INTO directory_objects
			(sid, kind, name, display_name, dn, domain, enabled, admin_count, domain_controller, dns_host_name, operating_system, description, last_logon, synced_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
			ON CONFLICT (sid) DO NOTHING`,
			o.SID, o.Kind, o.Name, o.DisplayName, o.DN, o.Domain, o.Enabled, o.AdminCount, o.DomainController,
			o.DNSHostName, o.OperatingSystem, o.Description, o.LastLogon, now); err != nil {
			return fmt.Errorf("insert directory object %s: %w", o.SID, err)
		}
	}
	for _, m := range members {
		if _, err := tx.Exec(ctx, `INSERT INTO directory_members (group_sid, member_sid) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			m.GroupSID, m.MemberSID); err != nil {
			return fmt.Errorf("insert directory member: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ListDirectoryObjects(ctx context.Context) ([]DirectoryObject, error) {
	rows, err := s.pool.Query(ctx, `SELECT sid, kind, name, display_name, dn, domain, enabled, admin_count, domain_controller,
		dns_host_name, operating_system, description, last_logon, synced_at FROM directory_objects ORDER BY kind, name`)
	if err != nil {
		return nil, fmt.Errorf("list directory objects: %w", err)
	}
	defer rows.Close()
	var out []DirectoryObject
	for rows.Next() {
		var o DirectoryObject
		if err := rows.Scan(&o.SID, &o.Kind, &o.Name, &o.DisplayName, &o.DN, &o.Domain, &o.Enabled, &o.AdminCount, &o.DomainController,
			&o.DNSHostName, &o.OperatingSystem, &o.Description, &o.LastLogon, &o.SyncedAt); err != nil {
			return nil, fmt.Errorf("scan directory object: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) ListDirectoryMembers(ctx context.Context) ([]DirectoryMember, error) {
	rows, err := s.pool.Query(ctx, `SELECT group_sid, member_sid FROM directory_members`)
	if err != nil {
		return nil, fmt.Errorf("list directory members: %w", err)
	}
	defer rows.Close()
	var out []DirectoryMember
	for rows.Next() {
		var m DirectoryMember
		if err := rows.Scan(&m.GroupSID, &m.MemberSID); err != nil {
			return nil, fmt.Errorf("scan directory member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DirectoryCounts is what the settings page shows after a sync.
type DirectoryCounts struct {
	Users     int        `json:"users"`
	Groups    int        `json:"groups"`
	Computers int        `json:"computers"`
	Members   int        `json:"memberships"`
	SyncedAt  *time.Time `json:"synced_at,omitempty"`
}

func (s *Store) DirectoryCounts(ctx context.Context) (DirectoryCounts, error) {
	var c DirectoryCounts
	err := s.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE kind='user'), count(*) FILTER (WHERE kind='group'), count(*) FILTER (WHERE kind='computer'),
		(SELECT count(*) FROM directory_members), max(synced_at) FROM directory_objects`).
		Scan(&c.Users, &c.Groups, &c.Computers, &c.Members, &c.SyncedAt)
	if err != nil {
		return c, fmt.Errorf("directory counts: %w", err)
	}
	return c, nil
}
