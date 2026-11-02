package store

import (
	"context"
	"fmt"
	"time"
)

// EntraDevice is one device as Microsoft Entra ID and Intune see it.
type EntraDevice struct {
	Key             string     `json:"key"`
	EntraDeviceID   string     `json:"entra_device_id"`
	IntuneID        string     `json:"intune_id"`
	Name            string     `json:"name"`
	OS              string     `json:"os"`
	OSVersion       string     `json:"os_version"`
	TrustType       string     `json:"trust_type"`
	AccountEnabled  *bool      `json:"account_enabled,omitempty"`
	EntraCompliant  *bool      `json:"entra_compliant,omitempty"`
	LastSignIn      *time.Time `json:"last_sign_in,omitempty"`
	ComplianceState string     `json:"compliance_state"`
	LastSync        *time.Time `json:"last_sync,omitempty"`
	UserUPN         string     `json:"user_upn"`
	Serial          string     `json:"serial"`
	AgentID         string     `json:"agent_id"`
	SyncedAt        time.Time  `json:"synced_at"`
}

const entraColumns = `key, entra_device_id, intune_id, name, os, os_version, trust_type, account_enabled, entra_compliant, last_sign_in,
	compliance_state, last_sync, user_upn, serial, agent_id, synced_at`

// ReplaceEntraDevices stores one complete sync: devices Graph no longer
// returns are removed.
func (s *Store) ReplaceEntraDevices(ctx context.Context, devices []EntraDevice) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM entra_devices`); err != nil {
		return fmt.Errorf("replace entra devices: %w", err)
	}
	for _, d := range devices {
		if _, err := tx.Exec(ctx, `INSERT INTO entra_devices (`+entraColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, now())`,
			d.Key, d.EntraDeviceID, d.IntuneID, d.Name, d.OS, d.OSVersion, d.TrustType, d.AccountEnabled, d.EntraCompliant, d.LastSignIn,
			d.ComplianceState, d.LastSync, d.UserUPN, d.Serial, d.AgentID); err != nil {
			return fmt.Errorf("insert entra device: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ListEntraDevices(ctx context.Context, agentID string) ([]EntraDevice, error) {
	q := `SELECT ` + entraColumns + ` FROM entra_devices`
	args := []any{}
	if agentID != "" {
		q += ` WHERE agent_id = $1`
		args = append(args, agentID)
	}
	rows, err := s.pool.Query(ctx, q+` ORDER BY lower(name)`, args...)
	if err != nil {
		return nil, fmt.Errorf("list entra devices: %w", err)
	}
	defer rows.Close()
	out := []EntraDevice{}
	for rows.Next() {
		var d EntraDevice
		if err := rows.Scan(&d.Key, &d.EntraDeviceID, &d.IntuneID, &d.Name, &d.OS, &d.OSVersion, &d.TrustType, &d.AccountEnabled, &d.EntraCompliant,
			&d.LastSignIn, &d.ComplianceState, &d.LastSync, &d.UserUPN, &d.Serial, &d.AgentID, &d.SyncedAt); err != nil {
			return nil, fmt.Errorf("scan entra device: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
