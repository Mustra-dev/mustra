package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ManagedCert is a certificate Cert Manager keeps renewed on an endpoint.
type ManagedCert struct {
	ID            string     `json:"id" api:"readonly"`
	AgentID       string     `json:"agent_id" api:"required"`
	Hostname      string     `json:"hostname,omitempty" api:"readonly"`
	Name          string     `json:"name"`
	Names         []string   `json:"names" api:"required"`
	CertPath      string     `json:"cert_path" api:"required"`
	KeyPath       string     `json:"key_path"`
	ReloadCmd     string     `json:"reload_cmd"`
	VerifyPort    int        `json:"verify_port"`
	CA            string     `json:"ca" api:"required"` // private, acme, cloudflare_origin, adcs
	WinBind       string     `json:"win_bind"`          // Windows store: "", iis, rdp
	IISSite       string     `json:"iis_site"`
	RenewDays     int        `json:"renew_days" api:"required"` // renew this many days before expiry
	Approval      string     `json:"approval" api:"required"`   // auto, approve
	Enabled       bool       `json:"enabled"`
	State         string     `json:"state" api:"readonly"` // idle, awaiting_approval, renewing, failed
	LastRenewedAt *time.Time `json:"last_renewed_at,omitempty" api:"readonly"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty" api:"readonly"`
	LastDetail    string     `json:"last_detail" api:"readonly"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedBy     string     `json:"created_by" api:"readonly"`
	CreatedAt     time.Time  `json:"created_at" api:"readonly"`
}

const managedCertCols = `m.id, m.agent_id, coalesce(a.hostname, ''), m.name, m.names, m.cert_path, m.key_path, m.reload_cmd,
  m.verify_port, m.ca, m.renew_days, m.approval, m.enabled, m.state, m.last_renewed_at, m.last_attempt_at,
  m.last_detail, m.expires_at, m.created_by, m.created_at, m.win_bind, m.iis_site`

func scanManagedCert(row pgx.Row) (ManagedCert, error) {
	var m ManagedCert
	err := row.Scan(&m.ID, &m.AgentID, &m.Hostname, &m.Name, &m.Names, &m.CertPath, &m.KeyPath, &m.ReloadCmd,
		&m.VerifyPort, &m.CA, &m.RenewDays, &m.Approval, &m.Enabled, &m.State, &m.LastRenewedAt, &m.LastAttemptAt,
		&m.LastDetail, &m.ExpiresAt, &m.CreatedBy, &m.CreatedAt, &m.WinBind, &m.IISSite)
	return m, err
}

func (s *Store) ListManagedCerts(ctx context.Context) ([]ManagedCert, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+managedCertCols+` FROM managed_certs m LEFT JOIN agents a ON a.agent_id = m.agent_id ORDER BY m.expires_at NULLS LAST, m.name`)
	if err != nil {
		return nil, fmt.Errorf("list managed certs: %w", err)
	}
	defer rows.Close()
	out := []ManagedCert{}
	for rows.Next() {
		m, err := scanManagedCert(rows)
		if err != nil {
			return nil, fmt.Errorf("scan managed cert: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) GetManagedCert(ctx context.Context, id string) (*ManagedCert, error) {
	m, err := scanManagedCert(s.pool.QueryRow(ctx, `SELECT `+managedCertCols+` FROM managed_certs m LEFT JOIN agents a ON a.agent_id = m.agent_id WHERE m.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get managed cert: %w", err)
	}
	return &m, nil
}

func (s *Store) SaveManagedCert(ctx context.Context, m ManagedCert) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO managed_certs (id, agent_id, name, names, cert_path, key_path, reload_cmd, verify_port, ca, renew_days, approval, enabled, created_by, win_bind, iis_site)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (id) DO UPDATE SET agent_id=EXCLUDED.agent_id, name=EXCLUDED.name, names=EXCLUDED.names, cert_path=EXCLUDED.cert_path,
  key_path=EXCLUDED.key_path, reload_cmd=EXCLUDED.reload_cmd, verify_port=EXCLUDED.verify_port, ca=EXCLUDED.ca,
  renew_days=EXCLUDED.renew_days, approval=EXCLUDED.approval, enabled=EXCLUDED.enabled, win_bind=EXCLUDED.win_bind,
  iis_site=EXCLUDED.iis_site, updated_at=now()`,
		m.ID, m.AgentID, m.Name, m.Names, m.CertPath, m.KeyPath, m.ReloadCmd, m.VerifyPort, m.CA, m.RenewDays, m.Approval, m.Enabled, m.CreatedBy, m.WinBind, m.IISSite)
	if err != nil {
		return fmt.Errorf("save managed cert: %w", err)
	}
	return nil
}

func (s *Store) DeleteManagedCert(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM managed_certs WHERE id = $1`, id)
	return err
}

// SetManagedCertState records where a renewal stands. renewed sets the
// renewal time and the new expiry; a nil expires leaves it alone.
func (s *Store) SetManagedCertState(ctx context.Context, id, state, detail string, renewed bool, expires *time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE managed_certs SET state = $2, last_detail = $3, last_attempt_at = now(),
  last_renewed_at = CASE WHEN $4 THEN now() ELSE last_renewed_at END,
  expires_at = coalesce($5, expires_at), updated_at = now() WHERE id = $1`, id, state, detail, renewed, expires)
	return err
}

// SetManagedCertExpiry keeps the cached expiry current from discovery.
func (s *Store) SetManagedCertExpiry(ctx context.Context, id string, expires time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE managed_certs SET expires_at = $2 WHERE id = $1 AND (expires_at IS DISTINCT FROM $2)`, id, expires)
	return err
}
