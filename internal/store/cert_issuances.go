package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CertIssuance is one certificate Mustra issued (or adopted from what a
// managed certificate's file held before Mustra recorded issuances).
type CertIssuance struct {
	ID            string     `json:"id"`
	ManagedCertID string     `json:"managed_cert_id"`
	AgentID       string     `json:"agent_id"`
	Hostname      string     `json:"hostname,omitempty"`
	Name          string     `json:"name"`
	Names         []string   `json:"names"`
	CertPath      string     `json:"cert_path"`
	CA            string     `json:"ca"`
	Serial        string     `json:"serial"`
	Fingerprint   string     `json:"fingerprint"`
	Issuer        string     `json:"issuer"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	CertPEM       string     `json:"cert_pem,omitempty"`
	Source        string     `json:"source"` // issued, discovered
	IssuedBy      string     `json:"issued_by"`
	IssuedAt      time.Time  `json:"issued_at"`
	SupersededAt  *time.Time `json:"superseded_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedBy     string     `json:"revoked_by,omitempty"`
	RevokeReason  string     `json:"revoke_reason,omitempty"`
	RevokeDetail  string     `json:"revoke_detail,omitempty"`
}

const certIssuanceCols = `i.id, i.managed_cert_id, i.agent_id, coalesce(a.hostname, ''), i.name, i.names, i.cert_path, i.ca,
  i.serial, i.fingerprint, i.issuer, i.not_before, i.not_after, i.cert_pem, i.source, i.issued_by, i.issued_at,
  i.superseded_at, i.revoked_at, i.revoked_by, i.revoke_reason, i.revoke_detail`

func scanCertIssuance(row pgx.Row) (CertIssuance, error) {
	var c CertIssuance
	err := row.Scan(&c.ID, &c.ManagedCertID, &c.AgentID, &c.Hostname, &c.Name, &c.Names, &c.CertPath, &c.CA,
		&c.Serial, &c.Fingerprint, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.CertPEM, &c.Source, &c.IssuedBy, &c.IssuedAt,
		&c.SupersededAt, &c.RevokedAt, &c.RevokedBy, &c.RevokeReason, &c.RevokeDetail)
	return c, err
}

// RecordCertIssuance stores a new issuance and marks the managed
// certificate's earlier ones superseded, in one transaction.
func (s *Store) RecordCertIssuance(ctx context.Context, c CertIssuance) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if c.ManagedCertID != "" {
		if _, err := tx.Exec(ctx, `UPDATE cert_issuances SET superseded_at = now()
WHERE managed_cert_id = $1 AND superseded_at IS NULL AND id <> $2`, c.ManagedCertID, c.ID); err != nil {
			return fmt.Errorf("supersede cert issuances: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cert_issuances (id, managed_cert_id, agent_id, name, names, cert_path, ca, serial,
  fingerprint, issuer, not_before, not_after, cert_pem, source, issued_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT DO NOTHING`, c.ID, c.ManagedCertID, c.AgentID, c.Name, c.Names, c.CertPath, c.CA, c.Serial,
		c.Fingerprint, c.Issuer, c.NotBefore, c.NotAfter, c.CertPEM, c.Source, c.IssuedBy); err != nil {
		return fmt.Errorf("record cert issuance: %w", err)
	}
	return tx.Commit(ctx)
}

// ListCertIssuances returns every issuance, newest first.
func (s *Store) ListCertIssuances(ctx context.Context) ([]CertIssuance, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+certIssuanceCols+` FROM cert_issuances i
LEFT JOIN agents a ON a.agent_id = i.agent_id ORDER BY i.issued_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list cert issuances: %w", err)
	}
	defer rows.Close()
	out := []CertIssuance{}
	for rows.Next() {
		c, err := scanCertIssuance(rows)
		if err != nil {
			return nil, fmt.Errorf("scan cert issuance: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCertIssuance(ctx context.Context, id string) (*CertIssuance, error) {
	c, err := scanCertIssuance(s.pool.QueryRow(ctx, `SELECT `+certIssuanceCols+` FROM cert_issuances i
LEFT JOIN agents a ON a.agent_id = i.agent_id WHERE i.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cert issuance: %w", err)
	}
	return &c, nil
}

// MarkCertRevoked records a revocation. It reports false when the
// issuance was already revoked, changing nothing.
func (s *Store) MarkCertRevoked(ctx context.Context, id, by, reason, detail string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE cert_issuances SET revoked_at = now(), revoked_by = $2, revoke_reason = $3, revoke_detail = $4
WHERE id = $1 AND revoked_at IS NULL`, id, by, reason, detail)
	if err != nil {
		return false, fmt.Errorf("mark cert revoked: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// RevokedPrivateSerials lists what Mustra's own CA has revoked, for its CRL.
func (s *Store) RevokedPrivateSerials(ctx context.Context) ([]CertIssuance, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+certIssuanceCols+` FROM cert_issuances i
LEFT JOIN agents a ON a.agent_id = i.agent_id WHERE i.ca = 'private' AND i.revoked_at IS NOT NULL AND i.serial <> ''
ORDER BY i.revoked_at`)
	if err != nil {
		return nil, fmt.Errorf("revoked private serials: %w", err)
	}
	defer rows.Close()
	var out []CertIssuance
	for rows.Next() {
		c, err := scanCertIssuance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
