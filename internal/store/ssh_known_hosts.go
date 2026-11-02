package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SSHKnownHost is a host key the console has been told to trust for an
// agent-push target. Push refuses a target whose key differs.
type SSHKnownHost struct {
	Target      string    `json:"target"`
	KeyType     string    `json:"key_type"`
	Fingerprint string    `json:"fingerprint"` // SHA256:… as ssh-keygen -l prints it
	PublicKey   string    `json:"public_key"`  // authorized_keys format
	ConfirmedBy string    `json:"confirmed_by"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Store) GetSSHKnownHost(ctx context.Context, target string) (*SSHKnownHost, error) {
	var h SSHKnownHost
	err := s.pool.QueryRow(ctx, `SELECT target, key_type, fingerprint, public_key, confirmed_by, created_at
FROM ssh_known_hosts WHERE target = $1`, target).Scan(&h.Target, &h.KeyType, &h.Fingerprint, &h.PublicKey, &h.ConfirmedBy, &h.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get ssh known host: %w", err)
	}
	return &h, nil
}

// SaveSSHKnownHost records a confirmed key. An existing entry is not
// replaced: a changed host key is removed deliberately, then confirmed.
func (s *Store) SaveSSHKnownHost(ctx context.Context, h SSHKnownHost) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO ssh_known_hosts (target, key_type, fingerprint, public_key, confirmed_by)
VALUES ($1, $2, $3, $4, $5) ON CONFLICT (target) DO NOTHING`, h.Target, h.KeyType, h.Fingerprint, h.PublicKey, h.ConfirmedBy)
	if err != nil {
		return fmt.Errorf("save ssh known host: %w", err)
	}
	return nil
}

func (s *Store) DeleteSSHKnownHost(ctx context.Context, target string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM ssh_known_hosts WHERE target = $1`, target); err != nil {
		return fmt.Errorf("delete ssh known host: %w", err)
	}
	return nil
}
