package store

import (
	"context"
	"fmt"
	"time"
)

// BitLockerKey is one escrowed recovery password. The password itself is
// only ever handled as ciphertext here; the server's vault decrypts it for
// a permitted, audited read.
type BitLockerKey struct {
	AgentID       string    `json:"agent_id"`
	Mount         string    `json:"mount"`
	KeyID         string    `json:"key_id"`
	PasswordEnc   []byte    `json:"-"`
	FirstEscrowed time.Time `json:"first_escrowed"`
	LastSeen      time.Time `json:"last_seen"`
}

func (s *Store) UpsertBitLockerKey(ctx context.Context, k BitLockerKey) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO bitlocker_keys (agent_id, mount, key_id, password_enc, first_escrowed, last_seen)
		VALUES ($1, $2, $3, $4, now(), now())
		ON CONFLICT (agent_id, key_id) DO UPDATE SET mount = EXCLUDED.mount, password_enc = EXCLUDED.password_enc, last_seen = now()`,
		k.AgentID, k.Mount, k.KeyID, k.PasswordEnc)
	if err != nil {
		return fmt.Errorf("upsert bitlocker key: %w", err)
	}
	return nil
}

// ListBitLockerKeys lists escrowed keys, all of them or one endpoint's,
// without the ciphertext.
func (s *Store) ListBitLockerKeys(ctx context.Context, agentID string) ([]BitLockerKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, mount, key_id, first_escrowed, last_seen FROM bitlocker_keys
		WHERE $1 = '' OR agent_id = $1 ORDER BY agent_id, mount, key_id`, agentID)
	if err != nil {
		return nil, fmt.Errorf("list bitlocker keys: %w", err)
	}
	defer rows.Close()
	out := []BitLockerKey{}
	for rows.Next() {
		var k BitLockerKey
		if err := rows.Scan(&k.AgentID, &k.Mount, &k.KeyID, &k.FirstEscrowed, &k.LastSeen); err != nil {
			return nil, fmt.Errorf("scan bitlocker key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) GetBitLockerKey(ctx context.Context, agentID, keyID string) (*BitLockerKey, error) {
	var k BitLockerKey
	err := s.pool.QueryRow(ctx, `SELECT agent_id, mount, key_id, password_enc, first_escrowed, last_seen FROM bitlocker_keys WHERE agent_id = $1 AND key_id = $2`, agentID, keyID).
		Scan(&k.AgentID, &k.Mount, &k.KeyID, &k.PasswordEnc, &k.FirstEscrowed, &k.LastSeen)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("get bitlocker key: %w", err)
	}
	return &k, nil
}

// ListBitLockerCiphers lists every escrowed key with its ciphertext, for
// the vault's re-encryption pass.
func (s *Store) ListBitLockerCiphers(ctx context.Context) ([]BitLockerKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, key_id, password_enc FROM bitlocker_keys ORDER BY agent_id, key_id`)
	if err != nil {
		return nil, fmt.Errorf("list bitlocker ciphers: %w", err)
	}
	defer rows.Close()
	var out []BitLockerKey
	for rows.Next() {
		var k BitLockerKey
		if err := rows.Scan(&k.AgentID, &k.KeyID, &k.PasswordEnc); err != nil {
			return nil, fmt.Errorf("scan bitlocker cipher: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// ReplaceBitLockerCipher swaps a key's ciphertext only if it is still the
// one that was read; it reports whether it did.
func (s *Store) ReplaceBitLockerCipher(ctx context.Context, agentID, keyID string, old, replacement []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE bitlocker_keys SET password_enc = $4 WHERE agent_id = $1 AND key_id = $2 AND password_enc = $3`,
		agentID, keyID, old, replacement)
	if err != nil {
		return false, fmt.Errorf("replace bitlocker cipher: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
