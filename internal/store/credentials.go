package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DeployCredential is the metadata for one stored SSH credential — never
// carries the decrypted secret; that only ever exists transiently in
// internal/server/vault, decrypted just-in-time for an SSH connection.
type DeployCredential struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	AuthType  string    `json:"auth_type"` // "password" | "private_key"
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// CreateDeployCredential stores an already-encrypted secret (and, for a
// passphrase-protected private key, an already-encrypted passphrase —
// passphraseCipher is nil otherwise). Encryption happens in
// internal/server/vault — this layer only ever sees ciphertext.
func (s *Store) CreateDeployCredential(ctx context.Context, id, name, username, authType string, secretCipher, passphraseCipher []byte, createdBy string) (*DeployCredential, error) {
	const q = `
INSERT INTO deploy_credentials (id, name, username, auth_type, secret_cipher, passphrase_cipher, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, name, username, auth_type, created_at, created_by`
	row := s.pool.QueryRow(ctx, q, id, name, username, authType, secretCipher, passphraseCipher, createdBy)
	var c DeployCredential
	if err := row.Scan(&c.ID, &c.Name, &c.Username, &c.AuthType, &c.CreatedAt, &c.CreatedBy); err != nil {
		return nil, fmt.Errorf("create deploy credential: %w", err)
	}
	return &c, nil
}

// ListDeployCredentials returns credential metadata only, never secrets.
func (s *Store) ListDeployCredentials(ctx context.Context) ([]DeployCredential, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, username, auth_type, created_at, created_by FROM deploy_credentials ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list deploy credentials: %w", err)
	}
	defer rows.Close()
	out := []DeployCredential{}
	for rows.Next() {
		var c DeployCredential
		if err := rows.Scan(&c.ID, &c.Name, &c.Username, &c.AuthType, &c.CreatedAt, &c.CreatedBy); err != nil {
			return nil, fmt.Errorf("scan deploy credential: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetDeployCredentialCipher returns a credential's encrypted secret (and
// encrypted passphrase, if any) for decryption immediately before an SSH
// connection — never cached, never logged, never returned over HTTP.
func (s *Store) GetDeployCredentialCipher(ctx context.Context, id string) (username, authType string, secretCipher, passphraseCipher []byte, err error) {
	row := s.pool.QueryRow(ctx, `SELECT username, auth_type, secret_cipher, passphrase_cipher FROM deploy_credentials WHERE id = $1`, id)
	if err := row.Scan(&username, &authType, &secretCipher, &passphraseCipher); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", nil, nil, nil
		}
		return "", "", nil, nil, fmt.Errorf("get deploy credential cipher: %w", err)
	}
	return username, authType, secretCipher, passphraseCipher, nil
}

func (s *Store) DeleteDeployCredential(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM deploy_credentials WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete deploy credential: %w", err)
	}
	return nil
}

// DeployCredentialCipher is one credential's stored ciphertexts, for the
// vault's re-encryption pass.
type DeployCredentialCipher struct {
	ID               string
	SecretCipher     []byte
	PassphraseCipher []byte
}

func (s *Store) ListDeployCredentialCiphers(ctx context.Context) ([]DeployCredentialCipher, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, secret_cipher, passphrase_cipher FROM deploy_credentials ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list deploy credential ciphers: %w", err)
	}
	defer rows.Close()
	var out []DeployCredentialCipher
	for rows.Next() {
		var c DeployCredentialCipher
		if err := rows.Scan(&c.ID, &c.SecretCipher, &c.PassphraseCipher); err != nil {
			return nil, fmt.Errorf("scan deploy credential cipher: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReplaceDeployCredentialCipher swaps a credential's ciphertexts only if
// they are still the ones that were read; it reports whether it did.
func (s *Store) ReplaceDeployCredentialCipher(ctx context.Context, id string, oldSecret, oldPass, newSecret, newPass []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE deploy_credentials SET secret_cipher = $4, passphrase_cipher = $5
WHERE id = $1 AND secret_cipher = $2 AND passphrase_cipher IS NOT DISTINCT FROM $3`, id, oldSecret, oldPass, newSecret, newPass)
	if err != nil {
		return false, fmt.Errorf("replace deploy credential cipher: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
