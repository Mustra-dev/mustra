package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// UserTOTP is a local account's two-step sign-in state. Secret is the
// vault-sealed base32 secret, nil when none was ever set up; EnabledAt is
// nil while enrollment is still pending.
type UserTOTP struct {
	Secret    []byte
	EnabledAt *time.Time
	LastStep  int64
}

// Enabled reports whether sign-in requires a code.
func (t UserTOTP) Enabled() bool { return t.EnabledAt != nil && len(t.Secret) > 0 }

// GetUserTOTP returns the user's TOTP state, or nil for no such user.
func (s *Store) GetUserTOTP(ctx context.Context, userID string) (*UserTOTP, error) {
	var t UserTOTP
	err := s.pool.QueryRow(ctx, `SELECT totp_secret, totp_enabled_at, totp_last_step FROM users WHERE id = $1`, userID).
		Scan(&t.Secret, &t.EnabledAt, &t.LastStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user totp: %w", err)
	}
	return &t, nil
}

// SetPendingTOTP stores a new sealed secret awaiting its first code. It
// never replaces an enabled one: changing an enabled factor goes through
// DisableTOTP first, which the caller gates on a valid code.
func (s *Store) SetPendingTOTP(ctx context.Context, userID string, sealed []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET totp_secret = $2, totp_last_step = 0, updated_at = now()
		WHERE id = $1 AND totp_enabled_at IS NULL`, userID, sealed)
	if err != nil {
		return false, fmt.Errorf("set pending totp: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// EnableTOTP confirms the pending secret, records the step of the code
// that confirmed it, and replaces the recovery codes, all at once.
func (s *Store) EnableTOTP(ctx context.Context, userID string, step int64, codeHashes []string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET totp_enabled_at = now(), totp_last_step = $2, updated_at = now()
			WHERE id = $1 AND totp_secret IS NOT NULL AND totp_enabled_at IS NULL`, userID, step)
		if err != nil {
			return fmt.Errorf("enable totp: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("enable totp: no pending enrollment")
		}
		return replaceRecoveryCodes(ctx, tx, userID, codeHashes)
	})
}

// DisableTOTP removes the factor and its recovery codes.
func (s *Store) DisableTOTP(ctx context.Context, userID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = 0, updated_at = now() WHERE id = $1`, userID); err != nil {
			return fmt.Errorf("disable totp: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id = $1`, userID); err != nil {
			return fmt.Errorf("disable totp: %w", err)
		}
		return nil
	})
}

// AdvanceTOTPStep records step as used, and reports false when it (or a
// later one) already was: the compare-and-set is what stops a code being
// accepted twice, even by two sign-ins racing each other.
func (s *Store) AdvanceTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2`, userID, step)
	if err != nil {
		return false, fmt.Errorf("advance totp step: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ReplaceRecoveryCodes discards the user's recovery codes for new ones.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return replaceRecoveryCodes(ctx, tx, userID, codeHashes) })
}

func replaceRecoveryCodes(ctx context.Context, tx pgx.Tx, userID string, codeHashes []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx, `INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return fmt.Errorf("replace recovery codes: %w", err)
		}
	}
	return nil
}

// UseRecoveryCode spends one unused code and reports whether it existed.
func (s *Store) UseRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE user_recovery_codes SET used_at = now()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, userID, codeHash)
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RecoveryCodesLeft counts the user's unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, userID string) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}
	return n, nil
}

// LoginChallenge is a password accepted and a second step still owed.
type LoginChallenge struct {
	UserID   string
	Purpose  string // "totp" | "enroll"
	Next     string
	Attempts int
}

// CreateLoginChallenge records a challenge under the hash of its token.
func (s *Store) CreateLoginChallenge(ctx context.Context, tokenHash, userID, purpose, next string, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO login_challenges (token_hash, user_id, purpose, next, expires_at)
		VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5::bigint))`, tokenHash, userID, purpose, next, int64(ttl/time.Second))
	if err != nil {
		return fmt.Errorf("create login challenge: %w", err)
	}
	return nil
}

// GetLoginChallenge returns a live challenge, or nil if it is unknown or
// expired.
func (s *Store) GetLoginChallenge(ctx context.Context, tokenHash string) (*LoginChallenge, error) {
	var c LoginChallenge
	err := s.pool.QueryRow(ctx, `SELECT user_id, purpose, next, attempts FROM login_challenges
		WHERE token_hash = $1 AND expires_at > now()`, tokenHash).Scan(&c.UserID, &c.Purpose, &c.Next, &c.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get login challenge: %w", err)
	}
	return &c, nil
}

// FailLoginChallenge counts a wrong code and returns the new count.
func (s *Store) FailLoginChallenge(ctx context.Context, tokenHash string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `UPDATE login_challenges SET attempts = attempts + 1 WHERE token_hash = $1 RETURNING attempts`, tokenHash).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("fail login challenge: %w", err)
	}
	return n, nil
}

// DeleteLoginChallenge ends a challenge, and with it, expired ones.
func (s *Store) DeleteLoginChallenge(ctx context.Context, tokenHash string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM login_challenges WHERE token_hash = $1 OR expires_at <= now()`, tokenHash); err != nil {
		return fmt.Errorf("delete login challenge: %w", err)
	}
	return nil
}
