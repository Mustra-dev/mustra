package auth

import "golang.org/x/crypto/bcrypt"

// HashPassword bcrypt-hashes a password for storage.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword reports whether password matches the stored bcrypt hash.
func VerifyPassword(hash, password string) bool {
	if hash == "" {
		return false // SSO/SCIM-only accounts have no password hash — never authenticate them locally
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
