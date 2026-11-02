package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/vault"
)

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.New(nil, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSecretsSealAndOpen(t *testing.T) {
	v := testVault(t)
	sealed, err := sealWith(v, oidcSecretAAD("sso"), "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "vault:") || strings.Contains(sealed, "s3cret") {
		t.Fatalf("not sealed: %q", sealed)
	}
	if got, err := openWith(v, oidcSecretAAD("sso"), sealed); err != nil || got != "s3cret" {
		t.Fatalf("open: %q %v", got, err)
	}
	// Bound to its record: one provider's ciphertext can't be replayed as another's.
	if _, err := openWith(v, oidcSecretAAD("google"), sealed); err == nil {
		t.Fatal("a secret sealed for one provider opened for another")
	}
	// Without a vault the value is marked plain rather than silently sealed.
	if p, _ := sealWith(nil, "x", "abc"); p != "plain:abc" {
		t.Fatalf("no vault: %q", p)
	}
	if _, err := openWith(nil, "x", sealed); err == nil {
		t.Fatal("a sealed secret opened without a vault")
	}
}

// Values written before sealing existed carry no prefix and must keep
// working until the startup pass seals them.
func TestLegacyPlainSecretsStillRead(t *testing.T) {
	for _, v := range []*vault.Vault{nil, testVault(t)} {
		if got, err := openWith(v, "setting/scim.token", "abcdef0123"); err != nil || got != "abcdef0123" {
			t.Fatalf("legacy read: %q %v", got, err)
		}
	}
	for stored, want := range map[string]bool{"": true, "vault:AAAA": true, "plain:x": true, "raw-token": false} {
		if sealedAlready(stored) != want {
			t.Errorf("sealedAlready(%q) = %v", stored, !want)
		}
	}
	if s, err := sealWith(testVault(t), "x", ""); err != nil || s != "" {
		t.Fatal("an empty secret must stay empty (it means keep the stored one)")
	}
}
