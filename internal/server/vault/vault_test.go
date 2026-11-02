package vault

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

func testVault(t *testing.T, st *store.Store) *Vault {
	t.Helper()
	v, err := New(st, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A sealed value opens only for the record it was sealed for: copying one
// endpoint's recovery password onto another, or one credential's secret
// onto another, must fail rather than decrypt.
func TestSealedValuesAreBoundToTheirRecord(t *testing.T) {
	v := testVault(t, nil)
	ct, err := v.Seal("hunter2", BitLockerAAD("agent-a", "key-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(ct, v2Prefix) {
		t.Fatal("new ciphertexts must carry the version-2 prefix")
	}
	pt, legacy, err := v.Open(ct, BitLockerAAD("agent-a", "key-1"))
	if err != nil || pt != "hunter2" || legacy {
		t.Fatalf("own record: %q legacy=%v err=%v", pt, legacy, err)
	}
	for _, other := range []string{
		BitLockerAAD("agent-b", "key-1"), BitLockerAAD("agent-a", "key-2"),
		CredentialAAD("agent-a", "key-1"), SettingAAD("x"), "",
	} {
		if _, _, err := v.Open(ct, other); err == nil {
			t.Errorf("value sealed for agent-a/key-1 opened as %q", other)
		}
	}
	// Field separation within one credential.
	sec, _ := v.Seal("pw", CredentialAAD("cred-1", "secret"))
	if _, _, err := v.Open(sec, CredentialAAD("cred-1", "passphrase")); err == nil {
		t.Error("a secret opened as the passphrase")
	}
}

// Values written before version 2 still decrypt, reported as legacy so
// they get re-sealed.
func TestLegacyCiphertextStillOpens(t *testing.T) {
	v := testVault(t, nil)
	old, err := v.sealLegacy("old secret")
	if err != nil {
		t.Fatal(err)
	}
	pt, legacy, err := v.Open(old, CredentialAAD("cred-1", "secret"))
	if err != nil || pt != "old secret" || !legacy {
		t.Fatalf("legacy: %q legacy=%v err=%v", pt, legacy, err)
	}
	other, _ := New(nil, bytes.Repeat([]byte{8}, 32))
	if _, _, err := other.Open(old, ""); err == nil {
		t.Error("a different key opened the value")
	}
}

// MigrateLegacy re-seals stored version-1 values bound to their records,
// and a second pass finds nothing to do.
func TestMigrateLegacyReseals(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to disposable Postgres")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Registered first so it runs last: the row cleanups below need the pool.
	t.Cleanup(st.Close)
	v := testVault(t, st)
	secret, _ := v.sealLegacy("legacy-password")
	pass, _ := v.sealLegacy("legacy-passphrase")
	cred, err := st.CreateDeployCredential(ctx, idgen.New("cred-vault-mig-"), "mig", "root", "private_key", secret, pass, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteDeployCredential(context.Background(), cred.ID) })
	modern, err := v.Create(ctx, "modern", "root", "password", "new-password", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteDeployCredential(context.Background(), modern.ID) })

	migrated, failed, err := v.MigrateLegacy(ctx)
	if err != nil || failed != 0 || migrated < 1 {
		t.Fatalf("migrate: migrated=%d failed=%d err=%v", migrated, failed, err)
	}
	_, _, sc, pc, err := st.GetDeployCredentialCipher(ctx, cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(sc, v2Prefix) || !bytes.HasPrefix(pc, v2Prefix) {
		t.Fatal("legacy credential was not re-sealed")
	}
	got, err := v.Resolve(ctx, cred.ID)
	if err != nil || got.Secret != "legacy-password" || got.Passphrase != "legacy-passphrase" {
		t.Fatalf("re-sealed credential: %+v %v", got, err)
	}
	if got, err := v.Resolve(ctx, modern.ID); err != nil || got.Secret != "new-password" {
		t.Fatalf("modern credential: %+v %v", got, err)
	}
	again, failed, err := v.MigrateLegacy(ctx)
	if err != nil || failed != 0 {
		t.Fatal(err)
	}
	// Other tests may leave legacy rows behind in a shared database, but
	// none of ours remain.
	_ = again
	_, _, sc2, _, _ := st.GetDeployCredentialCipher(ctx, cred.ID)
	if !bytes.Equal(sc, sc2) {
		t.Error("a second pass rewrote an already re-sealed value")
	}
}

// After re-sealing has completed, strict mode refuses an unbound
// (version-1) ciphertext, so a value downgraded by a database writer no
// longer decrypts and cannot be relocated between records. Version-2
// values still open (review minor).
func TestRefuseLegacyRejectsUnboundCiphertext(t *testing.T) {
	v := testVault(t, nil)
	legacyCT, err := v.sealLegacy("old secret")
	if err != nil {
		t.Fatal(err)
	}
	boundCT, err := v.Seal("new secret", CredentialAAD("cred-1", "secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Before strict mode the legacy value still opens (migration needs it).
	if _, legacy, err := v.Open(legacyCT, CredentialAAD("cred-1", "secret")); err != nil || !legacy {
		t.Fatalf("pre-strict legacy open: legacy=%v err=%v", legacy, err)
	}

	v.RefuseLegacy(true)
	if _, _, err := v.Open(legacyCT, CredentialAAD("cred-1", "secret")); err == nil {
		t.Fatal("strict mode accepted an unbound version-1 ciphertext")
	}
	// A bound value is unaffected.
	if pt, legacy, err := v.Open(boundCT, CredentialAAD("cred-1", "secret")); err != nil || legacy || pt != "new secret" {
		t.Fatalf("strict mode broke a bound value: %q legacy=%v err=%v", pt, legacy, err)
	}
}
