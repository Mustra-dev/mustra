// Package vault is the credential vault backing the deploy page's
// network-scan-and-SSH-push flow: named SSH credentials (password or
// private key) encrypted at rest with AES-256-GCM. Plaintext exists only
// transiently — decrypted immediately before an SSH connection
// (internal/server/sshdeploy) and never logged, cached, or returned over
// HTTP once stored.
package vault

import (
	"bytes"
	"strings"

	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// Vault wraps the store's encrypted-blob CRUD with the actual encryption.
type Vault struct {
	store *store.Store
	gcm   cipher.AEAD
	// refuseLegacy, once set, makes Open reject a version-1 (unbound)
	// ciphertext instead of accepting it. It is turned on after every
	// stored value has been re-sealed as version 2 (MigrateLegacy with no
	// failures, recorded in a setting), so from then on a value downgraded
	// to the unbound format — by anyone who can write the database — no
	// longer decrypts and cannot be relocated between records.
	refuseLegacy bool
}

// RefuseLegacy turns strict mode on or off (see the field). The server
// enables it once re-sealing has completed.
func (v *Vault) RefuseLegacy(on bool) { v.refuseLegacy = on }

// New constructs a Vault. key must be exactly 32 bytes (AES-256) — see
// GenerateKey for producing one, and deploy/.env.example for how it's
// configured (MUSTRA_CREDENTIAL_ENCRYPTION_KEY).
func New(st *store.Store, key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("credential encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init GCM: %w", err)
	}
	return &Vault{store: st, gcm: gcm}, nil
}

// Ciphertext formats.
//
// Version 1 (no prefix) is nonce || AES-256-GCM(plaintext) with no
// associated data, which let anyone able to write the database move a
// ciphertext from one record to another -- one endpoint's BitLocker
// recovery password revealed (and audited) as another's, or one SSH
// credential's secret served under a different credential's name.
//
// Version 2 is v2Prefix || nonce || AES-256-GCM(plaintext, AD), where AD is
// v2Prefix plus a string naming the record and field the value belongs to
// (CredentialAAD, BitLockerAAD, SettingAAD). Moved anywhere else it fails
// to decrypt. Version 1 still decrypts, so existing secrets keep working,
// and MigrateLegacy rewrites stored ones as version 2 at startup.
var v2Prefix = []byte("mv2\x00")

// CredentialAAD binds a deploy credential's field ("secret" or
// "passphrase") to that credential.
func CredentialAAD(id, field string) string { return "deploy_credential/" + field + "/" + id }

// BitLockerAAD binds an escrowed recovery password to its endpoint and
// protector.
func BitLockerAAD(agentID, keyID string) string { return "bitlocker/" + agentID + "/" + keyID }

// SettingAAD binds an encrypted setting value to its key.
func SettingAAD(key string) string { return "setting/" + key }

// Seal encrypts plaintext bound to aad (version 2). The same aad must be
// given to Open.
func (v *Vault) Seal(plaintext, aad string) ([]byte, error) {
	nonce := make([]byte, v.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	out := append(append([]byte{}, v2Prefix...), nonce...)
	return v.gcm.Seal(out, nonce, []byte(plaintext), v.ad(aad)), nil
}

// Open decrypts a value sealed for aad. legacy reports a version-1
// ciphertext (no record binding), which the caller should re-seal.
func (v *Vault) Open(ciphertext []byte, aad string) (plaintext string, legacy bool, err error) {
	n := v.gcm.NonceSize()
	if bytes.HasPrefix(ciphertext, v2Prefix) && len(ciphertext) >= len(v2Prefix)+n {
		body := ciphertext[len(v2Prefix):]
		if pt, err := v.gcm.Open(nil, body[:n], body[n:], v.ad(aad)); err == nil {
			return string(pt), false, nil
		}
		// A version-1 nonce can start with the prefix bytes (one in 2^32);
		// only that case reaches the legacy path below and still opens.
	}
	if len(ciphertext) < n {
		return "", false, fmt.Errorf("ciphertext too short")
	}
	if v.refuseLegacy {
		// Every stored value has been re-sealed bound to its record; an
		// unbound value reaching here is a downgrade and is refused.
		return "", true, fmt.Errorf("decrypt: refusing an unbound (version-1) ciphertext after re-sealing")
	}
	pt, err := v.gcm.Open(nil, ciphertext[:n], ciphertext[n:], nil)
	if err != nil {
		return "", false, fmt.Errorf("decrypt: the value does not belong to this record or was encrypted with a different key")
	}
	return string(pt), true, nil
}

func (v *Vault) ad(aad string) []byte {
	return append(append([]byte{}, v2Prefix...), aad...)
}

// sealLegacy produces a version-1 ciphertext. Only tests use it, to stand
// in for values written before version 2.
func (v *Vault) sealLegacy(plaintext string) ([]byte, error) {
	nonce := make([]byte, v.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return v.gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// Create stores a new named credential. authType is "password" or
// "private_key" (secret is the PEM contents for the latter). passphrase is
// only meaningful for a passphrase-protected private_key — pass "" for a
// password credential or an unprotected key.
func (v *Vault) Create(ctx context.Context, name, username, authType, secretPlaintext, passphrase, createdBy string) (*store.DeployCredential, error) {
	id := idgen.New("cred-")
	cipherBytes, err := v.Seal(secretPlaintext, CredentialAAD(id, "secret"))
	if err != nil {
		return nil, err
	}
	var passphraseCipher []byte
	if passphrase != "" {
		passphraseCipher, err = v.Seal(passphrase, CredentialAAD(id, "passphrase"))
		if err != nil {
			return nil, err
		}
	}
	return v.store.CreateDeployCredential(ctx, id, name, username, authType, cipherBytes, passphraseCipher, createdBy)
}

// List returns credential metadata only — never secrets.
func (v *Vault) List(ctx context.Context) ([]store.DeployCredential, error) {
	return v.store.ListDeployCredentials(ctx)
}

// PublicKey derives the OpenSSH public key for a stored private-key
// credential, in authorized_keys format. Safe to show: a public key is
// public by definition, and having it on screen is what turns "the host
// rejected this key" into something you can actually fix.
func (v *Vault) PublicKey(ctx context.Context, id string) (string, error) {
	cred, err := v.Resolve(ctx, id)
	if err != nil {
		return "", err
	}
	if cred == nil {
		return "", fmt.Errorf("no such credential")
	}
	if cred.AuthType != "private_key" {
		return "", fmt.Errorf("credential %q is a password, not a key", id)
	}
	var signer ssh.Signer
	if cred.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cred.Secret), []byte(cred.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(cred.Secret))
	}
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " mustra-" + id, nil
}

func (v *Vault) Delete(ctx context.Context, id string) error {
	return v.store.DeleteDeployCredential(ctx, id)
}

// Decrypted is a credential with its plaintext secret (and passphrase, if
// the private key needs one), held only in memory for the duration of an
// SSH connection attempt.
type Decrypted struct {
	Username   string
	AuthType   string
	Secret     string
	Passphrase string // "" if not a passphrase-protected private_key
}

// Resolve decrypts one credential for immediate use establishing an SSH
// connection. Returns (nil, nil) if the credential doesn't exist.
func (v *Vault) Resolve(ctx context.Context, id string) (*Decrypted, error) {
	username, authType, cipherBytes, passphraseCipher, err := v.store.GetDeployCredentialCipher(ctx, id)
	if err != nil {
		return nil, err
	}
	if cipherBytes == nil {
		return nil, nil
	}
	secret, _, err := v.Open(cipherBytes, CredentialAAD(id, "secret"))
	if err != nil {
		return nil, fmt.Errorf("decrypt credential %s: %w", id, err)
	}
	var passphrase string
	if len(passphraseCipher) > 0 {
		passphrase, _, err = v.Open(passphraseCipher, CredentialAAD(id, "passphrase"))
		if err != nil {
			return nil, fmt.Errorf("decrypt credential %s passphrase: %w", id, err)
		}
	}
	return &Decrypted{Username: username, AuthType: authType, Secret: secret, Passphrase: passphrase}, nil
}

// GenerateKey returns a fresh random 32-byte AES-256 key, hex-encoded —
// used by the deploy tooling/docs to produce MUSTRA_CREDENTIAL_ENCRYPTION_KEY.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// MigrateLegacy re-seals every stored version-1 ciphertext (deploy
// credentials and escrowed recovery passwords) as version 2, bound to its
// record. It runs at startup and is idempotent: a version-2 value is left
// alone. Each row is rewritten only if it still holds the ciphertext that
// was read, so a concurrent change wins. A value that does not decrypt
// (a different key) is left as it is and counted.
func (v *Vault) MigrateLegacy(ctx context.Context) (migrated, failed int, err error) {
	creds, err := v.store.ListDeployCredentialCiphers(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, c := range creds {
		secret, legacyS, err := v.Open(c.SecretCipher, CredentialAAD(c.ID, "secret"))
		if err != nil {
			failed++
			continue
		}
		newSecret, newPass := c.SecretCipher, c.PassphraseCipher
		changed := false
		if legacyS {
			if newSecret, err = v.Seal(secret, CredentialAAD(c.ID, "secret")); err != nil {
				return migrated, failed, err
			}
			changed = true
		}
		if len(c.PassphraseCipher) > 0 {
			pass, legacyP, err := v.Open(c.PassphraseCipher, CredentialAAD(c.ID, "passphrase"))
			if err != nil {
				failed++
				continue
			}
			if legacyP {
				if newPass, err = v.Seal(pass, CredentialAAD(c.ID, "passphrase")); err != nil {
					return migrated, failed, err
				}
				changed = true
			}
		}
		if !changed {
			continue
		}
		ok, err := v.store.ReplaceDeployCredentialCipher(ctx, c.ID, c.SecretCipher, c.PassphraseCipher, newSecret, newPass)
		if err != nil {
			return migrated, failed, err
		}
		if ok {
			migrated++
		}
	}
	keys, err := v.store.ListBitLockerCiphers(ctx)
	if err != nil {
		return migrated, failed, err
	}
	for _, k := range keys {
		pw, legacy, err := v.Open(k.PasswordEnc, BitLockerAAD(k.AgentID, k.KeyID))
		if err != nil {
			failed++
			continue
		}
		if !legacy {
			continue
		}
		sealed, err := v.Seal(pw, BitLockerAAD(k.AgentID, k.KeyID))
		if err != nil {
			return migrated, failed, err
		}
		ok, err := v.store.ReplaceBitLockerCipher(ctx, k.AgentID, k.KeyID, k.PasswordEnc, sealed)
		if err != nil {
			return migrated, failed, err
		}
		if ok {
			migrated++
		}
	}
	return migrated, failed, nil
}
