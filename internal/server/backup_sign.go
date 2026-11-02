package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Backup signatures.
//
// The manifest's SHA-256 only proves an archive agrees with itself: whoever
// wrote the dump wrote the checksum too. A restore runs the dump through
// psql as the database owner, so "agrees with itself" is not enough. Each
// backup this server takes is signed with HMAC-SHA256 under a key the
// server holds and the archive does not, and a restore refuses an archive
// that is unsigned or signed by anyone else — unless an administrator uses
// the explicit external-import path, which screens the dump strictly first.
//
// The key, in order of preference:
//
//  1. MUSTRA_BACKUP_SIGNING_KEY (hex, at least 32 bytes);
//  2. derived from MUSTRA_CREDENTIAL_ENCRYPTION_KEY, which a deployment
//     already keeps safe and restores with the database;
//  3. a random key generated once into MUSTRA_BACKUP_SIGNING_KEY_FILE
//     (default /var/lib/mustra/backup-signing.key, mode 0600).
//
// None of these is inside a backup.

var backupKeyMu sync.Mutex

func (s *Server) backupSigningKey() ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("MUSTRA_BACKUP_SIGNING_KEY")); v != "" {
		k, err := hex.DecodeString(v)
		if err != nil || len(k) < 32 {
			return nil, fmt.Errorf("MUSTRA_BACKUP_SIGNING_KEY must be at least 32 bytes of hex")
		}
		return k, nil
	}
	if len(s.cfg.CredentialEncryptionKey) >= 32 {
		mac := hmac.New(sha256.New, s.cfg.CredentialEncryptionKey)
		mac.Write([]byte("mustra backup signing v1"))
		return mac.Sum(nil), nil
	}
	path := os.Getenv("MUSTRA_BACKUP_SIGNING_KEY_FILE")
	if path == "" {
		path = "/var/lib/mustra/backup-signing.key"
	}
	backupKeyMu.Lock()
	defer backupKeyMu.Unlock()
	if b, err := os.ReadFile(path); err == nil {
		k, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(k) < 32 {
			return nil, fmt.Errorf("%s does not hold a usable backup signing key", path)
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("no backup signing key: set MUSTRA_BACKUP_SIGNING_KEY or MUSTRA_CREDENTIAL_ENCRYPTION_KEY (%w)", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("no backup signing key: set MUSTRA_BACKUP_SIGNING_KEY or MUSTRA_CREDENTIAL_ENCRYPTION_KEY (%w)", err)
	}
	s.logger.Warn("generated a backup signing key; keep it with the deployment's other secrets, or set MUSTRA_BACKUP_SIGNING_KEY", "file", path)
	return k, nil
}

// manifestMAC is the signature over every manifest field but itself.
func manifestMAC(key []byte, m BackupManifest) string {
	m.Signature = ""
	blob, _ := json.Marshal(m)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("mustra-backup-manifest\x00"))
	mac.Write(blob)
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyManifest(key []byte, m BackupManifest) bool {
	if m.Signature == "" || len(key) == 0 {
		return false
	}
	want := manifestMAC(key, m)
	return hmac.Equal([]byte(want), []byte(m.Signature))
}

// treeDigest accumulates the package-file members of an archive in the
// order they appear, so the manifest covers them as well as the dump.
type treeDigest struct{ h hashWriter }

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func newTreeDigest() *treeDigest { return &treeDigest{h: sha256.New()} }

func (t *treeDigest) add(name string, fileSHA []byte) {
	fmt.Fprintf(t.h, "%s\x00%x\n", name, fileSHA)
}

func (t *treeDigest) sum() string { return hex.EncodeToString(t.h.Sum(nil)) }
