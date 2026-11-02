//go:build !windows

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

func signCSR(t *testing.T, csrPEM string) string {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject, DNSNames: csr.DNSNames,
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, csr.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Pi-hole's layout: key and certificate in one file, owner and mode kept.
func TestCertRenewCombinedAndRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.pem")
	os.WriteFile(path, []byte("old"), 0o600)

	csr, err := certCSR(proto.CertJob{RequestID: "r1", Names: []string{"pi.hole"}})
	if err != nil || !strings.Contains(csr, "CERTIFICATE REQUEST") {
		t.Fatalf("csr: %v", err)
	}
	out, err := certInstall(context.Background(), proto.CertJob{RequestID: "r1", CertPath: path, CertPEM: signCSR(t, csr), ReloadCmd: "true"})
	if err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "EC PRIVATE KEY") || !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Fatalf("combined file: %s", data)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	baks, _ := filepath.Glob(path + ".mustra-bak-*")
	for _, b := range baks {
		if st, _ := os.Stat(b); st.Mode().Perm() != 0o600 {
			t.Errorf("backup %s mode %v; it holds a private key", b, st.Mode().Perm())
		}
	}

	// A reload that fails puts the previous file back.
	before, _ := os.ReadFile(path)
	csr2, _ := certCSR(proto.CertJob{RequestID: "r2", Names: []string{"pi.hole"}})
	if _, err := certInstall(context.Background(), proto.CertJob{RequestID: "r2", CertPath: path, CertPEM: signCSR(t, csr2), ReloadCmd: "exit 3"}); err == nil {
		t.Fatal("a failed reload must fail the install")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Error("the previous certificate was not restored")
	}
}

func TestCertRenewSeparateFilesAndKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "site.crt"), filepath.Join(dir, "site.key")
	csr, _ := certCSR(proto.CertJob{RequestID: "s1", Names: []string{"a.example", "b.example"}})
	if _, err := certInstall(context.Background(), proto.CertJob{RequestID: "s1", CertPath: cert, KeyPath: key, CertPEM: signCSR(t, csr)}); err != nil {
		t.Fatal(err)
	}
	if c, _ := os.ReadFile(cert); strings.Contains(string(c), "PRIVATE KEY") {
		t.Error("the certificate file must not hold the key")
	}
	if k, _ := os.ReadFile(key); !strings.Contains(string(k), "EC PRIVATE KEY") {
		t.Error("key file missing the key")
	}
	// A certificate for a different key is refused before anything is written.
	other, _ := certCSR(proto.CertJob{RequestID: "s2", Names: []string{"x"}})
	_, _ = certCSR(proto.CertJob{RequestID: "s3", Names: []string{"x"}})
	if _, err := certInstall(context.Background(), proto.CertJob{RequestID: "s3", CertPath: cert, KeyPath: key, CertPEM: signCSR(t, other)}); err == nil {
		t.Error("a certificate for another key must be refused")
	}
	if _, err := certInstall(context.Background(), proto.CertJob{RequestID: "nope", CertPath: cert, CertPEM: "x"}); err == nil {
		t.Error("an unknown request must be refused")
	}
}

func TestModeManagedByFS(t *testing.T) {
	if !modeManagedByFS(&os.PathError{Op: "chmod", Path: "/etc/pve/local/x", Err: os.ErrPermission}) {
		t.Error("EPERM from a filesystem that sets its own modes must be tolerated")
	}
	if modeManagedByFS(&os.PathError{Op: "chmod", Path: "/x", Err: os.ErrNotExist}) {
		t.Error("other errors still fail the install")
	}
}
