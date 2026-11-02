package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func testCertAndKey(t *testing.T) (certPEM, keyPEM string, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "upload.example.com"},
		DNSNames: []string{"upload.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})), cert, key
}

func TestParseUpload(t *testing.T) {
	certPEM, keyPEM, cert, key := testCertAndKey(t)
	u, err := parseUpload(certPEM, keyPEM, "", "")
	if err != nil || u.Leaf.Subject.CommonName != "upload.example.com" {
		t.Fatalf("PEM pair: %v", err)
	}
	// DER certificate, as a .cer file arrives (base64 from the browser).
	if _, err := parseUpload(base64.StdEncoding.EncodeToString(cert.Raw), keyPEM, "", ""); err != nil {
		t.Errorf("DER certificate: %v", err)
	}
	// A key that is not the certificate's.
	_, otherKey, _, _ := testCertAndKey(t)
	if _, err := parseUpload(certPEM, otherKey, "", ""); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("a mismatched key must be refused: %v", err)
	}
	if _, err := parseUpload(certPEM, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", "", ""); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("an encrypted key needs a clear message: %v", err)
	}
	// A modern (AES) PFX with its password, and with the wrong one.
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseUpload("", "", base64.StdEncoding.EncodeToString(pfx), "s3cret"); err != nil {
		t.Errorf("PFX: %v", err)
	}
	if _, err := parseUpload("", "", base64.StdEncoding.EncodeToString(pfx), "wrong"); err == nil {
		t.Error("a wrong PFX password must fail")
	}
	// For the Windows store it is repacked as a PFX the agent can import.
	job, err := u.installJob(true)
	if err != nil || job.PFXBase64 == "" || job.PFXPassword == "" || job.KeyPEM != "" {
		t.Fatalf("store job: %+v %v", job, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(job.PFXBase64)
	if _, c, err := pkcs12.Decode(raw, job.PFXPassword); err != nil || c.SerialNumber.Int64() != 7 {
		t.Errorf("the repacked PFX must open with its password: %v", err)
	}
	if job, _ := u.installJob(false); job.KeyPEM == "" || job.PFXBase64 != "" {
		t.Error("file targets get the key as PEM")
	}
}
