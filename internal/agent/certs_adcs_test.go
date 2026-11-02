package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCertreqPending(t *testing.T) {
	pending := "RequestId: 7\r\nRequestId: \"7\"\r\nCertificate request is pending: Taken Under Submission (0)\r\n"
	if id, ok := certreqPending(pending); !ok || id != "7" {
		t.Fatalf("pending not recognised: %q %v", id, ok)
	}
	issued := "RequestId: 8\r\nRequestId: \"8\"\r\nCertificate retrieved(Issued) Issued\r\n"
	if _, ok := certreqPending(issued); ok {
		t.Fatal("an issued certificate is not pending")
	}
	denied := "RequestId: 9\r\nCertificate not issued (Denied) Denied by Policy Module 0x80094012\r\n"
	if _, ok := certreqPending(denied); ok {
		t.Fatal("a denied request is not pending")
	}
}

func TestCheckADCSJobAndPEM(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"a.example.com"}}, key)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if err := checkADCSJob(csr, `ca01.ad.example.com\Example Enterprise CA`, "WebServer"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct{ config, tmpl string }{
		{`ca01.ad.example.com`, "WebServer"},
		{`ca01\x" & calc`, "WebServer"},
		{`ca01\CA`, `Web"Server`},
	} {
		if checkADCSJob(csr, bad.config, bad.tmpl) == nil {
			t.Errorf("accepted %q / %q", bad.config, bad.tmpl)
		}
	}
	if checkADCSJob("nope", `ca01\CA`, "WebServer") == nil {
		t.Error("accepted a missing CSR")
	}

	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	fromDER, err := pemCertificates(certDER)
	if err != nil || !strings.HasPrefix(fromDER, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("DER not converted: %v", err)
	}
	fromPEM, err := pemCertificates([]byte("junk\n" + fromDER))
	if err != nil || fromPEM != fromDER {
		t.Fatalf("PEM not kept: %v", err)
	}
	if _, err := pemCertificates([]byte("not a cert")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestParseRoot(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(ca bool) string {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "r"}, NotBefore: time.Now(),
			NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	r, err := parseRoot(mk(true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.file, "mustra-") || !strings.HasSuffix(r.file, ".crt") || len(r.sha1) != 40 {
		t.Fatalf("file %q thumbprint %q", r.file, r.sha1)
	}
	if _, err := parseRoot(mk(false)); err == nil {
		t.Fatal("a leaf certificate must not be pushed as a root")
	}
	if _, err := parseRoot("junk"); err == nil {
		t.Fatal("junk accepted")
	}
}
