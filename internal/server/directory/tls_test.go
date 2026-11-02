package directory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// A self-signed certificate naming a host, as a domain controller's
// usually does, served on a loopback address it does not name -- the
// shape of pointing mustra at a DC by IP.
func selfSigned(t *testing.T, dnsName string) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pemBytes)
}

func serve(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func TestPinnedSelfSignedCertificateByIP(t *testing.T) {
	cert, pemStr := selfSigned(t, "dc.example.internal")
	addr := serve(t, cert)
	host, _, _ := net.SplitHostPort(addr)

	cfg, err := tlsConfigFor(Config{CAPEM: pemStr}, host)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("pinned certificate should verify by IP: %v", err)
	}
	c.Close()

	// A different certificate, even from a name the URL would match, is
	// refused: the pin is the check.
	other, otherPEM := selfSigned(t, "dc.example.internal")
	_ = other
	cfg2, _ := tlsConfigFor(Config{CAPEM: otherPEM}, host)
	if c, err := tls.Dial("tcp", addr, cfg2); err == nil {
		c.Close()
		t.Fatal("a certificate that is not the pinned one was accepted")
	}

	// Without a pin, the standard verifier applies and an IP with no SAN
	// fails as it should.
	cfg3, _ := tlsConfigFor(Config{}, host)
	if c, err := tls.Dial("tcp", addr, cfg3); err == nil {
		c.Close()
		t.Fatal("an unpinned self-signed certificate was accepted")
	}
}
