package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, cn string) (tls.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A fake broker that, like NATS, sends a plain INFO line and then upgrades
// to TLS. The agent's CA file is a different authority from the one the
// server presents; the diagnosis has to name both, so the mismatch is
// visible in one log line.
func TestTLSDiagnosisNamesBothSides(t *testing.T) {
	serverCert, _ := selfSigned(t, "mustra-nats")
	_, otherCA := selfSigned(t, "some other CA")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("INFO {\"tls_required\":true}\r\n"))
		tls.Server(c, &tls.Config{Certificates: []tls.Certificate{serverCert}}).Handshake()
	}()
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(caFile, otherCA, 0o600)

	f := tlsDiagnosis("tls://"+ln.Addr().String(), caFile)
	got := map[string]string{}
	for i := 0; i+1 < len(f); i += 2 {
		got[f[i].(string)] = toString(f[i+1])
	}
	if got["ca_subject"] != "CN=some other CA" || got["server_subject"] != "CN=mustra-nats" || got["server_issuer"] != "CN=mustra-nats" {
		t.Fatalf("diagnosis: %v", got)
	}
	if got["ca_sha256"] == "" || got["ca_sha256"] == got["server_sha256"] || !strings.Contains(got["server_names"], "127.0.0.1") {
		t.Fatalf("fingerprints and names: %v", got)
	}

	missing := tlsDiagnosis("tls://127.0.0.1:1", filepath.Join(t.TempDir(), "gone.crt"))
	if !strings.Contains(toString(missing[3]), "unreadable") {
		t.Fatalf("a missing CA file should say so: %v", missing)
	}
}

func TestIsCertificateError(t *testing.T) {
	if !isCertificateError(errors.New("nats: tls error: tls: failed to verify certificate: x509: certificate signed by unknown authority")) {
		t.Error("unknown authority not recognised")
	}
	if isCertificateError(errors.New("nats: no servers available for connection")) || isCertificateError(nil) {
		t.Error("an unreachable broker is not a certificate problem")
	}
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}
