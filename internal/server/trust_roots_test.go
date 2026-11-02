package server

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

	"github.com/mustra-dev/mustra/internal/store"
)

func TestTrustDue(t *testing.T) {
	now := time.Now()
	cases := []struct {
		mode, state string
		age         time.Duration
		want        bool
	}{
		{"all", "", 0, true},
		{"all", "installed", 0, false},
		{"all", "removed", 0, true},
		{"all", "failed", time.Hour, false},
		{"all", "failed", 7 * time.Hour, true},
		{"all", "unsupported", 7 * time.Hour, false},
		{"all", "unsupported", 25 * time.Hour, true},
		{"remove", "installed", 0, true},
		{"remove", "", 0, false},
		{"remove", "failed", 48 * time.Hour, false},
	}
	for _, c := range cases {
		got := trustDue(c.mode, store.RootTrust{State: c.state, UpdatedAt: now.Add(-c.age)}, now)
		if got != c.want {
			t.Errorf("mode %s state %q age %s: got %v", c.mode, c.state, c.age, got)
		}
	}
}

func TestRootProfileIsStableAndParses(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test <Root> & Co"}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	root := trustRootInfo{Name: "Test <Root> & Co", pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	a, err := rootProfile(root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := rootProfile(root)
	if string(a) != string(b) {
		t.Fatal("the profile must be identical for the same root, so a re-push replaces it")
	}
	v, err := parsePlist(a)
	if err != nil {
		t.Fatalf("profile is not a valid plist: %v", err)
	}
	m := v.(map[string]any)
	if m["PayloadType"] != "Configuration" || !strings.HasPrefix(m["PayloadIdentifier"].(string), "dev.mustra.trust.") {
		t.Fatalf("unexpected profile: %v", m)
	}
}
