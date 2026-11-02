package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestBlockedAddr(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00:ec2::254", "::ffff:127.0.0.1", "224.0.0.1",
		// NAT64 well-known (RFC 6052) and local-use (RFC 8215) prefixes
		// embedding an internal IPv4.
		"64:ff9b::7f00:1", "64:ff9b:1::a01:203"} {
		if !blockedAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s not blocked", a)
		}
	}
	for _, a := range []string{"1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"} {
		if blockedAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s blocked", a)
		}
	}
}

// The guarded client refuses an https server on loopback unless the host
// is allowlisted — the check happens at dial time, on the resolved address.
func TestGuardedClientRefusesInternalAddresses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	c := guardedHTTPClient(map[string]bool{}, 5*time.Second)
	_, err := c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("loopback fetch: err = %v, want refusal", err)
	}
	// Redirects to an internal host are refused the same way.
	if _, err := c.Get("https://localhost:1/"); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("localhost: err = %v, want refusal", err)
	}
	// Allowlisted: the dial is permitted (TLS then fails on the test cert,
	// which is the point — it got as far as connecting).
	c = guardedHTTPClient(map[string]bool{"127.0.0.1": true}, 5*time.Second)
	if _, err := c.Get(srv.URL); err != nil && strings.Contains(err.Error(), "internal address") {
		t.Fatalf("allowlisted host still refused: %v", err)
	}
}

func TestSSHHostKeyCallbacks(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	key := signer.PublicKey()
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	signer2, _ := ssh.NewSignerFromKey(priv2)
	other := signer2.PublicKey()

	if err := pinnedHostKey(key)("h:22", nil, key); err != nil {
		t.Fatalf("pinned key refused: %v", err)
	}
	if err := pinnedHostKey(key)("h:22", nil, other); err == nil {
		t.Fatal("a changed host key was accepted")
	}
	var seen ssh.PublicKey
	if err := fingerprintHostKey(ssh.FingerprintSHA256(key), &seen)("h:22", nil, key); err != nil || seen == nil {
		t.Fatalf("confirmed fingerprint refused: %v", err)
	}
	seen = nil
	if err := fingerprintHostKey(ssh.FingerprintSHA256(key), &seen)("h:22", nil, other); err == nil || seen != nil {
		t.Fatal("a key with a different fingerprint was accepted")
	}
	if _, _, err := sshClientConfig(nil, nil); err == nil {
		t.Fatal("an SSH config without host key verification was built")
	}
}
