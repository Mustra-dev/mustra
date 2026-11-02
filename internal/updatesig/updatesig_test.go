package updatesig

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

const agentA = "agt-0123456789abcdef0123456789abcdef"

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func base() Manifest {
	return Manifest{File: "mustra-agent-linux-amd64", OS: "linux", Arch: "amd64", Version: "0.80.0",
		SHA256: strings.Repeat("ab", 32), Size: 1234}
}

func want(cur string) Expectation {
	return Expectation{OS: "linux", Arch: "amd64", AgentID: agentA, CurrentVersion: cur, Now: time.Now()}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	m, err := Sign(base(), priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := m.Marshal()
	back, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Check(pub, want("0.79.1")); err != nil {
		t.Fatalf("good upgrade refused: %v", err)
	}
	if back.KeyID != KeyID(pub) {
		t.Error("key id not recorded")
	}
}

func TestTamperingIsRefused(t *testing.T) {
	pub, priv := testKey(t)
	m, _ := Sign(base(), priv)
	for name, mut := range map[string]func(*Manifest){
		"digest":  func(m *Manifest) { m.SHA256 = strings.Repeat("cd", 32) },
		"version": func(m *Manifest) { m.Version = "9.9.9" },
		"os":      func(m *Manifest) { m.OS = "darwin" },
		"size":    func(m *Manifest) { m.Size++ },
		"downgrade": func(m *Manifest) {
			m.AllowDowngrade = true
			m.AgentID = agentA
			m.Expires = time.Now().Add(time.Hour).Unix()
		},
		"sig": func(m *Manifest) { m.Sig = "AAAA" },
	} {
		c := m
		mut(&c)
		if err := c.Check(pub, want("0.79.1")); err == nil {
			t.Errorf("%s: tampered manifest accepted", name)
		}
	}
	other, _ := testKey(t)
	if err := m.Check(other, want("0.79.1")); err == nil {
		t.Error("manifest accepted under a different key")
	}
}

func TestDowngradeRules(t *testing.T) {
	pub, priv := testKey(t)
	old := base()
	old.Version = "0.70.0"
	m, _ := Sign(old, priv)
	if err := m.Check(pub, want("0.80.0")); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("unsigned downgrade not refused: %v", err)
	}
	same, _ := Sign(base(), priv)
	if err := same.Check(pub, want("0.80.0")); err == nil {
		t.Error("reinstall of the same version accepted as an update")
	}

	auth := old
	auth.AllowDowngrade, auth.AgentID, auth.Expires = true, agentA, time.Now().Add(time.Hour).Unix()
	signed, err := Sign(auth, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.Check(pub, want("0.80.0")); err != nil {
		t.Errorf("authorized downgrade refused: %v", err)
	}
	w := want("0.80.0")
	w.AgentID = "agt-ffffffffffffffffffffffffffffffff"
	if err := signed.Check(pub, w); err == nil {
		t.Error("downgrade for another agent accepted")
	}
	w = want("0.80.0")
	w.Now = time.Now().Add(2 * time.Hour)
	if err := signed.Check(pub, w); err == nil {
		t.Error("expired downgrade accepted")
	}
	if _, err := Sign(Manifest{File: "x", OS: "linux", Arch: "amd64", Version: "1.0.0", SHA256: strings.Repeat("ab", 32), Size: 1, AllowDowngrade: true}, priv); err == nil {
		t.Error("open-ended downgrade manifest signed")
	}
}

func TestPlatformMismatch(t *testing.T) {
	pub, priv := testKey(t)
	m, _ := Sign(base(), priv)
	w := want("0.79.1")
	w.Arch = "arm64"
	if err := m.Check(pub, w); err == nil {
		t.Error("wrong-arch build accepted")
	}
}

func TestKeyParsing(t *testing.T) {
	pub, priv := testKey(t)
	back, err := ParsePublicKey(EncodePublicKey(pub))
	if err != nil || !back.Equal(pub) {
		t.Fatalf("public key round trip: %v", err)
	}
	seed := EncodePublicKey(ed25519.PublicKey(priv.Seed())) // same base64 of 32 bytes
	k, err := ParsePrivateKey(seed)
	if err != nil || !k.Equal(priv) {
		t.Fatalf("seed parse: %v", err)
	}
	if _, err := ParsePublicKey("bm90IGEga2V5"); err == nil {
		t.Error("short key accepted")
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.35.10", "0.35.9", true}, {"0.35.9", "0.35.10", false}, {"1.0.0", "1.0.0-rc", true}, {"1.0.0-rc", "1.0.0", false}, {"dev", "1.0.0", false}} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q)=%v", c.a, c.b, got)
		}
	}
}
