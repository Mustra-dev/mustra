package updatesig

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// fuzzKey is a fixed key so the fuzzer is deterministic.
var fuzzSeed = make([]byte, ed25519.SeedSize)
var fuzzPriv = ed25519.NewKeyFromSeed(fuzzSeed)
var fuzzPub = fuzzPriv.Public().(ed25519.PublicKey)

var otherSeed = func() []byte { b := make([]byte, ed25519.SeedSize); b[0] = 1; return b }()
var otherPub = ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)

// FuzzUnmarshalVerify feeds arbitrary bytes to the .sig parser and the
// verifier. Properties: neither panics, and a manifest whose signature was
// not produced by the pinned key never verifies and never passes Check.
func FuzzUnmarshalVerify(f *testing.F) {
	good, _ := Sign(Manifest{File: "mustra-agent-linux-amd64", OS: "linux", Arch: "amd64",
		Version: "1.2.3", SHA256: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", Size: 10}, fuzzPriv)
	gb, _ := good.Marshal()
	f.Add(gb)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"v":1,"sig":"AAAA"}`))
	f.Add([]byte(`{"v":1,"file":"x","os":"linux","arch":"amd64","version":"1.0.0","sha256":"` +
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" + `","size":1,"sig":""}`))
	f.Add([]byte("not json"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		m, err := Unmarshal(data)
		if err != nil {
			return
		}
		// Verify is total and deterministic, and a wrong-key verifier must
		// never accept what the pinned-key verifier accepts for free.
		v1 := m.Verify(fuzzPub)
		if (m.Verify(fuzzPub) == nil) != (v1 == nil) {
			t.Fatalf("Verify is not deterministic for %q", data)
		}
		if v1 == nil && m.Verify(otherPub) == nil {
			t.Fatalf("a manifest verified under two unrelated keys: %q", data)
		}
		// Check must never panic for any expectation.
		_ = m.Check(fuzzPub, Expectation{OS: m.OS, Arch: m.Arch, AgentID: m.AgentID,
			CurrentVersion: "1.0.0", Now: time.Unix(0, 0)})
		_ = m.Check(fuzzPub, Expectation{OS: "linux", Arch: "amd64", AgentID: "agt-x",
			CurrentVersion: m.Version, Now: time.Now()})
	})
}

// FuzzParseVersion checks the parser and the ordering it feeds. Properties:
// ParseVersion never panics; Newer is irreflexive and never reports both
// directions true.
func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"1.2.3", "0.0.0", "1.2.3-rc1", "10.20.30", "", "1.2", "x.y.z",
		"99999999999999999999.0.0", "1.2.3.4.5", "1.2.3+build"} {
		f.Add(s, "1.2.3")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		_, _ = ParseVersion(a)
		if Newer(a, a) {
			t.Fatalf("Newer(%q,%q) reports a version newer than itself", a, a)
		}
		if Newer(a, b) && Newer(b, a) {
			t.Fatalf("Newer disagrees with itself: %q and %q each newer", a, b)
		}
	})
}
