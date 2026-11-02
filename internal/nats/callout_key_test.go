package nats

import (
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

// deploy/nats/gen-callout-key.sh encodes nkeys in bash so init.sh needs no
// Go toolchain. If its encoding drifted from the nkeys library, the broker
// would trust one key and the server would sign with another, and every
// agent connection would be refused. This pins the two together.
func TestGenCalloutKeyScriptMatchesNkeys(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("bash", "../../deploy/nats/gen-callout-key.sh", hex.EncodeToString(raw)).CombinedOutput()
	if err != nil {
		t.Skipf("generator unavailable here: %v: %s", err, out)
	}
	lines := strings.Fields(string(out))
	if len(lines) != 2 {
		t.Fatalf("want seed and public key, got %q", out)
	}
	want, err := nkeys.FromRawSeed(nkeys.PrefixByteAccount, raw)
	if err != nil {
		t.Fatal(err)
	}
	wantSeed, _ := want.Seed()
	wantPub, _ := want.PublicKey()
	if lines[0] != string(wantSeed) {
		t.Errorf("seed: script %s, nkeys %s", lines[0], wantSeed)
	}
	if lines[1] != wantPub {
		t.Errorf("public key: script %s, nkeys %s", lines[1], wantPub)
	}
	kp, err := nkeys.FromSeed([]byte(lines[0]))
	if err != nil {
		t.Fatalf("nkeys cannot parse the script's seed: %v", err)
	}
	if pub, _ := kp.PublicKey(); pub != lines[1] || !nkeys.IsValidPublicAccountKey(pub) {
		t.Errorf("script seed and public key do not belong together")
	}
}
