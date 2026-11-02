package auth

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, with the secret "12345678901234567890"; a
// six-digit code is the low six digits of the RFC's eight.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestVerifyTOTPMatchesRFC6238(t *testing.T) {
	for _, tc := range []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	} {
		now := time.Unix(tc.unix, 0)
		step, ok := VerifyTOTP(rfcSecret, tc.code, now)
		if !ok || step != tc.unix/30 {
			t.Errorf("at %d: code %s: ok=%v step=%d, want step %d", tc.unix, tc.code, ok, step, tc.unix/30)
		}
	}
}

func TestVerifyTOTPWindowAndInput(t *testing.T) {
	key := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	at := time.Unix(1111111109, 0) // code 081804, step 37037036
	if _, ok := VerifyTOTP(key, "081 804", at); !ok {
		t.Error("a code typed with a space should be accepted")
	}
	if _, ok := VerifyTOTP(strings.ToLower(key), "081804", at); !ok {
		t.Error("a lower-case secret should still decode")
	}
	if step, ok := VerifyTOTP(key, "081804", at.Add(30*time.Second)); !ok || step != 37037036 {
		t.Errorf("the previous step's code should match one step late: ok=%v step=%d", ok, step)
	}
	if _, ok := VerifyTOTP(key, "081804", at.Add(90*time.Second)); ok {
		t.Error("a code three steps old must be refused")
	}
	for _, bad := range []string{"", "08180", "0818045", "abcdef"} {
		if _, ok := VerifyTOTP(key, bad, at); ok {
			t.Errorf("%q must be refused", bad)
		}
	}
	if _, ok := VerifyTOTP("not base32!", "081804", at); ok {
		t.Error("an undecodable secret must refuse every code")
	}
}

func TestNewTOTPSecretAndURI(t *testing.T) {
	a, b := NewTOTPSecret(), NewTOTPSecret()
	if a == b || len(a) != 32 {
		t.Fatalf("secrets should be fresh 160-bit base32 strings: %q %q", a, b)
	}
	u, err := url.Parse(OTPAuthURI("mustra", "jdoe@console.example", a))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || q.Get("secret") != a || q.Get("issuer") != "mustra" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Errorf("unexpected URI %s", u)
	}
	if !strings.HasPrefix(u.Path, "/mustra:jdoe@console.example") {
		t.Errorf("label should be issuer:account, got %q", u.Path)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes := NewRecoveryCodes(10)
	if len(codes) != 10 || len(hashes) != 10 {
		t.Fatalf("got %d codes, %d hashes", len(codes), len(hashes))
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 19 || strings.Count(c, "-") != 3 {
			t.Errorf("code %q is not xxxx-xxxx-xxxx-xxxx", c)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
		if HashRecoveryCode(c) != hashes[i] {
			t.Errorf("hash of %q does not match the stored one", c)
		}
		// Typed in upper case, without dashes, or with spaces around it.
		loose := " " + strings.ToUpper(strings.ReplaceAll(c, "-", "")) + " "
		if HashRecoveryCode(loose) != hashes[i] {
			t.Errorf("%q should normalize to %q", loose, c)
		}
	}
}
