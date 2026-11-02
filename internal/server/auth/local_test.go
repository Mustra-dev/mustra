package auth

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestSanitizeNextRejectsOffSiteTargets(t *testing.T) {
	bad := []string{
		"", "evil.example", "//evil.example", `/\evil.example`, `/\/evil.example`,
		"/\t/evil.example", "/\n/evil.example", "/\r//evil.example", `/foo\bar`,
		"https://evil.example", "/%09/evil.example\x00", "///evil.example",
		"javascript:alert(1)", "/\x7f",
	}
	for _, n := range bad {
		if got := sanitizeNext(n); got != "/" {
			t.Errorf("sanitizeNext(%q) = %q, want /", n, got)
		}
	}
	good := []string{"/", "/agents", "/endpoint/agt-1?tab=processes", "/patches#x", "/a/b%2Fc"}
	for _, n := range good {
		if got := sanitizeNext(n); got != n {
			t.Errorf("sanitizeNext(%q) = %q, want unchanged", n, got)
		}
	}
}

func TestLoginLimiterBacksOff(t *testing.T) {
	l := newLoginLimiter()
	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < limitPerIPUser-1; i++ {
		l.fail("10.0.0.1", "admin")
		if l.blocked("10.0.0.1", "admin") != 0 {
			t.Fatalf("blocked after %d failures, want only from %d", i+1, limitPerIPUser)
		}
	}
	l.fail("10.0.0.1", "admin")
	first := l.blocked("10.0.0.1", "admin")
	if first <= 0 {
		t.Fatal("not blocked after the threshold")
	}
	// The lock is about the account name, not whether it exists, and is
	// case-insensitive so ADMIN is not a fresh budget.
	if l.blocked("10.0.0.1", "ADMIN") == 0 {
		t.Fatal("case change escaped the limit")
	}
	if l.blocked("10.0.0.2", "admin") != 0 {
		t.Fatal("a different address was blocked by the per-address-and-user key alone")
	}
	now = now.Add(first + time.Millisecond)
	l.fail("10.0.0.1", "admin")
	if second := l.blocked("10.0.0.1", "admin"); second <= first {
		t.Fatalf("backoff did not grow: %v then %v", first, second)
	}
	l.succeed("10.0.0.1", "admin")
	if l.blocked("10.0.0.1", "admin") != 0 {
		t.Fatal("success did not clear the account counters")
	}
}

// Break-glass must stay reachable: failures from many addresses against the
// owner's account must not lock the owner out from a fresh address (review
// minor: a per-username cross-IP lock was a DoS against emergency access).
// Per-address brute-force protection still applies.
func TestLoginLimiterDoesNotLockAnAccountAcrossAddresses(t *testing.T) {
	l := newLoginLimiter()
	// Far past any old per-username threshold, each from its own address.
	for i := 0; i < 100; i++ {
		l.fail("10.1."+itoa(i/250)+"."+itoa(i%250+1), "owner")
	}
	if l.blocked("192.0.2.9", "owner") != 0 {
		t.Fatal("a distributed guess locked the owner out from a fresh address")
	}
	// A single address hammering the account is still locked out.
	for i := 0; i < limitPerIPUser; i++ {
		l.fail("198.51.100.1", "owner")
	}
	if l.blocked("198.51.100.1", "owner") == 0 {
		t.Fatal("per-address brute force was not throttled")
	}
	// And one address spraying many accounts is still bounded by the
	// per-address key.
	l2 := newLoginLimiter()
	for i := 0; i < limitPerIP; i++ {
		l2.fail("203.0.113.5", "acct"+itoa(i))
	}
	if l2.blocked("203.0.113.5", "acctX") == 0 {
		t.Fatal("per-address spray was not throttled")
	}
}

func TestClientIPIgnoresForwardedHeadersFromUntrustedPeers(t *testing.T) {
	old := trustedProxies
	defer func() { trustedProxies = old }()
	trustedProxies = nil
	r := httptest.NewRequest("POST", "/login/local", nil)
	r.RemoteAddr = "198.51.100.7:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("CF-Connecting-IP", "5.6.7.8")
	if got := ClientIP(r); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want the TCP peer", got)
	}
	trustedProxies = parseTrustedProxies("198.51.100.0/24")
	if got := ClientIP(r); got != "5.6.7.8" {
		t.Fatalf("ClientIP behind a trusted proxy = %q, want 5.6.7.8", got)
	}
}
