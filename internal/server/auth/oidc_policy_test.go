package auth

import (
	"strings"
	"testing"
)

func TestOIDCPolicyRefusesEverythingWithoutRules(t *testing.T) {
	ok, why := OIDCPolicy{}.Allows(map[string]any{"email": "a@example.com", "email_verified": true})
	if ok || !strings.Contains(why, "no SSO allowlist rule") {
		t.Fatalf("empty policy admitted a sign-in (%v, %q)", ok, why)
	}
}

func TestOIDCPolicyRules(t *testing.T) {
	p := OIDCPolicy{AllowedDomains: []string{"Example.com"}, AllowedEmails: []string{"ops@partner.net"}, AllowedGroups: []string{"mustra-ops"}}
	cases := []struct {
		claims map[string]any
		want   bool
	}{
		{map[string]any{"email": "alice@example.com", "email_verified": true}, true},
		{map[string]any{"email": "ALICE@EXAMPLE.COM", "email_verified": "true"}, true},
		{map[string]any{"email": "alice@example.com"}, false},                          // unverified
		{map[string]any{"email": "alice@example.com", "email_verified": false}, false}, // unverified
		{map[string]any{"email": "alice@evil-example.com", "email_verified": true}, false},
		{map[string]any{"email": "alice@sub.example.com", "email_verified": true}, false},
		{map[string]any{"email": "alice@example.com.evil.net", "email_verified": true}, false},
		{map[string]any{"email": "ops@partner.net", "email_verified": true}, true},
		{map[string]any{"groups": []any{"x", "mustra-ops"}}, true},
		{map[string]any{"groups": []any{"mustra-ops-not"}}, false},
		{map[string]any{"sub": "only"}, false},
	}
	for _, c := range cases {
		if got, why := p.Allows(c.claims); got != c.want {
			t.Errorf("Allows(%v) = %v (%s), want %v", c.claims, got, why, c.want)
		}
	}
	custom := OIDCPolicy{AllowedGroups: []string{"admins"}, GroupsClaim: "roles"}
	if ok, _ := custom.Allows(map[string]any{"roles": []any{"admins"}}); !ok {
		t.Fatal("custom groups claim not honoured")
	}
	if ok, _ := custom.Allows(map[string]any{"groups": []any{"admins"}}); ok {
		t.Fatal("the default claim was read although another was configured")
	}
}

func TestDisambiguatedUsernameIsStable(t *testing.T) {
	a := disambiguatedUsername("alice", "https://idp-a", "1")
	if a != disambiguatedUsername("alice", "https://idp-a", "1") || a == disambiguatedUsername("alice", "https://idp-b", "1") || a == "alice" {
		t.Fatal("disambiguated username is not a stable function of (issuer, subject)")
	}
}
