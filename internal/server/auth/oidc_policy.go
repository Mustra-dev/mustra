package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// OIDCPolicy decides which IdP accounts may sign in at all.
//
// Configuring "Sign in with Google" (or Discord, or any IdP anyone can make
// an account at) used to admit every account it could authenticate. A
// console that runs commands on a fleet needs a positive list, so SSO
// refuses every sign-in until at least one rule exists, and then admits
// only accounts that match one.
type OIDCPolicy struct {
	// AllowedDomains admits verified email addresses in these domains.
	AllowedDomains []string
	// AllowedEmails admits these verified email addresses.
	AllowedEmails []string
	// AllowedGroups admits accounts whose GroupsClaim includes one of
	// these values.
	AllowedGroups []string
	// GroupsClaim is the ID-token claim carrying group membership
	// ("groups" when empty).
	GroupsClaim string
}

// HasRules reports whether any allowlist rule is configured.
func (p OIDCPolicy) HasRules() bool {
	return len(p.AllowedDomains)+len(p.AllowedEmails)+len(p.AllowedGroups) > 0
}

// Allows checks one sign-in's claims. Email rules need email_verified to
// be true: an unverified address is just a string the account's owner
// typed in.
func (p OIDCPolicy) Allows(claims map[string]any) (bool, string) {
	if !p.HasRules() {
		return false, "no SSO allowlist rule is configured"
	}
	email, _ := claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	verified := false
	switch v := claims["email_verified"].(type) {
	case bool:
		verified = v
	case string:
		verified = strings.EqualFold(v, "true")
	}
	if email != "" && verified {
		for _, e := range p.AllowedEmails {
			if strings.EqualFold(strings.TrimSpace(e), email) {
				return true, ""
			}
		}
		if at := strings.LastIndexByte(email, '@'); at > 0 {
			domain := email[at+1:]
			for _, d := range p.AllowedDomains {
				d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
				if d != "" && domain == d {
					return true, ""
				}
			}
		}
	}
	if len(p.AllowedGroups) > 0 {
		claim := p.GroupsClaim
		if claim == "" {
			claim = "groups"
		}
		have := map[string]bool{}
		switch v := claims[claim].(type) {
		case []any:
			for _, g := range v {
				if s, ok := g.(string); ok {
					have[s] = true
				}
			}
		case string:
			for _, g := range strings.Split(v, ",") {
				have[strings.TrimSpace(g)] = true
			}
		}
		for _, g := range p.AllowedGroups {
			if g = strings.TrimSpace(g); g != "" && have[g] {
				return true, ""
			}
		}
	}
	if email != "" && !verified && (len(p.AllowedDomains)+len(p.AllowedEmails) > 0) {
		return false, "the IdP did not mark this account's email address as verified"
	}
	return false, "this account matches no SSO allowlist rule"
}

// SplitList parses a comma- or newline-separated list, dropping blanks.
func SplitList(v string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SetOIDCPolicySource tells Auth where to read the current allowlist. It
// is read on every sign-in, so a Settings change applies to the next one.
func (a *Auth) SetOIDCPolicySource(f func(ctx context.Context) OIDCPolicy) {
	a.mu.Lock()
	a.policy = f
	a.mu.Unlock()
}

func (a *Auth) oidcPolicy(ctx context.Context) OIDCPolicy {
	a.mu.RLock()
	f := a.policy
	a.mu.RUnlock()
	if f == nil {
		return OIDCPolicy{}
	}
	return f(ctx)
}

// usernameFromClaims chooses the username for a first sign-in.
func usernameFromClaims(preferred, email, subject string) string {
	for _, c := range []string{preferred, email, subject} {
		c = strings.TrimSpace(c)
		if c == "" || len(c) > 200 || strings.IndexFunc(c, unicode.IsControl) >= 0 {
			continue
		}
		return c
	}
	return "sso-user"
}

// disambiguatedUsername is what a first sign-in gets when the name it
// asked for already belongs to another account. Attaching to that account
// is exactly the takeover this avoids.
func disambiguatedUsername(base, issuer, subject string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return fmt.Sprintf("%s-%s", base, hex.EncodeToString(sum[:4]))
}
