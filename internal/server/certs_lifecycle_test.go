package server

import (
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestIssuanceStatusAndRevocable(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(30*24*time.Hour)
	base := store.CertIssuance{CA: "private", Serial: "1a2b", NotAfter: &future, CertPEM: "x"}
	cases := []struct {
		name   string
		mod    func(*store.CertIssuance)
		status string
		why    string // "" = revocable; else a word the reason contains
	}{
		{"active", func(*store.CertIssuance) {}, "active", ""},
		{"superseded is still revocable", func(c *store.CertIssuance) { c.SupersededAt = &past }, "superseded", ""},
		{"expired", func(c *store.CertIssuance) { c.NotAfter = &past }, "expired", "expired"},
		{"revoked", func(c *store.CertIssuance) { c.RevokedAt = &past }, "revoked", "already"},
		{"tailscale", func(c *store.CertIssuance) { c.CA = "tailscale" }, "active", "Tailscale"},
		{"acme without the certificate", func(c *store.CertIssuance) { c.CA, c.CertPEM = "acme", "" }, "active", "Let's Encrypt"},
		{"no serial", func(c *store.CertIssuance) { c.Serial = "" }, "active", "serial"},
	}
	for _, tc := range cases {
		c := base
		tc.mod(&c)
		if got := issuanceStatus(c, now); got != tc.status {
			t.Errorf("%s: status %q, want %q", tc.name, got, tc.status)
		}
		why := revocableWhy(c, now)
		if (tc.why == "") != (why == "") || (tc.why != "" && !strings.Contains(why, tc.why)) {
			t.Errorf("%s: revocable reason %q, want one mentioning %q", tc.name, why, tc.why)
		}
	}
}
