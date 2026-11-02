package server

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	bnats "github.com/mustra-dev/mustra/internal/nats"
)

// The shared agent credential is retired (#231): with identity enforced,
// the callout refuses it under either name and refuses trading it for a
// credential, even with the right password, and before touching the store.
func TestCalloutRefusesRetiredLegacyCredential(t *testing.T) {
	s := &Server{logger: slog.Default(), trust: &agentTrust{legacyUser: "fleet-agents", legacyPassword: "the-old-shared-password"}}
	for _, user := range []string{bnats.LegacyAgentUser, "fleet-agents", bnats.LegacyEnrollUser(strings.Repeat("ab", 16))} {
		perms, as, ttl, reason := s.authorizeConnection(context.Background(), user, "the-old-shared-password")
		if as != "" || ttl != 0 || len(perms.PubAllow)+len(perms.SubAllow) != 0 || !strings.Contains(reason, "retired") {
			t.Errorf("%s: authorized as %q for %s (%q)", user, as, ttl, reason)
		}
	}
	if s.legacySubjectsAccepted(context.Background()) != true {
		t.Error("without the callout, the identity-free subjects are all there is")
	}
}
