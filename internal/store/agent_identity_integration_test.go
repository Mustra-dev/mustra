package store

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
)

func testAgentID(t *testing.T) string {
	t.Helper()
	// agt- plus 32 hex, the shape internal/nats.ValidAgentID accepts.
	id := idgen.New("agt-")
	if len(id) != 36 {
		t.Fatalf("unexpected agent id shape %q", id)
	}
	return id
}

// Enrolment must not hand out an identity the requester has not proven,
// and a revoked identity must stay revoked (review finding: a revoked
// credential row was deleted, so its host could claim the ID again; any
// token holder could name any not-yet-enrolled agent's ID).
func TestEnrollmentCannotClaimOrResurrectIdentities(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Applying the schema again must be harmless (upgrade path).
	if err := applySchema(ctx, s.pool); err != nil {
		t.Fatal("repeated migration:", err)
	}

	tokenHash := "hash-" + idgen.New("tok-")
	if err := s.CreateEnrollmentToken(ctx, EnrollmentToken{ID: idgen.New("tok-"), Label: "it", MaxUses: 10,
		CreatedBy: "test", ExpiresAt: time.Now().Add(time.Hour)}, tokenHash); err != nil {
		t.Fatal(err)
	}

	// A legacy-era agent that has registered but not enrolled.
	legacyID := testAgentID(t)
	if err := s.UpsertOnRegister(ctx, legacyID, proto.AgentInfo{Hostname: "legacy-host", OS: "linux"}); err != nil {
		t.Fatal(err)
	}

	// 1. A token holder naming that ID gets a fresh one instead.
	got, _, err := s.EnrollWithToken(ctx, tokenHash, legacyID, testAgentID(t), "secret-a")
	if err != nil {
		t.Fatal(err)
	}
	if got == legacyID {
		t.Fatal("token enrolment took over a not-yet-enrolled agent's ID")
	}

	// 2. The legacy agent itself keeps its ID through legacy enrolment.
	got, err = s.EnrollLegacy(ctx, legacyID, testAgentID(t), "secret-b")
	if err != nil {
		t.Fatal(err)
	}
	if got != legacyID {
		t.Fatalf("legacy self-enrolment did not keep the agent's ID: got %s", got)
	}

	// 3. An ID this server has never seen is not minted on request.
	unknown := testAgentID(t)
	got, err = s.EnrollLegacy(ctx, unknown, testAgentID(t), "secret-c")
	if err != nil {
		t.Fatal(err)
	}
	if got == unknown {
		t.Fatal("legacy enrolment minted an identity of the requester's choosing")
	}

	// 4. Revocation is a tombstone: the ID cannot authenticate, still
	// counts as enrolled for the legacy deny list, and cannot be claimed
	// back by legacy or token enrolment.
	ok, err := s.RevokeAgentCredential(ctx, legacyID)
	if err != nil || !ok {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	if again, _ := s.RevokeAgentCredential(ctx, legacyID); again {
		t.Fatal("revoking twice reported a second revocation")
	}
	if h, err := s.AgentCredentialHash(ctx, legacyID); err != nil || h != "" {
		t.Fatalf("revoked credential still authenticates: %q %v", h, err)
	}
	if has, err := s.AgentHasCredential(ctx, legacyID); err != nil || !has {
		t.Fatalf("revoked identity no longer counts as enrolled: %v %v", has, err)
	}
	ids, err := s.ListCredentialAgentIDs(ctx)
	if err != nil || !slices.Contains(ids, legacyID) {
		t.Fatalf("revoked identity missing from the legacy deny list: %v", err)
	}
	if _, err := s.EnrollLegacy(ctx, legacyID, testAgentID(t), "secret-d"); !errors.Is(err, ErrIdentityEnrolled) {
		t.Fatalf("legacy enrolment resurrected a revoked identity: %v", err)
	}
	got, _, err = s.EnrollWithToken(ctx, tokenHash, legacyID, testAgentID(t), "secret-e")
	if err != nil {
		t.Fatal(err)
	}
	if got == legacyID {
		t.Fatal("token enrolment resurrected a revoked identity")
	}

	// 5. The console shows the revoked agent as needing re-enrolment.
	list, err := s.ListAgentIdentities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		if a.AgentID == legacyID && (a.Enrolled || a.RevokedAt == nil) {
			t.Fatalf("revoked agent listed as %+v", a)
		}
	}
}
