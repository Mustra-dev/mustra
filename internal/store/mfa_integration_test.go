package store

import (
	"context"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
)

func TestTOTPLifecyclePostgres(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	id := idgen.New("usr-mfa-")
	if _, err := s.CreateLocalUser(ctx, id, id, "x", "MFA test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id) })

	if tt, err := s.GetUserTOTP(ctx, id); err != nil || tt == nil || tt.Enabled() {
		t.Fatalf("a new account has no factor: %+v %v", tt, err)
	}
	if err := s.EnableTOTP(ctx, id, 5, nil); err == nil {
		t.Fatal("enabling with nothing pending must fail")
	}
	if ok, err := s.SetPendingTOTP(ctx, id, []byte("sealed-1")); err != nil || !ok {
		t.Fatalf("pending: %v %v", ok, err)
	}
	if err := s.EnableTOTP(ctx, id, 100, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	tt, _ := s.GetUserTOTP(ctx, id)
	if !tt.Enabled() || tt.LastStep != 100 {
		t.Fatalf("after enabling: %+v", tt)
	}
	// An enabled factor is not replaced by a new setup.
	if ok, _ := s.SetPendingTOTP(ctx, id, []byte("sealed-2")); ok {
		t.Fatal("setup must not replace an enabled secret")
	}
	// The step that enabled it, or an older one, cannot be used again.
	for _, step := range []int64{99, 100} {
		if ok, _ := s.AdvanceTOTPStep(ctx, id, step); ok {
			t.Fatalf("step %d replayed", step)
		}
	}
	if ok, _ := s.AdvanceTOTPStep(ctx, id, 101); !ok {
		t.Fatal("a newer step should be accepted")
	}
	// Recovery codes are single-use.
	if n, _ := s.RecoveryCodesLeft(ctx, id); n != 2 {
		t.Fatalf("codes left %d", n)
	}
	if ok, _ := s.UseRecoveryCode(ctx, id, "h1"); !ok {
		t.Fatal("first use should succeed")
	}
	if ok, _ := s.UseRecoveryCode(ctx, id, "h1"); ok {
		t.Fatal("second use must fail")
	}
	if ok, _ := s.UseRecoveryCode(ctx, id, "nope"); ok {
		t.Fatal("unknown code must fail")
	}
	if err := s.ReplaceRecoveryCodes(ctx, id, []string{"h3"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.RecoveryCodesLeft(ctx, id); n != 1 {
		t.Fatalf("after replacing, codes left %d", n)
	}
	if err := s.DisableTOTP(ctx, id); err != nil {
		t.Fatal(err)
	}
	if tt, _ := s.GetUserTOTP(ctx, id); tt.Enabled() || tt.Secret != nil {
		t.Fatalf("after disabling: %+v", tt)
	}
	if n, _ := s.RecoveryCodesLeft(ctx, id); n != 0 {
		t.Fatal("disabling must drop recovery codes")
	}

	// Challenges: counted, expiring, deleted.
	if err := s.CreateLoginChallenge(ctx, "ch-"+id, id, "totp", "/agents", time.Minute); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetLoginChallenge(ctx, "ch-"+id)
	if err != nil || c == nil || c.Purpose != "totp" || c.Next != "/agents" || c.UserID != id {
		t.Fatalf("challenge: %+v %v", c, err)
	}
	if n, _ := s.FailLoginChallenge(ctx, "ch-"+id); n != 1 {
		t.Fatalf("attempts %d", n)
	}
	if err := s.DeleteLoginChallenge(ctx, "ch-"+id); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetLoginChallenge(ctx, "ch-"+id); c != nil {
		t.Fatal("deleted challenge still found")
	}
	if err := s.CreateLoginChallenge(ctx, "old-"+id, id, "totp", "/", 0); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetLoginChallenge(ctx, "old-"+id); c != nil {
		t.Fatal("an expired challenge must not be returned")
	}
}
