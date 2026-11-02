package agent

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// fakeJIT replaces the OS halves for the duration of a test and records
// what they were asked to do.
type fakeJIT struct {
	accounts  map[string]bool
	createErr error
	deleteErr error
	deleted   []string
}

func installFakeJIT(t *testing.T) *fakeJIT {
	t.Helper()
	f := &fakeJIT{accounts: map[string]bool{}}
	oc, od := jitCreateAccount, jitDeleteAccount
	jitCreateAccount = func(_ context.Context, job proto.JITAccountJob) (string, error) {
		if f.accounts[job.Username] {
			return "", errJITExists
		}
		if f.createErr != nil {
			return "", f.createErr
		}
		f.accounts[job.Username] = true
		return "", nil
	}
	jitDeleteAccount = func(_ context.Context, name string) (string, error) {
		if f.deleteErr != nil {
			return "", f.deleteErr
		}
		f.deleted = append(f.deleted, name)
		delete(f.accounts, name)
		return "", nil
	}
	t.Cleanup(func() { jitCreateAccount, jitDeleteAccount = oc, od })
	return f
}

func jitTestAgent(t *testing.T) *Agent {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := New(Config{})
	a.store = st
	return a
}

func TestJITRefusesNamesItDidNotMint(t *testing.T) {
	f := installFakeJIT(t)
	a := jitTestAgent(t)
	for _, name := range []string{"Administrator", "root", "mustra-", "mustra-ABCDEF", "mustra-abc", "mustra-abcdef/../x", "xmustra-abcdef", "mustra-abcdef\n"} {
		if _, err := a.jitRemove(context.Background(), name); err == nil {
			t.Errorf("jitRemove(%q) succeeded; only minted names may be removed", name)
		}
		if _, err := a.jitCreate(context.Background(), proto.JITAccountJob{Username: name, Password: "x", ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
			t.Errorf("jitCreate(%q) succeeded", name)
		}
	}
	if len(f.deleted) != 0 || len(f.accounts) != 0 {
		t.Fatalf("an invalid name reached the OS: deleted %v, created %v", f.deleted, f.accounts)
	}
}

func TestJITCreateRecordsAndSweepRemovesExpired(t *testing.T) {
	f := installFakeJIT(t)
	a := jitTestAgent(t)
	now := time.Now()
	for _, j := range []proto.JITAccountJob{
		{Username: "mustra-aaaaaa", Password: "p", ExpiresAt: now.Add(time.Hour)},
		{Username: "mustra-bbbbbb", AuthorizedKey: "ssh-ed25519 AAAA", ExpiresAt: now.Add(2 * time.Hour)},
	} {
		if _, err := a.jitCreate(context.Background(), j); err != nil {
			t.Fatal(err)
		}
	}
	a.sweepJIT(context.Background(), now.Add(90*time.Minute))
	if strings.Join(f.deleted, ",") != "mustra-aaaaaa" {
		t.Fatalf("sweep removed %v, want only the expired account", f.deleted)
	}
	recs, _ := a.store.listJIT()
	if len(recs) != 1 || recs[0].Username != "mustra-bbbbbb" {
		t.Fatalf("records after sweep: %+v", recs)
	}
}

func TestJITFailedRemovalIsRetried(t *testing.T) {
	f := installFakeJIT(t)
	a := jitTestAgent(t)
	if _, err := a.jitCreate(context.Background(), proto.JITAccountJob{Username: "mustra-cccccc", Password: "p", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	f.deleteErr = errors.New("busy")
	a.sweepJIT(context.Background(), time.Now().Add(time.Hour))
	if recs, _ := a.store.listJIT(); len(recs) != 1 {
		t.Fatal("a failed removal dropped the record; the sweep would never retry it")
	}
	f.deleteErr = nil
	a.sweepJIT(context.Background(), time.Now().Add(time.Hour))
	if recs, _ := a.store.listJIT(); len(recs) != 0 || f.accounts["mustra-cccccc"] {
		t.Fatal("the retry did not remove the account")
	}
}

func TestJITCreateFailureIsUndone(t *testing.T) {
	f := installFakeJIT(t)
	a := jitTestAgent(t)
	f.createErr = errors.New("group add failed")
	if _, err := a.jitCreate(context.Background(), proto.JITAccountJob{Username: "mustra-dddddd", Password: "p", ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("expected the failure")
	}
	if strings.Join(f.deleted, ",") != "mustra-dddddd" {
		t.Fatalf("a half-made account was not undone: %v", f.deleted)
	}
	if recs, _ := a.store.listJIT(); len(recs) != 0 {
		t.Fatalf("records after undo: %+v", recs)
	}
}

func TestJITNeverUndoesAnAccountItDidNotMake(t *testing.T) {
	f := installFakeJIT(t)
	a := jitTestAgent(t)
	f.accounts["mustra-eeeeee"] = true // made by someone else
	_, err := a.jitCreate(context.Background(), proto.JITAccountJob{Username: "mustra-eeeeee", Password: "p", ExpiresAt: time.Now().Add(time.Hour)})
	if !errors.Is(err, errJITExists) {
		t.Fatalf("err = %v, want errJITExists", err)
	}
	if len(f.deleted) != 0 || !f.accounts["mustra-eeeeee"] {
		t.Fatal("the pre-existing account was deleted")
	}
	if recs, _ := a.store.listJIT(); len(recs) != 0 {
		t.Fatal("the pre-existing account was recorded, so the sweep would delete it")
	}
}

func TestJITDeadlineIsCapped(t *testing.T) {
	installFakeJIT(t)
	a := jitTestAgent(t)
	if _, err := a.jitCreate(context.Background(), proto.JITAccountJob{Username: "mustra-ffffff", Password: "p", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	recs, _ := a.store.listJIT()
	if len(recs) != 1 || time.Until(recs[0].ExpiresAt) > jitMaxLifetime {
		t.Fatalf("deadline not capped: %+v", recs)
	}
	if _, err := a.jitCreate(context.Background(), proto.JITAccountJob{Username: "mustra-gggggg", Password: "p", ExpiresAt: time.Now().Add(-time.Minute)}); err == nil {
		t.Fatal("an already-passed deadline was accepted")
	}
}

// A Windows profile still loaded at removal: the account is gone, so the
// server hears success, but the profile stays on record and the sweep
// deletes it once Windows lets go of it.
func TestJITLeftoverProfileIsRetried(t *testing.T) {
	f := installFakeJIT(t)
	a := jitTestAgent(t)
	if _, err := a.jitCreate(context.Background(), proto.JITAccountJob{Username: "mustra-hhhhhh", Password: "p", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	jitDeleteAccount = func(_ context.Context, name string) (string, error) {
		delete(f.accounts, name)
		return "", &jitProfilePending{SID: "S-1-5-21-1-2-3-1004"}
	}
	busy := true
	var tries int
	od := jitDeleteProfile
	jitDeleteProfile = func(sid string) (bool, error) {
		tries++
		if sid != "S-1-5-21-1-2-3-1004" {
			t.Errorf("retried the wrong profile %q", sid)
		}
		return !busy, nil
	}
	t.Cleanup(func() { jitDeleteProfile = od })

	if _, err := a.jitRemove(context.Background(), "mustra-hhhhhh"); err != nil {
		t.Fatalf("a removed account with a busy profile must count as removed: %v", err)
	}
	recs, _ := a.store.listJIT()
	if len(recs) != 1 || recs[0].ProfileSID == "" {
		t.Fatalf("the leftover profile was not kept for the sweep: %+v", recs)
	}
	a.sweepJIT(context.Background(), time.Now())
	if recs, _ := a.store.listJIT(); len(recs) != 1 || tries != 1 {
		t.Fatalf("a still-busy profile was dropped: %+v (tries %d)", recs, tries)
	}
	busy = false
	a.sweepJIT(context.Background(), time.Now())
	if recs, _ := a.store.listJIT(); len(recs) != 0 {
		t.Fatalf("the deleted profile's record remains: %+v", recs)
	}
}

func TestJITLeftoverProfileGivesUp(t *testing.T) {
	installFakeJIT(t)
	a := jitTestAgent(t)
	od := jitDeleteProfile
	jitDeleteProfile = func(string) (bool, error) { return false, errors.New("in use") }
	t.Cleanup(func() { jitDeleteProfile = od })
	old := time.Now().Add(-jitProfileRetryFor - time.Hour)
	if err := a.store.putJIT(jitRecord{Username: "mustra-iiiiii", ProfileSID: "S-1-5-21-9", RemovedAt: old, ExpiresAt: old}); err != nil {
		t.Fatal(err)
	}
	a.sweepJIT(context.Background(), time.Now())
	if recs, _ := a.store.listJIT(); len(recs) != 0 {
		t.Fatal("a profile past its retry window is retried forever")
	}
}

func TestJITOrphanProfilePattern(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Users\ADMIN_mustra-cep9us`:       true, // what DESKTOP01 made
		`C:\Users\mustra-cep9us1v`:           true,
		`C:\Users\mustra-cep9us1v.DESKTOP01`: true,
		`C:\Users\jdoe`:                      false,
		`C:\Users\mustra`:                    false,
		`C:\Users\mustra-admin\Documents`:    false,
		`C:\Users\my-mustra-cep9us1v-backup`: false,
		`D:\Profiles\notmustra-abcdef\x`:     false,
	} {
		if got := jitOrphanProfilePattern.MatchString(path); got != want {
			t.Errorf("%s: matched %v, want %v", path, got, want)
		}
	}
}
