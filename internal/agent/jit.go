package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Temporary sign-in accounts for remote sessions (JIT).
//
// The server asks for a local administrator just before a remote session
// opens and for its removal when the session ends. The agent keeps its own
// record of every account it made, with a deadline, and removes expired
// ones itself every minute: a server that is down, a connection that never
// comes back, or a removal that failed once must not leave an administrator
// behind. The record is written before the account is created, so even a
// crash between the two is cleaned up.
//
// Only names of the shape the server mints (mustra-<random>) are accepted,
// for creation and for removal alike. That is the whole of what stops a
// compromised or confused control plane from using jit_remove to delete
// Administrator or root, so it is checked here, on the endpoint.

var jitBucket = []byte("jit_accounts")

var jitNamePattern = regexp.MustCompile(`^mustra-[a-z0-9]{6,12}$`)

// jitOrphanProfilePattern matches the folder Windows gives a temporary
// account's profile: its name, possibly shortened, possibly with a prefix
// (one endpoint named one ADMIN_mustra-cep9us).
var jitOrphanProfilePattern = regexp.MustCompile(`(?i)\\(?:[a-z0-9]+_)?mustra-[a-z0-9]{4,12}(?:\.[a-z0-9-]+)?$`)

// jitMaxLifetime caps a deadline the server sends: a long Jump Gate window
// still gets an account that cannot outlive a working day.
const jitMaxLifetime = 24 * time.Hour

type jitRecord struct {
	Username  string    `json:"username"`
	SessionID string    `json:"session_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	// ProfileSID is set once the account is gone but its profile (a
	// Windows profile still loaded at removal) is not; the sweep retries
	// it until it is, for up to jitProfileRetryFor.
	ProfileSID string    `json:"profile_sid,omitempty"`
	RemovedAt  time.Time `json:"removed_at,omitempty"`
}

// jitProfilePending is what an OS half returns when it removed the
// account but not yet its profile. The account is what matters for
// access, so the removal counts as done; the profile is left to the sweep.
type jitProfilePending struct{ SID string }

func (e *jitProfilePending) Error() string { return "profile " + e.SID + " not yet deleted" }

const jitProfileRetryFor = 7 * 24 * time.Hour

// The OS-specific halves (jit_windows.go, jit_linux.go, jit_darwin.go).
// Variables so tests can run the bookkeeping without touching accounts.
var (
	jitCreateAccount  = jitCreateAccountOS
	jitDeleteAccount  = jitDeleteAccountOS
	jitDeleteProfile  = jitDeleteProfileOS
	jitOrphanProfiles = jitOrphanProfilesOS
)

func validJITName(name string) bool { return jitNamePattern.MatchString(name) }

// errJITExists is what the OS halves return for a name already taken. It
// is never undone: the account it names is not one this request made.
var errJITExists = errors.New("an account with that name already exists")

func (a *Agent) jitCreate(ctx context.Context, job proto.JITAccountJob) (string, error) {
	if !validJITName(job.Username) {
		return "", fmt.Errorf("refusing account name %q: temporary accounts are named mustra-<random>", job.Username)
	}
	if job.Password == "" && job.AuthorizedKey == "" {
		return "", errors.New("a temporary account needs a password or a key")
	}
	now := time.Now()
	if !job.ExpiresAt.After(now) {
		return "", errors.New("the account's deadline has already passed")
	}
	if job.ExpiresAt.Sub(now) > jitMaxLifetime {
		job.ExpiresAt = now.Add(jitMaxLifetime)
	}
	a.jitMu.Lock()
	defer a.jitMu.Unlock()
	if existing, err := a.store.listJIT(); err == nil {
		for _, r := range existing {
			if r.Username == job.Username {
				return "", errJITExists
			}
		}
	}
	if err := a.store.putJIT(jitRecord{Username: job.Username, SessionID: job.SessionID, ExpiresAt: job.ExpiresAt, CreatedAt: now}); err != nil {
		return "", fmt.Errorf("recording the account before creating it: %w", err)
	}
	out, err := jitCreateAccount(ctx, job)
	if errors.Is(err, errJITExists) {
		_ = a.store.deleteJIT(job.Username)
		return out, err
	}
	if err != nil {
		// Undo whatever part of it exists. The record stays if that fails
		// too, so the sweep keeps trying.
		if _, derr := jitDeleteAccount(ctx, job.Username); derr == nil {
			_ = a.store.deleteJIT(job.Username)
		}
		return out, err
	}
	a.logger.Info("temporary account created", "username", job.Username, "session", job.SessionID, "expires_at", job.ExpiresAt)
	return out, nil
}

func (a *Agent) jitRemove(ctx context.Context, username string) (string, error) {
	if !validJITName(username) {
		return "", fmt.Errorf("refusing to remove %q: only temporary mustra-<random> accounts are removed", username)
	}
	a.jitMu.Lock()
	defer a.jitMu.Unlock()
	out, err := jitDeleteAccount(ctx, username)
	var pending *jitProfilePending
	if errors.As(err, &pending) {
		// Keep the record, now for the profile alone, so the sweep can
		// finish the job; the account itself is gone.
		if perr := a.store.putJIT(jitRecord{Username: username, ProfileSID: pending.SID, RemovedAt: time.Now(), ExpiresAt: time.Now()}); perr != nil {
			a.logger.Warn("temporary account removed but its leftover profile could not be recorded", "username", username, "error", perr)
		}
		a.logger.Info("temporary account removed; its profile will be deleted when Windows releases it", "username", username)
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := a.store.deleteJIT(username); err != nil {
		a.logger.Warn("temporary account removed but its record was not", "username", username, "error", err)
	}
	a.logger.Info("temporary account removed", "username", username)
	return out, nil
}

// runJITSweep removes accounts past their deadline, at start (an endpoint
// that was off when one expired) and every minute after.
func (a *Agent) runJITSweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		a.sweepJIT(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Agent) sweepJIT(ctx context.Context, now time.Time) {
	records, err := a.store.listJIT()
	if err != nil {
		a.logger.Warn("listing temporary accounts failed", "error", err)
		return
	}
	// Profiles of temporary accounts that are gone but not on record (left
	// by an older agent) are taken on, to be deleted like any other.
	known := map[string]bool{}
	for _, r := range records {
		known[r.ProfileSID] = true
	}
	for _, sid := range jitOrphanProfiles() {
		if known[sid] {
			continue
		}
		r := jitRecord{Username: "orphan-profile-" + sid, ProfileSID: sid, RemovedAt: now, ExpiresAt: now}
		if err := a.store.putJIT(r); err == nil {
			records = append(records, r)
		}
	}
	for _, r := range records {
		if r.ProfileSID != "" {
			a.sweepJITProfile(r, now)
			continue
		}
		if r.ExpiresAt.After(now) {
			continue
		}
		if _, err := a.jitRemove(ctx, r.Username); err != nil {
			a.logger.Warn("removing an expired temporary account failed; retrying next minute", "username", r.Username, "error", err)
		}
	}
}

// sweepJITProfile retries deleting the profile a removed account left
// behind, and gives up (with a warning) after jitProfileRetryFor.
func (a *Agent) sweepJITProfile(r jitRecord, now time.Time) {
	gone, err := jitDeleteProfile(r.ProfileSID)
	switch {
	case gone:
		a.logger.Info("leftover profile of a temporary account deleted", "username", r.Username, "sid", r.ProfileSID)
	case now.Sub(r.RemovedAt) > jitProfileRetryFor:
		a.logger.Warn("giving up on a temporary account's leftover profile", "username", r.Username, "sid", r.ProfileSID, "error", err)
	default:
		return
	}
	if err := a.store.deleteJIT(r.Username); err != nil {
		a.logger.Warn("dropping a temporary account's record failed", "username", r.Username, "error", err)
	}
}

func (s *Store) putJIT(r jitRecord) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(jitBucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(r.Username), raw)
	})
}

func (s *Store) deleteJIT(username string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(jitBucket); b != nil {
			return b.Delete([]byte(username))
		}
		return nil
	})
}

func (s *Store) listJIT() ([]jitRecord, error) {
	var out []jitRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(jitBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var r jitRecord
			if json.Unmarshal(v, &r) == nil {
				out = append(out, r)
			}
			return nil
		})
	})
	return out, err
}
