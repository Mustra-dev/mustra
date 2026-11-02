package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/updatesig"
)

// This agent's identity on the bus.
//
// Every agent used to log in as the same shared user, with permissions that
// let it publish as, and listen in on, every other agent. Now each one has
// its own credential — its agent ID and a random secret, of which the
// server keeps only a hash — and the broker scopes it to its own subjects.
//
// It gets that credential once, by enrolling:
//
//   - with an enrollment token an administrator created, which the
//     installer leaves in enroll.token beside the identity database; or
//   - automatically, if it still holds the old shared password and the
//     operator still accepts it, by trading the password for a credential.
//
// The credential lives in agent-credential.json beside the identity
// database: mode 0600 on Linux and macOS, and on Windows a file whose DACL
// admits only SYSTEM and Administrators (identity_windows.go). Never an
// environment variable — those are world-readable on Windows and inherited
// by every command the agent runs everywhere.

const (
	credentialFile  = "agent-credential.json"
	enrollTokenFile = "enroll.token"
	updateKeyFile   = "update-signing.pub"
)

// agentCredential is what enrollment produces.
type agentCredential struct {
	AgentID string `json:"agent_id"`
	Secret  string `json:"secret"`
	// UpdateSigningKey is the pinned public key agent updates must be
	// signed with (base64 ed25519).
	UpdateSigningKey string    `json:"update_signing_key,omitempty"`
	EnrolledAt       time.Time `json:"enrolled_at"`
	Via              string    `json:"via"`
}

func (a *Agent) dataDir() string { return filepath.Dir(a.cfg.DataDir) }

func loadCredential(path string) (*agentCredential, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c agentCredential
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("credential file is corrupt: %w", err)
	}
	if !bnats.ValidAgentID(c.AgentID) || c.Secret == "" {
		return nil, errors.New("credential file is incomplete")
	}
	return &c, nil
}

func saveCredential(path string, c agentCredential) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeSecretFile(path, raw)
}

// readEnrollToken returns the token from configuration or the token file.
func (a *Agent) readEnrollToken() string {
	if t := strings.TrimSpace(a.cfg.EnrollToken); t != "" {
		return t
	}
	raw, err := os.ReadFile(filepath.Join(a.dataDir(), enrollTokenFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// installTimeUpdateKey is the signing key the installer delivered over the
// token-authorized install channel, preferred over the one in the
// enrollment reply.
func (a *Agent) installTimeUpdateKey() string {
	if k := strings.TrimSpace(a.cfg.UpdatePubKey); k != "" {
		return k
	}
	raw, err := os.ReadFile(filepath.Join(a.dataDir(), updateKeyFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// updateKey is the pinned key, or nil when there is none.
func (a *Agent) updateKey() ed25519.PublicKey {
	key := ""
	if a.cred != nil {
		key = a.cred.UpdateSigningKey
	}
	if key == "" {
		key = a.installTimeUpdateKey()
	}
	if key == "" {
		return nil
	}
	pub, err := updatesig.ParsePublicKey(key)
	if err != nil {
		a.logger.Warn("pinned update signing key is unusable", "error", err)
		return nil
	}
	return pub
}

// errEnrollRefused is a definitive answer: retrying will not help.
var errEnrollRefused = errors.New("enrollment refused")

func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// enrollOnce opens a short-lived connection authenticated with the token
// (or, legacy, the shared password) and asks for a credential.
func (a *Agent) enrollOnce(ctx context.Context, priorID, token string, legacy bool) (*agentCredential, error) {
	nonce := newNonce()
	creds := bnats.Creds{CAFile: a.cfg.NATSCreds.CAFile, InboxPrefix: bnats.EnrollInboxPrefix(nonce)}
	subject := bnats.EnrollToken()
	req := proto.EnrollRequest{PriorAgentID: priorID, Info: a.info}
	if legacy {
		creds.User, creds.Password = bnats.LegacyEnrollUser(nonce), a.cfg.NATSCreds.Password
		subject = bnats.EnrollLegacy()
	} else {
		creds.User, creds.Password = bnats.EnrollUser(nonce), token
		req.Token = token
	}
	nc, err := bnats.ConnectWithCreds(a.cfg.NATSURL, "enroll:"+a.info.Hostname, creds, a.logger)
	if err != nil {
		if errors.Is(err, gonats.ErrAuthorization) || strings.Contains(strings.ToLower(err.Error()), "authorization violation") {
			return nil, fmt.Errorf("%w: the broker did not accept the %s", errEnrollRefused,
				map[bool]string{true: "legacy shared credential", false: "enrollment token"}[legacy])
		}
		return nil, err
	}
	defer nc.Close()
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	msg, err := nc.RequestWithContext(rctx, subject, payload)
	if err != nil {
		return nil, err
	}
	var resp proto.EnrollResponse
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return nil, fmt.Errorf("malformed enrolment reply: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("%w: %s", errEnrollRefused, resp.Error)
	}
	if !bnats.ValidAgentID(resp.AgentID) || resp.Secret == "" {
		return nil, errors.New("enrolment reply is incomplete")
	}
	key := a.installTimeUpdateKey()
	if key == "" {
		key = resp.UpdateSigningKey
	} else if resp.UpdateSigningKey != "" && resp.UpdateSigningKey != key {
		// The installer's key came over the token-authorized console
		// channel; it wins, and a disagreement is worth an operator's look.
		a.logger.Warn("the server's update signing key differs from the one the installer pinned; keeping the installer's")
	}
	via := "token"
	if legacy {
		via = "legacy"
	}
	return &agentCredential{AgentID: resp.AgentID, Secret: resp.Secret, UpdateSigningKey: key,
		EnrolledAt: time.Now().UTC(), Via: via}, nil
}

// establishIdentity loads or obtains this agent's credential and returns
// the connection credentials to use. A nil credential with no error means
// the agent runs on the legacy shared password (or, in development, none).
func (a *Agent) establishIdentity(ctx context.Context, priorID string) (bnats.Creds, error) {
	credPath := filepath.Join(a.dataDir(), credentialFile)
	cred, err := loadCredential(credPath)
	if err != nil {
		return bnats.Creds{}, fmt.Errorf("%s: %w", credPath, err)
	}
	if cred == nil {
		if token := a.readEnrollToken(); token != "" {
			cred, err = a.enrollWithRetry(ctx, priorID, token, false, 0)
			if err != nil {
				return bnats.Creds{}, fmt.Errorf("enroll with token: %w", err)
			}
		} else if a.cfg.NATSCreds.Password != "" {
			// Trading the shared password for an identity of its own. A
			// server that predates enrollment, or an operator who has
			// already switched the shared credential off, answers no; the
			// first means carrying on as before.
			cred, err = a.enrollWithRetry(ctx, priorID, "", true, 3)
			if err != nil {
				a.logger.Warn("could not trade the shared credential for an identity of its own; continuing on the shared credential",
					"error", err)
				cred = nil
			}
		}
		if cred != nil {
			if err := saveCredential(credPath, *cred); err != nil {
				return bnats.Creds{}, fmt.Errorf("save credential: %w", err)
			}
			a.logger.Info("enrolled: this agent now has its own credential", "agent_id", cred.AgentID, "via", cred.Via)
			a.scrubLegacyCredential()
		}
	}
	// Whatever brought us here, a token is spent or no longer needed.
	if cred != nil {
		_ = os.Remove(filepath.Join(a.dataDir(), enrollTokenFile))
		a.cred = cred
		return bnats.Creds{CAFile: a.cfg.NATSCreds.CAFile, User: cred.AgentID, Password: cred.Secret,
			InboxPrefix: bnats.AgentInboxPrefix(cred.AgentID)}, nil
	}
	return a.cfg.NATSCreds, nil
}

// enrollWithRetry retries network failures, with backoff, until ctx ends
// or (when limit > 0) limit attempts have been made. A definitive refusal
// is returned at once.
func (a *Agent) enrollWithRetry(ctx context.Context, priorID, token string, legacy bool, limit int) (*agentCredential, error) {
	backoff := 2 * time.Second
	for attempt := 1; ; attempt++ {
		cred, err := a.enrollOnce(ctx, priorID, token, legacy)
		if err == nil {
			return cred, nil
		}
		if errors.Is(err, errEnrollRefused) || (limit > 0 && attempt >= limit) {
			return nil, err
		}
		a.logger.Warn("enrolment attempt failed, retrying", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// legacyEnrollRetryLoop keeps trying to move off the shared credential
// while the agent runs on it, and asks for a restart once it has, so the
// agent reconnects as itself.
func (a *Agent) legacyEnrollRetryLoop(ctx context.Context, priorID string, restart func()) {
	if a.cred != nil || a.cfg.NATSCreds.Password == "" {
		return
	}
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cred, err := a.enrollOnce(ctx, priorID, "", true)
		if err != nil {
			a.logger.Debug("still on the shared credential", "error", err)
			continue
		}
		if err := saveCredential(filepath.Join(a.dataDir(), credentialFile), *cred); err != nil {
			a.logger.Error("save credential", "error", err)
			continue
		}
		a.logger.Info("enrolled: restarting to reconnect with this agent's own credential", "agent_id", cred.AgentID)
		a.scrubLegacyCredential()
		restart()
		return
	}
}

// scrubLegacyCredential removes the shared password from where older
// installers left it, once this agent no longer needs it.
func (a *Agent) scrubLegacyCredential() {
	exe, err := os.Executable()
	if err == nil {
		path := filepath.Join(filepath.Dir(exe), "agent.env")
		if raw, err := os.ReadFile(path); err == nil {
			var keep []string
			for _, line := range strings.Split(string(raw), "\n") {
				key, _, _ := strings.Cut(strings.TrimSpace(line), "=")
				if isLegacyCredentialKey(key) {
					continue
				}
				keep = append(keep, line)
			}
			if body := strings.TrimSpace(strings.Join(keep, "\n")); body == "" {
				_ = os.Remove(path)
			} else {
				_ = writeSecretFile(path, []byte(body+"\n"))
			}
		}
	}
	scrubMachineCredential(a.logger)
}

func isLegacyCredentialKey(key string) bool {
	switch strings.TrimSpace(key) {
	case "MUSTRA_NATS_USER", "MUSTRA_NATS_PASSWORD", "BEACON_NATS_USER", "BEACON_NATS_PASSWORD":
		return true
	}
	return false
}
