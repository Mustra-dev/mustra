package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"

	gonats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// Endpoint identity and update trust: who an agent is, how it proves it,
// and how it knows an update came from this deployment.
//
//   - Identity. nats-server hands every connection that is not the
//     server's own to this process (auth callout, natsauth_callout.go),
//     which answers with a user JWT scoped to the one identity the
//     connection proved: an enrolled agent's ID and secret, an enrollment
//     token, or — only while the operator allows it — the legacy shared
//     agent password.
//   - Enrollment. A new agent presents a token an administrator created
//     (enroll_tokens.go) and receives its own credential
//     (enroll_agent.go). An agent still on the shared password exchanges
//     it the same way, automatically.
//   - Updates. Agent binaries are offered with a manifest signed by this
//     deployment's ed25519 key (enroll_signing.go), which the agent pinned
//     at enrollment.
//   - URLs. Everything an agent is told to fetch is built from the
//     configured public URL (enroll_publicurl.go), never from a request's
//     Host header.
//
// Configuration comes from the environment rather than Config so the
// deployed entrypoints need no change; each MUSTRA_* name also accepts the
// pre-rename BEACON_* spelling, as everywhere else.

// Setting keys owned by this feature.
const (
	settingAgentPublicURL       = "agent.public_url"
	settingAgentPublicURLHTTPOK = "agent.public_url_allow_http"
	settingUpdateSigningKey     = "agent.update_signing_key"
)

// agentTrust is the runtime state of the trust chain.
type agentTrust struct {
	// calloutKey signs the broker's authorization responses and the user
	// JWTs inside them. nil means the broker is not running the auth
	// callout (local development against nats.dev.conf), and identity is
	// not enforced at the broker at all.
	calloutKey nkeys.KeyPair
	// signKey signs agent update manifests; nil when the deployment only
	// serves pre-signed manifests (MUSTRA_AGENT_SIGNING_PUBKEY).
	signKey ed25519.PrivateKey
	signPub ed25519.PublicKey
	// publicURLEnv overrides the console setting when set.
	publicURLEnv     string
	publicURLEnvHTTP bool
	legacyUser       string
	legacyPassword   string
}

func trustEnv(key string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	if legacy, ok := strings.CutPrefix(key, "MUSTRA_"); ok {
		return strings.TrimSpace(os.Getenv("BEACON_" + legacy))
	}
	return ""
}

// loadAgentTrust reads the environment and the database and prepares the
// trust chain. It does not start anything; startAgentTrust does.
func (s *Server) loadAgentTrust(ctx context.Context) (*agentTrust, error) {
	t := &agentTrust{
		publicURLEnv:     trustEnv("MUSTRA_PUBLIC_URL"),
		publicURLEnvHTTP: strings.EqualFold(trustEnv("MUSTRA_ALLOW_INSECURE_PUBLIC_URL"), "true"),
		legacyUser:       s.cfg.AgentNATSUser,
		legacyPassword:   s.cfg.AgentNATSPassword,
	}
	if t.legacyUser == "" {
		t.legacyUser = "mustra-agent"
	}
	if seed := trustEnv("MUSTRA_NATS_CALLOUT_SEED"); seed != "" {
		kp, err := nkeys.FromSeed([]byte(seed))
		if err != nil {
			return nil, fmt.Errorf("MUSTRA_NATS_CALLOUT_SEED is not an nkey seed: %w", err)
		}
		if pub, err := kp.PublicKey(); err != nil || !nkeys.IsValidPublicAccountKey(pub) {
			return nil, fmt.Errorf("MUSTRA_NATS_CALLOUT_SEED must be an account seed (starts with SA)")
		}
		t.calloutKey = kp
	}
	if t.publicURLEnv != "" {
		norm, err := validatePublicURL(t.publicURLEnv, t.publicURLEnvHTTP)
		if err != nil {
			return nil, fmt.Errorf("MUSTRA_PUBLIC_URL: %w", err)
		}
		t.publicURLEnv = norm
	}
	if err := s.loadSigningKey(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// startAgentTrust loads the trust chain and starts the broker-facing
// responders: the auth callout and the two enrolment subjects. Called once
// from Run, after the store and the NATS connection exist. The returned
// function unsubscribes everything.
func (s *Server) startAgentTrust(ctx context.Context) (func(), error) {
	t, err := s.loadAgentTrust(ctx)
	if err != nil {
		return nil, err
	}
	s.trust = t
	var subs []*gonats.Subscription
	stop := func() {
		for _, sub := range subs {
			_ = sub.Unsubscribe()
		}
	}
	if t.calloutKey != nil {
		sub, err := s.subscribeAuthCallout(ctx)
		if err != nil {
			return nil, fmt.Errorf("subscribe auth callout: %w", err)
		}
		subs = append(subs, sub)
		pub, _ := t.calloutKey.PublicKey()
		s.logger.Info("agent identity enforced by the broker (auth callout)", "issuer", pub)
	} else {
		s.logger.Warn("MUSTRA_NATS_CALLOUT_SEED is not set: the broker is not consulting this server, so agent identity is NOT enforced. " +
			"This is only acceptable for local development against nats.dev.conf; run deploy/init.sh for a real deployment.")
	}
	for _, f := range []func(context.Context) (*gonats.Subscription, error){s.subscribeEnrollToken, s.subscribeEnrollLegacy, s.subscribeRegisterAgent} {
		sub, err := f(ctx)
		if err != nil {
			stop()
			return nil, err
		}
		subs = append(subs, sub)
	}
	return stop, nil
}

// identityEnforced reports whether the broker authenticates agents through
// this server. Without it, the subject an agent publishes on proves
// nothing, and legacy subjects are all there is.
func (s *Server) identityEnforced() bool { return s.trust != nil && s.trust.calloutKey != nil }

// legacySubjectsAccepted reports whether data on the identity-free legacy
// subjects (beacon.register, beacon.r.<query>) is accepted: only without
// the callout, where there is nothing else. With identity enforced, the
// shared credential that published there is retired (#231).
func (s *Server) legacySubjectsAccepted(ctx context.Context) bool {
	return !s.identityEnforced()
}

// legacyAllowed is false wherever it matters: the shared credential is
// retired whenever agent identity is enforced.
func (s *Server) legacyAllowed(ctx context.Context) bool { return false }
