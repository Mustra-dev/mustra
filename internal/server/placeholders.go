package server

import (
	"fmt"
	"strings"
)

// placeholderSecrets are the values the example configuration ships with.
// They exist so a first `docker compose up` has something to substitute,
// not so a fleet runs on them: the agent credential is what lets a host
// on the LAN publish to the bus, and the backdoor password is what lets
// anyone who reaches port 8080 run commands on every endpoint.
var placeholderSecrets = []string{
	"changeme", "change-me", "change-me-server", "change-me-agent", "change-me-sys",
	"password", "admin", "secret", "mustra", "beacon", "root", "test",
	"letmein", "default", "changeit", "admin123", "password123", "example",
}

// Minimum lengths. A NATS password is a bus credential that is never
// typed by a person, so there is no reason for it to be short.
const (
	minNATSPasswordLen       = 16
	minBreakGlassPasswordLen = 12
)

// CheckPlaceholderSecrets refuses to run on the example configuration's
// placeholder values. Returning an error rather than logging a warning,
// because a warning in a container log is read by nobody until the day
// it matters, and by then it is a post-mortem line.
//
// The bootstrap script (deploy/init.sh) generates real values, so the
// safe path and the easy path are the same one.
func CheckPlaceholderSecrets(cfg Config) error {
	var bad []string
	check := func(name, value string) {
		v := strings.ToLower(strings.TrimSpace(value))
		for _, p := range placeholderSecrets {
			if v == p {
				bad = append(bad, name)
				return
			}
		}
	}
	check("MUSTRA_BREAKGLASS_PASSWORD", cfg.BreakGlassPassword)
	check("MUSTRA_NATS_PASSWORD", cfg.NATSCreds.Password)
	check("MUSTRA_NATS_SYS_PASSWORD", cfg.NATSSysCreds.Password)
	check("MUSTRA_AGENT_NATS_PASSWORD", cfg.AgentNATSPassword)
	check("MUSTRA_SCIM_TOKEN", cfg.SCIMToken)
	// A user without a password is not authentication, and a short one is
	// not much more.
	if cfg.NATSCreds.User != "" && len(cfg.NATSCreds.Password) < minNATSPasswordLen {
		bad = append(bad, fmt.Sprintf("MUSTRA_NATS_PASSWORD (empty or shorter than %d characters)", minNATSPasswordLen))
	}
	// An empty agent password is how a fresh install says the legacy shared
	// credential is off (agents enroll for their own), so only a set-but-
	// short one is refused. Compose always passes the user name.
	if cfg.AgentNATSUser != "" && cfg.AgentNATSPassword != "" && len(cfg.AgentNATSPassword) < minNATSPasswordLen {
		bad = append(bad, fmt.Sprintf("MUSTRA_AGENT_NATS_PASSWORD (shorter than %d characters)", minNATSPasswordLen))
	}
	// Empty is an install from before the system account: revocation waits
	// for the JWT to expire. Set, it reaches the broker's system account.
	if cfg.NATSSysCreds.Password != "" && len(cfg.NATSSysCreds.Password) < minNATSPasswordLen {
		bad = append(bad, fmt.Sprintf("MUSTRA_NATS_SYS_PASSWORD (shorter than %d characters)", minNATSPasswordLen))
	}
	if cfg.BreakGlassPassword != "" && len(cfg.BreakGlassPassword) < minBreakGlassPasswordLen {
		bad = append(bad, fmt.Sprintf("MUSTRA_BREAKGLASS_PASSWORD (shorter than %d characters)", minBreakGlassPasswordLen))
	}
	if cfg.SCIMToken != "" && len(cfg.SCIMToken) < 32 {
		bad = append(bad, "MUSTRA_SCIM_TOKEN (shorter than 32 characters)")
	}
	if len(cfg.CredentialEncryptionKey) != 0 && len(cfg.CredentialEncryptionKey) != 32 {
		bad = append(bad, "MUSTRA_CREDENTIAL_ENCRYPTION_KEY (must be 32 bytes of hex)")
	}
	// The Postgres password only reaches the server inside the DSN.
	for _, p := range placeholderSecrets {
		if strings.Contains(cfg.PostgresDSN, ":"+p+"@") {
			bad = append(bad, "POSTGRES_PASSWORD")
			break
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("refusing to start with placeholder secrets in %s; run deploy/init.sh or set real values (openssl rand -base64 32)", strings.Join(bad, ", "))
}
