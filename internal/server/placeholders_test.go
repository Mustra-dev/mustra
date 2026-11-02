package server

import (
	"strings"
	"testing"

	bnats "github.com/mustra-dev/mustra/internal/nats"
)

func TestPlaceholderSecretsAreRefused(t *testing.T) {
	cfg := Config{
		BreakGlassPassword: "changeme",
		AgentNATSPassword:  "change-me-agent",
		NATSCreds:          bnats.Creds{Password: "real-enough-Xk9"},
		PostgresDSN:        "postgres://mustra:changeme@postgres:5432/mustra",
	}
	err := CheckPlaceholderSecrets(cfg)
	if err == nil {
		t.Fatal("example values were accepted")
	}
	for _, want := range []string{"MUSTRA_BREAKGLASS_PASSWORD", "MUSTRA_AGENT_NATS_PASSWORD", "POSTGRES_PASSWORD"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "MUSTRA_NATS_PASSWORD,") || strings.HasSuffix(err.Error(), "MUSTRA_NATS_PASSWORD") {
		t.Errorf("a real value was reported as a placeholder: %v", err)
	}
}

func TestGeneratedSecretsPass(t *testing.T) {
	cfg := Config{
		BreakGlassPassword: "9fQ2xL0pWm3vT7yB",
		AgentNATSUser:      "mustra-agent",
		AgentNATSPassword:  "u1H4kZ8nR2sD6gJ0",
		NATSCreds:          bnats.Creds{User: "mustra-server", Password: "aB3dE5fG7hJ9kL1m"},
		PostgresDSN:        "postgres://mustra:pQ7wE2rT4yU6iO8p@postgres:5432/mustra",
	}
	if err := CheckPlaceholderSecrets(cfg); err != nil {
		t.Fatalf("real values refused: %v", err)
	}
}

// Empty is not a placeholder: an empty break-glass password disables the
// account (server.go documents this), and no NATS user means an
// unauthenticated dev bus. Both are choices, not the example file left alone.
func TestEmptySecretsAreNotPlaceholders(t *testing.T) {
	if err := CheckPlaceholderSecrets(Config{PostgresDSN: "postgres://mustra:pQ7wE2rT4yU6iO8p@127.0.0.1/mustra"}); err != nil {
		t.Fatalf("empty values refused: %v", err)
	}
}

// A NATS user with an empty or short password is refused, as are the
// default DSN's mustra:mustra and a short SCIM token.
func TestWeakSecretsAreRefused(t *testing.T) {
	for name, cfg := range map[string]Config{
		"empty server nats password": {NATSCreds: bnats.Creds{User: "mustra-server"}},
		"short agent nats password":  {AgentNATSUser: "mustra-agent", AgentNATSPassword: "short"},
		"default dsn":                {PostgresDSN: "postgres://mustra:mustra@127.0.0.1:5432/mustra"},
		"short scim token":           {SCIMToken: "abc123"},
		"short break-glass":          {BreakGlassPassword: "Xk9!short"},
	} {
		if err := CheckPlaceholderSecrets(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A fresh install leaves the legacy shared agent password empty -- agents
// enroll for their own credential -- while compose still passes the agent
// user name. That must start: refusing it crash-looped every new install.
func TestEmptyLegacyAgentPasswordStarts(t *testing.T) {
	cfg := Config{
		AgentNATSUser: "mustra-agent",
		NATSCreds:     bnats.Creds{User: "mustra-server", Password: "aB3dE5fG7hJ9kL1m"},
		PostgresDSN:   "postgres://mustra:pQ7wE2rT4yU6iO8p@postgres:5432/mustra",
	}
	if err := CheckPlaceholderSecrets(cfg); err != nil {
		t.Fatalf("legacy-off install refused: %v", err)
	}
}
