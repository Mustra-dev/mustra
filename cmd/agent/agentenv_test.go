package main

import "testing"

// An enrolled agent's agent.env holds only the CA. It must still be used:
// dropping it made every restart after enrolling fail TLS verification on
// installs whose agent URL is nats://.
func TestAgentEnvCAWithoutPassword(t *testing.T) {
	user, pass, ca := "", "", ""
	applyAgentEnvFile(&user, &pass, &ca)("", "", "/opt/mustra-agent/ca.crt")
	if ca != "/opt/mustra-agent/ca.crt" {
		t.Errorf("CA from agent.env ignored without a password: %q", ca)
	}
	if user != "" || pass != "" {
		t.Errorf("credential invented: %q %q", user, pass)
	}
}

func TestAgentEnvFlagsWin(t *testing.T) {
	user, pass, ca := "", "", "/flag/ca.crt"
	applyAgentEnvFile(&user, &pass, &ca)("mustra-agent", "pw", "/file/ca.crt")
	if ca != "/flag/ca.crt" {
		t.Errorf("--nats-ca overridden by agent.env: %q", ca)
	}
	if user != "mustra-agent" || pass != "pw" {
		t.Errorf("legacy credential not taken: %q %q", user, pass)
	}
	user, pass = "u", "p"
	applyAgentEnvFile(&user, &pass, &ca)("mustra-agent", "pw", "")
	if user != "u" || pass != "p" {
		t.Errorf("command-line credential overridden: %q %q", user, pass)
	}
}
