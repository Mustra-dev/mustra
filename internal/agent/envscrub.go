package agent

import (
	"os"
	"regexp"
	"strings"
)

// Secrets never reach a child process.
//
// Package commands, custom sensors, compliance checks and shell sessions
// all run with the agent's environment, and an older install put the
// shared bus password there (systemd EnvironmentFile, the launchd plist,
// Windows Machine variables). A custom sensor that printed `env` stored
// the fleet credential in Postgres for anyone with view rights to read.
// Credentials now live in files the agent reads itself; this is the second
// line: the agent removes anything credential-shaped from its own
// environment at startup, and every child environment it builds is
// filtered the same way.

// isSecretEnvKey reports whether an environment variable is one of ours
// and holds a credential.
func isSecretEnvKey(key string) bool {
	k := strings.ToUpper(key)
	if !strings.HasPrefix(k, "MUSTRA_") && !strings.HasPrefix(k, "BEACON_") {
		return false
	}
	for _, marker := range []string{"PASSWORD", "SECRET", "TOKEN", "_KEY", "NATS_USER", "CREDENTIAL"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

// ScrubSecretEnv removes credential variables from this process's
// environment. Called by cmd/agent once its flags have been read.
func ScrubSecretEnv() {
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if isSecretEnvKey(key) {
			_ = os.Unsetenv(key)
		}
	}
}

// childEnv is os.Environ() without credential variables, for exec.Cmd.Env.
func childEnv() []string {
	return filterEnv(os.Environ())
}

// enrollTokenPattern matches a mustra enrollment token. The console's
// install one-liner carries one on the command line, and a machine that
// already runs an agent records that command line as a process start.
var enrollTokenPattern = regexp.MustCompile(`mte_[A-Za-z0-9_-]{16,}`)

// redactCmdline removes enrollment tokens from a command line before it
// is reported, so a token that may still have uses left is never stored
// in the console's process history for every viewer to read.
func redactCmdline(s string) string {
	if !strings.Contains(s, "mte_") {
		return s
	}
	return enrollTokenPattern.ReplaceAllString(s, "mte_[redacted]")
}

func filterEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if isSecretEnvKey(key) {
			continue
		}
		out = append(out, kv)
	}
	return out
}
