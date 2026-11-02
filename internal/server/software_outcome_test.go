package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
)

// A legacy package's endpoint outcome used to be "failed" for every error,
// including the agent's own timeout and an offline agent. Failure,
// timeout and no response must stay distinct.
func TestSoftwareActionOutcomeKeepsFailureTimeoutAndNoResponseApart(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"success", nil, "succeeded"},
		{"package exited non-zero", errAgent("exit status 7"), "failed"},
		{"agent killed it at its budget", errAgent("command exceeded its 10s timeout"), "timed_out"},
		{"agent killed it at the default budget", errAgent("command exceeded its 15m0s timeout"), "timed_out"},
		{"timeout wording inside other text is not a timeout", errAgent("apt: command exceeded its quota"), "failed"},
		{"server gave up waiting", fmt.Errorf("request: %w", context.DeadlineExceeded), "timed_out"},
		{"nats request timeout", nats.ErrTimeout, "timed_out"},
		{"agent offline", nats.ErrNoResponders, "no_response"},
		{"anything else", errors.New("boom"), "failed"},
	} {
		if got := softwareActionOutcome(c.err); got != c.want {
			t.Errorf("%s: softwareActionOutcome(%v) = %q, want %q", c.name, c.err, got, c.want)
		}
	}
}

func TestSoftwareOutcomeDetailExplainsNonFailures(t *testing.T) {
	if d := softwareOutcomeDetail("no_response", nats.ErrNoResponders, ""); !strings.Contains(d, "not connected") {
		t.Errorf("no-response detail should say the agent is not connected: %q", d)
	}
	if d := softwareOutcomeDetail("timed_out", context.DeadlineExceeded, "partial"); !strings.Contains(d, "may still be running") || !strings.Contains(d, "partial") {
		t.Errorf("server-side timeout detail: %q", d)
	}
	if d := softwareOutcomeDetail("timed_out", errAgent("command exceeded its 10s timeout"), "out"); !strings.HasPrefix(d, "command exceeded its 10s timeout") {
		t.Errorf("agent timeout detail should keep the agent's message: %q", d)
	}
}
