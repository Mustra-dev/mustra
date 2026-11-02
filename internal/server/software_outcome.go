package server

import (
	"context"
	"errors"
	"strings"

	"github.com/nats-io/nats.go"
)

// softwareTimeoutPrefix and softwareTimeoutSuffix bracket the error an agent
// sends when a legacy package command ran out of its budget ("command
// exceeded its 10s timeout"). AgentCommandResult has no structured timeout
// flag, and agents from before the process-tree fix already send this exact
// wording, so matching it keeps old and new agents reporting the same way.
const (
	softwareTimeoutPrefix = "command exceeded its "
	softwareTimeoutSuffix = " timeout"
)

// softwareActionOutcome turns the result of one synchronous legacy package
// command into the per-endpoint status recorded on its action.
//
// The three non-success outcomes are kept apart because they call for
// different things from an operator: a failure is the package's own fault,
// a timeout means it ran out of budget (and may have done part of its
// work), and no response means the command never reached a running agent.
func softwareActionOutcome(err error) string {
	switch {
	case err == nil:
		return "succeeded"
	case errors.Is(err, nats.ErrNoResponders):
		// Nothing was subscribed to the endpoint's command subject: the
		// agent is offline, so the command never ran.
		return "no_response"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		// Delivered, but no reply within the package's budget plus the
		// server's grace period. An agent that predates the process-tree
		// fix can still be blocked on a grandchild here.
		return "timed_out"
	}
	var agentErr errAgent
	if errors.As(err, &agentErr) {
		msg := string(agentErr)
		if strings.HasPrefix(msg, softwareTimeoutPrefix) && strings.HasSuffix(msg, softwareTimeoutSuffix) {
			return "timed_out"
		}
	}
	return "failed"
}

// softwareOutcomeDetail is the human-readable detail stored with the action.
func softwareOutcomeDetail(status string, err error, out string) string {
	switch status {
	case "succeeded":
		return out
	case "no_response":
		return "The endpoint did not respond: its agent is not connected, so the command was not run."
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
		return "No result from the endpoint within the package timeout plus a minute; the command may still be running there.\n" + out
	}
	return err.Error() + "\n" + out
}
