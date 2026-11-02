package nats

import (
	"context"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// AgentStreamName is the JetStream stream that durably captures every
// per-agent subject (heartbeat, facts, and future additions). Durability
// here is what lets the server detect staleness reliably and lets us add
// durable consumers (e.g. a metrics writer) later without losing history.
const AgentStreamName = "BEACON_AGENTS"

// EnsureAgentStream creates the agent stream if it does not exist, or
// updates it in place if its config has drifted. Safe to call on every
// server startup.
//
// Retention is limits-based with a bounded age rather than work-queue or
// interest-based: multiple independent consumers (staleness tracker now,
// a metrics writer later) need to read the same messages, and we'd rather
// cap storage by time than require every consumer to explicitly ack before
// the message is considered done.
// DefaultStreamRetention is how long the buffer holds messages that every
// consumer has already read.
//
// Four hours, not the day it used to be. Retention here is replay depth for
// a control plane that is down — and what it buys differs sharply by
// message. Re-reading an old sensor snapshot is worthless (only the newest
// matters, and a fresh one lands within the sensor interval) and re-reading
// an old heartbeat is actively wrong, since it would claim a machine was
// alive at a time it was not. Only action results and security events are
// genuinely worth keeping, and a control plane down longer than an
// afternoon is a bigger problem than a lost patch result. Measured on a
// 39-endpoint fleet a day of retention was ~900 MB, nearly all of it
// snapshots nobody would ever replay.
//
// It is a setting, not a constant, because the right answer depends on how
// long an outage would go unnoticed — see Administration → Message Buffer.
const DefaultStreamRetention = 4 * time.Hour

// MinStreamRetention is the floor. Below an hour the buffer stops being a
// buffer: an ordinary deploy or a NATS restart takes minutes, and a window
// measured in the same units is one bad afternoon from losing data during
// routine maintenance.
const MinStreamRetention = time.Hour

// MaxStreamRetention is the ceiling, and it is about disk rather than
// principle: a week of this fleet's traffic is several gigabytes on the
// volume Postgres also lives on.
const MaxStreamRetention = 7 * 24 * time.Hour

// EnsureAgentStream is also how retention is changed. CreateOrUpdateStream
// applies a new MaxAge to the existing stream in place, dropping anything
// already past it, so the settings handler calls this again rather than
// needing a restart.
func EnsureAgentStream(ctx context.Context, nc *nats.Conn, retention time.Duration) (jetstream.Stream, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}
	if retention < MinStreamRetention {
		retention = MinStreamRetention
	}
	if retention > MaxStreamRetention {
		retention = MaxStreamRetention
	}
	cfg := jetstream.StreamConfig{
		Name:      AgentStreamName,
		Subjects:  []string{AgentWildcard()},
		Retention: jetstream.LimitsPolicy,
		MaxAge:    retention,
		// A ceiling as well as an age, because age cannot bound the case
		// that matters: one endpoint publishing in a loop, filling the disk
		// Postgres is also on and taking the control plane down with it.
		// Sized against the old 24-hour retention (~900 MB measured), so it
		// stays a runaway guard rather than a limit anybody meets by
		// choosing a longer window. Hitting it discards oldest-first, which
		// is what MaxAge already does and the right failure.
		MaxBytes: 3 << 30,
		Storage:  jetstream.FileStorage,
	}
	return js.CreateOrUpdateStream(ctx, cfg)
}

// JetStream returns a jetstream.JetStream handle for nc. Thin wrapper kept
// here so callers don't need to import the jetstream package directly for
// this one call.
func JetStream(nc *nats.Conn) (jetstream.JetStream, error) {
	return jetstream.New(nc)
}
