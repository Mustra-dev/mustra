package nats

import (
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/nats-io/nats.go"
)

// Creds are the credentials an agent or the server uses to authenticate.
//
// This channel carries the whole control plane — sensor snapshots in one
// direction, and in the other, commands that run as root on every endpoint.
// It ran open for a while, meaning anything that could reach the port could
// read the fleet's inventory, watch shell sessions, and execute arbitrary
// commands on 34 machines. TLS closes the reading half; authentication
// closes the writing half, which is the serious one.
type Creds struct {
	// CAFile is the certificate authority that signed the server's
	// certificate. Verified rather than skipped: encryption without
	// verification stops passive listening but not an active impostor, and
	// an impostor here owns every endpoint.
	CAFile   string
	User     string
	Password string
	// InboxPrefix replaces the shared "_INBOX" prefix for this connection's
	// request/reply inboxes. The broker grants each identity subscribe on
	// its own prefix only, so replies addressed to one agent (or to the
	// server) cannot be read by another. Empty keeps the nats.go default,
	// which is what an agent on the legacy credential still uses.
	InboxPrefix string
}

// Connect dials the NATS server at url with reconnect behavior suited to an
// agent that may spend long stretches offline: unlimited reconnect attempts,
// a bounded per-attempt wait, and slog-based logging of state transitions so
// operators can see flapping without the caller wiring up callbacks.
//
// name identifies the connection in `nats server ls connections` and logs
// (e.g. "agent:<agent_id>" or "server").
func Connect(url, name string, logger *slog.Logger) (*nats.Conn, error) {
	return ConnectWithCreds(url, name, Creds{}, logger)
}

// ConnectWithCreds is Connect with TLS and authentication. extra options
// are applied last, so they override the defaults here.
func ConnectWithCreds(url, name string, creds Creds, logger *slog.Logger, extra ...nats.Option) (*nats.Conn, error) {
	if logger == nil {
		logger = slog.Default()
	}
	opts := []nats.Option{
		nats.Name(name),
		nats.MaxReconnects(-1), // retry forever; the agent must survive long control-plane outages
		nats.ReconnectWait(2 * time.Second),
		nats.ReconnectBufSize(-1), // unbounded client-side buffer; bbolt is the durable buffer, this just smooths reconnect bursts
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Warn("nats disconnected", "error", err)
			} else {
				logger.Warn("nats disconnected")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("nats reconnected", "url", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			logger.Warn("nats connection closed")
		}),
	}
	if creds.CAFile != "" {
		opts = append(opts, nats.RootCAs(creds.CAFile))
	}
	if creds.User != "" {
		opts = append(opts, nats.UserInfo(creds.User, creds.Password))
		// An authorization error is not the end of the connection. With the
		// auth callout, every connection is decided by the control plane,
		// so a server restart refuses every reconnect until it is back, and
		// a credential's JWT expires on purpose so revocation takes effect.
		// nats.go gives up after the same auth error twice, which would
		// leave an agent deaf until its service restarted.
		opts = append(opts, nats.IgnoreAuthErrorAbort())
	}
	if creds.InboxPrefix != "" {
		opts = append(opts, nats.CustomInboxPrefix(creds.InboxPrefix))
	}
	opts = append(opts, extra...)
	return nats.Connect(url, opts...)
}

// FleetReconnectBackoff replaces the fixed reconnect wait for a connection
// that a whole fleet holds at once — an agent's.
//
// Every agent loses the broker at the same moment when it restarts, and
// each reconnection costs the broker a TLS handshake and the control plane
// an authorization. With a fixed two-second wait, 2,000 agents offered
// the broker more handshakes than it could finish within its authorization
// timeout; the refused agents came straight back, and in a load test the
// fleet was still not reconnected after thirteen minutes. Doubling the wait
// per failed attempt, up to 30 s, with full jitter, brought the same 2,000
// back in 40 s. The first retry still comes within a few seconds, so a
// short blip costs no more than before.
func FleetReconnectBackoff() nats.Option {
	return nats.CustomReconnectDelay(reconnectDelay)
}

const (
	reconnectBase = 2 * time.Second
	reconnectMax  = 30 * time.Second
)

// reconnectDelay is the wait before reconnect attempt number attempts
// (counted from 1): uniformly random up to min(reconnectMax,
// reconnectBase·2^attempts), plus half a second so no retry is immediate.
func reconnectDelay(attempts int) time.Duration {
	ceiling := reconnectMax
	if attempts < 5 {
		if d := reconnectBase << max(attempts, 0); d < ceiling {
			ceiling = d
		}
	}
	return 500*time.Millisecond + rand.N(ceiling)
}
