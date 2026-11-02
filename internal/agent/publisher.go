package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// publishTimeout bounds a single JetStream publish attempt (including the
// server ack round-trip) so a stalled connection can't hang the caller.
const publishTimeout = 3 * time.Second

// latestPublishTimeout is the longer budget for a latest-wins publish. A
// heartbeat that takes five seconds over a slow link is still a heartbeat;
// timing it out at three and buffering it behind a backlog is what made a
// MacBook on a VPN look offline for an afternoon while its process events
// streamed in fine.
const latestPublishTimeout = 8 * time.Second

// maxOutboxAttempts is how many flush cycles the message at the head of
// the outbox may fail before it is dropped.
//
// The outbox drains in order, which is what preserves it — but it also
// means one permanently undeliverable message blocks everything behind it
// forever, and does so quietly. That is not theoretical: an agent
// publishing to a subject its NATS credential did not allow got no ack,
// timed out every five seconds, and held a completed patch result hostage
// behind it while heartbeats (which publish directly) carried on as though
// nothing were wrong.
const maxOutboxAttempts = 10

// flushBatch is how many outbox messages are in flight at once during a
// flush. Publishing one at a time costs a round-trip per message: at 70 ms
// that is 14 messages a second, and a two-day backlog of process events
// takes longer to drain than it took to collect. JetStream keeps order per
// connection, so a batch is acked in order and deleted up to the first
// failure.
const flushBatch = 64

// Buffered telemetry has a shelf life. The server keeps the process
// timeline for 48 hours, so a batch queued longer than that would be
// pruned on arrival; dropping it here instead saves the round-trips. The
// count cap keeps the outbox from growing without bound on an endpoint
// that is offline for weeks.
const (
	telemetryMaxAge = 40 * time.Hour
	outboxMaxCount  = 100000
)

// isLatestSubject says whether a subject is latest-wins: the server keeps
// only the newest heartbeat, facts and sensor snapshot per endpoint.
func isLatestSubject(subject string) bool {
	return strings.HasSuffix(subject, ".heartbeat") || strings.HasSuffix(subject, ".facts") || strings.Contains(subject, ".sensor.")
}

// isExpirableSubject says whether a buffered message may be dropped when
// it is old or the outbox is full: telemetry streams and latest-wins
// snapshots. Action results and file events are never dropped by age.
func isExpirableSubject(subject string) bool {
	return isLatestSubject(subject) || strings.HasSuffix(subject, ".procevents") || strings.HasSuffix(subject, ".recevents")
}

// durablePublisher publishes messages via JetStream (so the server's
// heartbeat/facts stream durably captures them) and transparently falls
// back to the bbolt-backed outbox whenever NATS is unreachable or the
// publish fails. A background flush loop drains the outbox in order once
// the connection recovers, so the agent survives a control-plane outage
// with no data loss and no reordering.
type durablePublisher struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	store  *Store
	logger *slog.Logger

	// Head-of-line failure tracking. Only ever touched from the single
	// flush goroutine, so it needs no lock.
	stuckSubject  string
	stuckAttempts int
}

func newDurablePublisher(nc *nats.Conn, js jetstream.JetStream, store *Store, logger *slog.Logger) *durablePublisher {
	return &durablePublisher{nc: nc, js: js, store: store, logger: logger}
}

// Publish attempts an immediate durable publish; on any failure (including
// "not connected") it buffers the message locally instead of returning an
// error, since buffering is the expected, non-exceptional path during an
// outage. It only returns an error if even buffering fails (disk full,
// etc.) — that's the one case the caller can't recover from here.
func (p *durablePublisher) Publish(ctx context.Context, subject string, payload []byte) error {
	if p.nc.IsConnected() {
		pctx, cancel := context.WithTimeout(ctx, publishTimeout)
		_, err := p.js.Publish(pctx, subject, payload)
		cancel()
		if err == nil {
			return nil
		}
		p.logger.Warn("publish failed, buffering", "subject", subject, "error", err)
	}
	return p.store.Enqueue(BufferedMessage{Subject: subject, Payload: payload, Queued: time.Now()})
}

// PublishLatest is Publish for a latest-wins subject: a longer attempt,
// and on failure the buffered copy replaces any older one for the same
// subject. The flush loop sends these ahead of the telemetry backlog.
func (p *durablePublisher) PublishLatest(ctx context.Context, subject string, payload []byte) error {
	if p.nc.IsConnected() {
		pctx, cancel := context.WithTimeout(ctx, latestPublishTimeout)
		_, err := p.js.Publish(pctx, subject, payload)
		cancel()
		if err == nil {
			return nil
		}
		p.logger.Warn("publish failed, buffering latest", "subject", subject, "error", err)
	}
	return p.store.EnqueueLatest(BufferedMessage{Subject: subject, Payload: payload, Queued: time.Now()})
}

// runFlushLoop periodically drains the outbox while connected. It stops
// draining at the first failed publish within a tick (preserving order) and
// simply retries on the next tick.
func (p *durablePublisher) runFlushLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.flushOnce(ctx)
		}
	}
}

func (p *durablePublisher) flushOnce(ctx context.Context) {
	if !p.nc.IsConnected() {
		return
	}
	pending, err := p.store.Pending()
	if err != nil {
		p.logger.Warn("check outbox pending count failed", "error", err)
		return
	}
	if pending == 0 {
		return
	}
	if dropped, err := p.store.PruneOutbox(time.Now(), telemetryMaxAge, outboxMaxCount, isExpirableSubject); err != nil {
		p.logger.Warn("outbox prune failed", "error", err)
	} else if dropped > 0 {
		p.logger.Info("dropped stale buffered telemetry", "count", dropped, "pending_before", pending)
	}

	// Latest-wins subjects first, one at a time: there are at most a
	// handful (one per subject) and they are what marks the endpoint
	// online.
	err = p.store.DrainWhere(isLatestSubject, func(msg BufferedMessage) error {
		pctx, cancel := context.WithTimeout(ctx, latestPublishTimeout)
		defer cancel()
		_, err := p.js.Publish(pctx, msg.Subject, msg.Payload)
		return err
	})
	if err != nil {
		p.logger.Warn("outbox flush of latest snapshots stopped early, will retry", "error", err)
		return
	}

	// Then the ordered backlog, pipelined.
	flushed := 0
	for {
		batch, err := p.store.PeekBatch(flushBatch)
		if err != nil {
			p.logger.Warn("read outbox batch failed", "error", err)
			return
		}
		if len(batch) == 0 {
			break
		}
		acked, failed, ferr := p.publishBatch(ctx, batch)
		if acked > 0 {
			keys := make([][]byte, 0, acked)
			for _, e := range batch[:acked] {
				keys = append(keys, e.Key)
			}
			if err := p.store.DeleteKeys(keys); err != nil {
				p.logger.Error("delete flushed outbox entries failed", "error", err)
				return
			}
			flushed += acked
		}
		if failed == nil {
			continue
		}
		if failed.Subject == p.stuckSubject {
			p.stuckAttempts++
		} else {
			p.stuckSubject, p.stuckAttempts = failed.Subject, 1
		}
		if p.stuckAttempts >= maxOutboxAttempts {
			dropped, derr := p.store.DropFirst()
			if derr != nil {
				p.logger.Error("could not drop the stuck outbox message", "error", derr)
			} else {
				p.logger.Error("dropped an undeliverable message to unblock the outbox",
					"subject", dropped.Subject, "queued", dropped.Queued,
					"attempts", p.stuckAttempts, "last_error", ferr)
			}
			p.stuckSubject, p.stuckAttempts = "", 0
			return
		}
		p.logger.Warn("outbox flush stopped early, will retry",
			"flushed", flushed, "subject", failed.Subject,
			"attempts", p.stuckAttempts, "error", ferr)
		return
	}
	p.stuckSubject, p.stuckAttempts = "", 0
	if flushed > 0 {
		p.logger.Info("outbox flushed", "count", flushed)
	}
}

// publishBatch publishes the entries asynchronously and waits for the
// acks. It returns how many leading entries were acked; the first that
// was not, with its error, when one failed. Each publish carries a message
// id derived from its outbox position, so a batch whose acks were lost on
// the way back is deduplicated by the server when it is sent again.
func (p *durablePublisher) publishBatch(ctx context.Context, batch []OutboxEntry) (int, *BufferedMessage, error) {
	futures := make([]jetstream.PubAckFuture, 0, len(batch))
	for i, e := range batch {
		if e.Msg.Subject == "(unreadable)" {
			// Deletable, not publishable: count it as acked so the caller
			// removes it, but stop the batch there so nothing is sent
			// out of order around it.
			return i + 1, nil, nil
		}
		f, err := p.js.PublishAsync(e.Msg.Subject, e.Msg.Payload, jetstream.WithMsgID(fmt.Sprintf("%s/%x", e.Msg.Subject, e.Key)))
		if err != nil {
			if i == 0 {
				return 0, &batch[0].Msg, err
			}
			batch = batch[:i]
			futures = futures[:i]
			break
		}
		futures = append(futures, f)
	}
	timeout := publishTimeout + time.Duration(len(futures))*50*time.Millisecond
	select {
	case <-p.js.PublishAsyncComplete():
	case <-time.After(timeout):
	case <-ctx.Done():
		return 0, &batch[0].Msg, ctx.Err()
	}
	for i, f := range futures {
		select {
		case <-f.Ok():
			continue
		case err := <-f.Err():
			return i, &batch[i].Msg, err
		default:
			return i, &batch[i].Msg, errors.New("no ack within the flush window")
		}
	}
	return len(futures), nil, nil
}
