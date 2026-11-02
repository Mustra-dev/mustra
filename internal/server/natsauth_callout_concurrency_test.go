package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gonats "github.com/nats-io/nats.go"
)

// The callout is answered off the subscription's single delivery goroutine
// so that a reconnect storm is decided in parallel — but never by more
// than the bound, since every decision holds a database connection.
func TestBoundedHandlerRunsInParallelWithinBound(t *testing.T) {
	const workers, msgs = 4, 32
	var inFlight, peak atomic.Int64
	var wg sync.WaitGroup
	wg.Add(msgs)
	h := boundedHandler(workers, func(*gonats.Msg) {
		defer wg.Done()
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
	})
	start := time.Now()
	for range msgs {
		h(&gonats.Msg{}) // delivered one at a time, as a subscription does
	}
	wg.Wait()
	elapsed := time.Since(start)
	if p := peak.Load(); p != workers {
		t.Errorf("peak concurrency %d, want exactly %d", p, workers)
	}
	// Serial would be 32 x 20ms = 640ms; four at a time is about 160ms.
	if elapsed > 500*time.Millisecond {
		t.Errorf("32 messages took %s; they were not handled in parallel", elapsed)
	}
}
