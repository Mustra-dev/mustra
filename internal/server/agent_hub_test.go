package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// A burst of refresh requests — every heartbeat of a large fleet asks for
// one — must cost one rebuild per interval, not one per request, and the
// last request of a burst must still be acted on.
//
// Each rebuild blocks until the test releases it, so the bursts land while
// one is in progress and nothing depends on how fast the machine runs:
// timing the bursts against the interval failed on a loaded CI runner when
// a burst straddled the end of a pause, which correctly costs one more
// rebuild.
func TestCoalesceLoopBoundsRebuilds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const interval = 20 * time.Millisecond
	kick := make(chan struct{}, 1)
	var runs atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		coalesceLoop(ctx, kick, interval, func() bool { return true }, func(context.Context) {
			runs.Add(1)
			started <- struct{}{}
			<-release
		})
	}()
	request := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	awaitRebuild := func() {
		t.Helper()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("no rebuild within 5s")
		}
	}
	request()
	awaitRebuild()
	for range 2 {
		// Requests during a rebuild collapse into one trailing rebuild,
		// which waits out the interval first.
		for range 10000 {
			request()
		}
		released := time.Now()
		release <- struct{}{}
		awaitRebuild()
		if waited := time.Since(released); waited < interval {
			t.Fatalf("trailing rebuild after %v, want at least the %v interval", waited, interval)
		}
	}
	release <- struct{}{}
	// Nothing is pending now, so no wait is long enough to make this flaky.
	select {
	case <-started:
		t.Fatal("rebuilt with no request pending")
	case <-time.After(5 * interval):
	}
	if got := runs.Load(); got != 3 {
		t.Fatalf("a request and two bursts of 10000 ran %d rebuilds, want 3", got)
	}
	cancel()
	<-done
}

// With nobody subscribed there is nobody to broadcast to, so requests
// build nothing.
func TestCoalesceLoopSkipsWhileInactive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kick := make(chan struct{}, 1)
	var runs atomic.Int64
	var active atomic.Bool
	go coalesceLoop(ctx, kick, 10*time.Millisecond, active.Load, func(context.Context) { runs.Add(1) })
	kick <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	if runs.Load() != 0 {
		t.Fatalf("rebuilt with no subscriber")
	}
	active.Store(true)
	kick <- struct{}{}
	waitFor(t, func() bool { return runs.Load() == 1 })
}

func TestHubHasSubscribers(t *testing.T) {
	h := newHub()
	if h.HasSubscribers() {
		t.Fatal("new hub reports subscribers")
	}
	ch := h.Subscribe()
	if !h.HasSubscribers() {
		t.Fatal("subscribed hub reports none")
	}
	h.Unsubscribe(ch)
	if h.HasSubscribers() {
		t.Fatal("hub still reports a subscriber after unsubscribe")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
