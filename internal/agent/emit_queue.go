package agent

import "sync"

// emitQueue runs output callbacks in order on its own goroutine, so the
// writer feeding it (a command's output pipe) never waits on them. Memory
// is bounded by actionOutput's own cap on retained output.
type emitQueue struct {
	mu     sync.Mutex
	items  []func()
	closed bool
	wake   chan struct{}
	done   chan struct{}
}

func newEmitQueue() *emitQueue {
	q := &emitQueue{wake: make(chan struct{}, 1), done: make(chan struct{})}
	go q.loop()
	return q
}

func (q *emitQueue) add(f func()) {
	q.mu.Lock()
	q.items = append(q.items, f)
	q.mu.Unlock()
	q.signal()
}

func (q *emitQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *emitQueue) loop() {
	defer close(q.done)
	for {
		q.mu.Lock()
		batch, closed := q.items, q.closed
		q.items = nil
		q.mu.Unlock()
		for _, f := range batch {
			f()
		}
		if len(batch) == 0 {
			if closed {
				return
			}
			<-q.wake
		}
	}
}

// close waits until everything added has run. Safe to call more than once.
func (q *emitQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.signal()
	<-q.done
}
