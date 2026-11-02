package server

import "sync"

// hub is a tiny fan-out broadcaster for SSE: each subscriber gets a
// buffered channel of pre-encoded JSON payloads. A slow or gone subscriber
// never blocks the publisher — if its buffer is full, the update is
// dropped for that subscriber (the next broadcast supersedes it anyway,
// since every payload here is a full snapshot, not a delta).
type hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func newHub() *hub {
	return &hub{subs: make(map[chan []byte]struct{})}
}

func (h *hub) Subscribe() chan []byte {
	ch := make(chan []byte, 4)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

// HasSubscribers reports whether anyone is listening, so a publisher can
// skip building a payload nobody will receive.
func (h *hub) HasSubscribers() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs) > 0
}

func (h *hub) Publish(payload []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- payload:
		default:
		}
	}
}
