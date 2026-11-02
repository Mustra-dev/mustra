package nats

import (
	"testing"
	"time"
)

// A fleet reconnecting after a broker restart must spread out: the wait
// grows with each failed attempt up to the cap, is random within it, and
// is never zero.
func TestReconnectDelay(t *testing.T) {
	for attempts := -1; attempts <= 50; attempts++ {
		ceiling := reconnectMax
		if attempts < 5 {
			ceiling = min(reconnectMax, reconnectBase<<max(attempts, 0))
		}
		lo, hi := time.Duration(1<<62), time.Duration(0)
		for range 2000 {
			d := reconnectDelay(attempts)
			if d < 500*time.Millisecond || d >= 500*time.Millisecond+ceiling {
				t.Fatalf("attempt %d: delay %s outside [0.5s, %s)", attempts, d, 500*time.Millisecond+ceiling)
			}
			lo, hi = min(lo, d), max(hi, d)
		}
		// Full jitter: the draws cover most of the window.
		if hi-lo < ceiling/2 {
			t.Errorf("attempt %d: delays %s..%s barely spread over a %s window", attempts, lo, hi, ceiling)
		}
	}
	if reconnectDelay(1) >= 500*time.Millisecond+5*time.Second {
		t.Error("the first retry must stay quick so a short blip costs what it did")
	}
}
