package agent

import (
	"sync"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Producers that find the queue full and the batch loop past its cap both
// count drops, per kind, under one lock (run with -race).
func TestRecorderCountsDropsPerKind(t *testing.T) {
	r := &recorder{events: make(chan proto.RecorderEvent), pending: map[string]*proto.RecorderEvent{}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.emit(proto.RecorderEvent{Kind: "dns", Summary: "q"}) // nobody reads: dropped
		}()
	}
	for i := 0; i < maxRecorderPerBatch+5; i++ {
		r.record(proto.RecorderEvent{Kind: "network", Summary: string(rune('a'+i%26)) + string(rune(i))})
	}
	wg.Wait()
	if r.suppressed != 55 || r.suppressedByKind["dns"] != 50 || r.suppressedByKind["network"] != 5 {
		t.Fatalf("suppressed %d by kind %v, want 55: dns 50, network 5", r.suppressed, r.suppressedByKind)
	}
}
