package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// A fleet answering a live query must not cost one full snapshot per
// answer — but the stream must still end on the snapshot holding every
// answer, even though the hub drops notifications a slow stream has not
// read yet.
func TestStreamQuerySnapshotsBoundedAndComplete(t *testing.T) {
	aq := &activeQuery{ID: "q-test", Expected: 2000, responded: map[string]bool{}, hub: newHub()}
	ch := aq.hub.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var sends []int
	done := make(chan struct{})
	go func() {
		defer close(done)
		streamQuerySnapshots(ctx, aq, ch, 20*time.Millisecond, func(payload []byte) {
			var snap querySnapshot
			if err := json.Unmarshal(payload, &snap); err != nil {
				t.Error(err)
			}
			mu.Lock()
			sends = append(sends, snap.Responded)
			mu.Unlock()
		})
	}()

	for i := range aq.Expected {
		id := fmt.Sprintf("agt-%032x", i)
		aq.mu.Lock()
		aq.responded[id] = true
		aq.results = append(aq.results, proto.QueryResult{QueryID: aq.ID, AgentID: id})
		aq.mu.Unlock()
		aq.hub.Publish(nil)
		if i%100 == 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sends) > 0 && sends[len(sends)-1] == aq.Expected
	})
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(sends) > 50 {
		t.Errorf("%d answers produced %d snapshots; want a handful", aq.Expected, len(sends))
	}
	for i := 1; i < len(sends); i++ {
		if sends[i] < sends[i-1] {
			t.Errorf("snapshot %d went backwards: %v", i, sends)
		}
	}
}
