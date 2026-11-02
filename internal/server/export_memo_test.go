package server

import (
	"context"
	"errors"
	"testing"
)

// Panels of one dashboard that read the same source share a single read;
// different sources, different saved questions and separate renders do not.
func TestExportRowsMemo(t *testing.T) {
	calls := map[string]int{}
	compute := func(key string) func() ([]map[string]any, error) {
		return func() ([]map[string]any, error) {
			calls[key]++
			return []map[string]any{{"source": key}}, nil
		}
	}
	ctx := withExportMemo(context.Background())
	for range 6 {
		rows, err := exportRowsMemo(ctx, "endpoints", "", compute("endpoints"))
		if err != nil || len(rows) != 1 || rows[0]["source"] != "endpoints" {
			t.Fatalf("rows %v err %v", rows, err)
		}
	}
	_, _ = exportRowsMemo(ctx, "patches", "", compute("patches"))
	_, _ = exportRowsMemo(ctx, "question", "q1", compute("q1"))
	_, _ = exportRowsMemo(ctx, "question", "q2", compute("q2"))
	if calls["endpoints"] != 1 || calls["patches"] != 1 || calls["q1"] != 1 || calls["q2"] != 1 {
		t.Fatalf("calls %v: want one read per distinct source", calls)
	}

	// A new render reads again: nothing outlives the request.
	_, _ = exportRowsMemo(withExportMemo(context.Background()), "endpoints", "", compute("endpoints"))
	// No memo in the context: every call reads.
	_, _ = exportRowsMemo(context.Background(), "endpoints", "", compute("endpoints"))
	if calls["endpoints"] != 3 {
		t.Fatalf("endpoints read %d times, want 3", calls["endpoints"])
	}

	// A failed read is not remembered.
	fails := 0
	failing := func() ([]map[string]any, error) { fails++; return nil, errors.New("down") }
	_, err1 := exportRowsMemo(ctx, "findings", "", failing)
	_, err2 := exportRowsMemo(ctx, "findings", "", failing)
	if err1 == nil || err2 == nil || fails != 2 {
		t.Fatalf("errors %v %v after %d reads: a failure must be retried, not cached", err1, err2, fails)
	}
}
