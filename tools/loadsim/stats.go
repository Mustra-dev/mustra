//go:build loadsim

package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// latencies collects durations for percentile reporting. A mutex and a
// slice is plenty for the rates a single simulator process produces.
type latencies struct {
	mu sync.Mutex
	d  []time.Duration
}

func (l *latencies) add(d time.Duration) {
	l.mu.Lock()
	l.d = append(l.d, d)
	l.mu.Unlock()
}

// snapshot returns a sorted copy and, when reset, starts a new window.
func (l *latencies) snapshot(reset bool) []time.Duration {
	l.mu.Lock()
	out := append([]time.Duration(nil), l.d...)
	if reset {
		l.d = l.d[:0]
	}
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type summary struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50_ms"`
	P90 float64 `json:"p90_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

func summarize(sorted []time.Duration) summary {
	if len(sorted) == 0 {
		return summary{}
	}
	pct := func(p float64) float64 {
		i := int(p * float64(len(sorted)-1))
		return ms(sorted[i])
	}
	return summary{N: len(sorted), P50: pct(0.50), P90: pct(0.90), P99: pct(0.99), Max: ms(sorted[len(sorted)-1])}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (s summary) String() string {
	if s.N == 0 {
		return "n=0"
	}
	return fmt.Sprintf("n=%d p50=%.1fms p90=%.1fms p99=%.1fms max=%.1fms", s.N, s.P50, s.P90, s.P99, s.Max)
}
