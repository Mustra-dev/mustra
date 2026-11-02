package agent

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mustra-agent.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStoreAgentIDRoundTrip(t *testing.T) {
	s := openTestStore(t)

	id, err := s.LoadAgentID()
	if err != nil {
		t.Fatalf("LoadAgentID (empty): %v", err)
	}
	if id != "" {
		t.Fatalf("expected empty agent id before first save, got %q", id)
	}

	if err := s.SaveAgentID("agt-abc123"); err != nil {
		t.Fatalf("SaveAgentID: %v", err)
	}
	id, err = s.LoadAgentID()
	if err != nil {
		t.Fatalf("LoadAgentID: %v", err)
	}
	if id != "agt-abc123" {
		t.Fatalf("got agent id %q, want agt-abc123", id)
	}
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mustra-agent.db")

	s1, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := s1.SaveAgentID("agt-persisted"); err != nil {
		t.Fatalf("SaveAgentID: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen OpenStore: %v", err)
	}
	defer s2.Close()
	id, err := s2.LoadAgentID()
	if err != nil {
		t.Fatalf("LoadAgentID after reopen: %v", err)
	}
	if id != "agt-persisted" {
		t.Fatalf("got %q after reopen, want agt-persisted", id)
	}
}

func TestOutboxEnqueueDrainOrderAndRemoval(t *testing.T) {
	s := openTestStore(t)

	subjects := []string{"beacon.agent.a.heartbeat", "beacon.agent.a.facts", "beacon.agent.a.heartbeat"}
	for _, subj := range subjects {
		if err := s.Enqueue(BufferedMessage{Subject: subj, Payload: []byte("x")}); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	pending, err := s.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if pending != len(subjects) {
		t.Fatalf("Pending() = %d, want %d", pending, len(subjects))
	}

	var got []string
	err = s.Drain(func(msg BufferedMessage) error {
		got = append(got, msg.Subject)
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(got) != len(subjects) {
		t.Fatalf("drained %d messages, want %d", len(got), len(subjects))
	}
	for i, subj := range subjects {
		if got[i] != subj {
			t.Errorf("drain order[%d] = %q, want %q", i, got[i], subj)
		}
	}

	pending, err = s.Pending()
	if err != nil {
		t.Fatalf("Pending after drain: %v", err)
	}
	if pending != 0 {
		t.Fatalf("Pending() after full drain = %d, want 0", pending)
	}
}

func TestOutboxDrainStopsOnErrorPreservingOrder(t *testing.T) {
	s := openTestStore(t)

	for i := 0; i < 3; i++ {
		if err := s.Enqueue(BufferedMessage{Subject: "subj", Payload: []byte{byte(i)}}); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	calls := 0
	err := s.Drain(func(msg BufferedMessage) error {
		calls++
		if calls == 2 {
			return errSimulatedFailure
		}
		return nil
	})
	if err != errSimulatedFailure {
		t.Fatalf("Drain error = %v, want errSimulatedFailure", err)
	}
	if calls != 2 {
		t.Fatalf("Drain invoked fn %d times, want 2 (stop at failure)", calls)
	}

	pending, err := s.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if pending != 2 {
		t.Fatalf("Pending() after partial drain = %d, want 2 (first message removed, other two remain)", pending)
	}
}

var errSimulatedFailure = simulatedError{}

type simulatedError struct{}

func (simulatedError) Error() string { return "simulated publish failure" }

// The outbox drains in order, so one message that can never be published
// blocks every message queued behind it. DropFirst is how that deadlock is
// broken; this pins that it removes exactly the head and leaves the rest in
// order.
func TestStoreDropFirstUnblocksTheOutbox(t *testing.T) {
	s := openTestStore(t)

	for _, subj := range []string{"poison", "second", "third"} {
		if err := s.Enqueue(BufferedMessage{Subject: subj, Payload: []byte(subj)}); err != nil {
			t.Fatalf("Enqueue(%s): %v", subj, err)
		}
	}

	// Every drain attempt fails on the head, and nothing behind it moves.
	for i := 0; i < 3; i++ {
		var seen []string
		err := s.Drain(func(msg BufferedMessage) error {
			seen = append(seen, msg.Subject)
			return errUndeliverable
		})
		if err == nil {
			t.Fatal("expected Drain to stop on the failing head message")
		}
		if len(seen) != 1 || seen[0] != "poison" {
			t.Fatalf("attempt %d: drain saw %v, want just [poison]", i, seen)
		}
	}
	if n, _ := s.Pending(); n != 3 {
		t.Fatalf("pending = %d, want 3 (nothing should have drained)", n)
	}

	dropped, err := s.DropFirst()
	if err != nil {
		t.Fatalf("DropFirst: %v", err)
	}
	if dropped.Subject != "poison" {
		t.Fatalf("dropped %q, want poison", dropped.Subject)
	}

	// With the head gone the rest drain, still in order.
	var seen []string
	if err := s.Drain(func(msg BufferedMessage) error {
		seen = append(seen, msg.Subject)
		return nil
	}); err != nil {
		t.Fatalf("Drain after DropFirst: %v", err)
	}
	if len(seen) != 2 || seen[0] != "second" || seen[1] != "third" {
		t.Fatalf("drained %v, want [second third]", seen)
	}
	if n, _ := s.Pending(); n != 0 {
		t.Fatalf("pending = %d, want 0", n)
	}
}

func TestStoreDropFirstOnEmptyOutbox(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.DropFirst(); err != nil {
		t.Fatalf("DropFirst on empty outbox should be a no-op, got %v", err)
	}
}

var errUndeliverable = errorString("undeliverable")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestEnqueueLatestReplacesSameSubject(t *testing.T) {
	s := openTestStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Enqueue(BufferedMessage{Subject: "beacon.agent.a.procevents", Payload: []byte("p1")}))
	must(s.EnqueueLatest(BufferedMessage{Subject: "beacon.agent.a.heartbeat", Payload: []byte("h1")}))
	must(s.Enqueue(BufferedMessage{Subject: "beacon.agent.a.procevents", Payload: []byte("p2")}))
	must(s.EnqueueLatest(BufferedMessage{Subject: "beacon.agent.a.heartbeat", Payload: []byte("h2")}))
	n, _ := s.Pending()
	if n != 3 {
		t.Fatalf("pending = %d, want 3 (the first heartbeat replaced)", n)
	}
	var latest []string
	must(s.DrainWhere(func(subj string) bool { return subj == "beacon.agent.a.heartbeat" }, func(m BufferedMessage) error {
		latest = append(latest, string(m.Payload))
		return nil
	}))
	if len(latest) != 1 || latest[0] != "h2" {
		t.Fatalf("priority drain got %v, want [h2]", latest)
	}
	batch, err := s.PeekBatch(10)
	must(err)
	if len(batch) != 2 || string(batch[0].Msg.Payload) != "p1" || string(batch[1].Msg.Payload) != "p2" {
		t.Fatalf("remaining backlog wrong: %+v", batch)
	}
	must(s.DeleteKeys([][]byte{batch[0].Key}))
	n, _ = s.Pending()
	if n != 1 {
		t.Fatalf("pending after delete = %d, want 1", n)
	}
}

func TestPruneOutboxByAgeAndCount(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	old := now.Add(-50 * time.Hour)
	entries := []BufferedMessage{
		{Subject: "beacon.agent.a.procevents", Payload: []byte("stale"), Queued: old},
		{Subject: "beacon.agent.a.actionresult", Payload: []byte("keep-old-result"), Queued: old},
		{Subject: "beacon.agent.a.procevents", Payload: []byte("young1"), Queued: now},
		{Subject: "beacon.agent.a.procevents", Payload: []byte("young2"), Queued: now},
		{Subject: "beacon.agent.a.fileevents", Payload: []byte("keep-file"), Queued: now},
	}
	for _, e := range entries {
		if err := s.Enqueue(e); err != nil {
			t.Fatal(err)
		}
	}
	expirable := func(subj string) bool { return strings.HasSuffix(subj, ".procevents") }
	dropped, err := s.PruneOutbox(now, 40*time.Hour, 3, expirable)
	if err != nil {
		t.Fatal(err)
	}
	// stale by age, then young1 to get under the cap of 3.
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	batch, _ := s.PeekBatch(10)
	var got []string
	for _, e := range batch {
		got = append(got, string(e.Msg.Payload))
	}
	want := []string{"keep-old-result", "young2", "keep-file"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("after prune %v, want %v", got, want)
	}
}
