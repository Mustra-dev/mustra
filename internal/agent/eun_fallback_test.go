package agent

import (
	"testing"
	"time"
)

// The tray helper and msg.exe show the same message. When both run, the
// person gets two notifications for one event -- which is what happened on
// the first real endpoint the tray was installed on.
func TestTrayPresenceIsWhatSuppressesTheFallback(t *testing.T) {
	var seen lastSeen

	if seen.active(30 * time.Second) {
		t.Fatal("a tray that has never polled should not suppress anything")
	}

	seen.mark()
	if !seen.active(30 * time.Second) {
		t.Fatal("a tray that just polled should suppress the fallback")
	}

	// Stale: the tray was killed, or never started after a reboot. The
	// fallback has to come back on its own, because the alternative is an
	// endpoint that silently shows nothing.
	seen.mu.Lock()
	seen.at = time.Now().Add(-31 * time.Second)
	seen.mu.Unlock()
	if seen.active(30 * time.Second) {
		t.Fatal("a stale tray should let the fallback run again")
	}
}

// The supervisor uses the same signal to decide whether to start another
// helper. A window wider than the fallback's, because starting a duplicate
// is a worse outcome than one late notification.
func TestSupervisorTreatsAPollAsProofOfLife(t *testing.T) {
	var seen lastSeen
	seen.mark()
	if !seen.active(90 * time.Second) {
		t.Fatal("a helper that just polled should not be started again")
	}
	seen.mu.Lock()
	seen.at = time.Now().Add(-91 * time.Second)
	seen.mu.Unlock()
	if seen.active(90 * time.Second) {
		t.Fatal("a helper that stopped polling should be restarted")
	}
}
