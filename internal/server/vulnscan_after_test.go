package server

import (
	"testing"
	"time"
)

// Twenty endpoints finishing one patch run ask for a scan twenty times;
// the loop sees one pending request.
func TestRequestVulnScanCoalesces(t *testing.T) {
	s := &Server{vulnKick: make(chan struct{}, 1)}
	for range 20 {
		s.requestVulnScan()
	}
	if n := len(s.vulnKick); n != 1 {
		t.Fatalf("%d pending scan requests, want 1", n)
	}
	(&Server{}).requestVulnScan() // no loop running: must not block or panic
}

// A remediated endpoint's next software list triggers one scan, and only
// within the window.
func TestRemediatedRecentlyIsOneShot(t *testing.T) {
	s := &Server{}
	s.markRemediated("a1")
	if !s.remediatedRecently("a1") {
		t.Fatal("a just-remediated endpoint was not recognised")
	}
	if s.remediatedRecently("a1") {
		t.Fatal("the mark must be used once")
	}
	s.remediated.Store("a2", time.Now().Add(-remediatedWindow-time.Minute))
	if s.remediatedRecently("a2") {
		t.Fatal("a mark older than the window still counted")
	}
	if s.remediatedRecently("never") {
		t.Fatal("an unmarked endpoint counted")
	}
}
