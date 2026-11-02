package server

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// TestLockedWriterKeepsBothStreams pins the fix for pushes that came back
// with an empty transcript: stdout and stderr are copied concurrently, and
// every write from both must land.
func TestLockedWriterKeepsBothStreams(t *testing.T) {
	var buf bytes.Buffer
	w := &lockedWriter{w: &buf}
	const writers, writes = 2, 2000
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writes; j++ {
				w.Write([]byte("x\n"))
			}
		}()
	}
	wg.Wait()
	if got := strings.Count(buf.String(), "x\n"); got != writers*writes {
		t.Fatalf("got %d writes, want %d", got, writers*writes)
	}
}

func TestLastLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"only\n", "only"},
		{"first\nIt looks like a container. Nothing was changed.\n\n", "It looks like a container. Nothing was changed."},
	} {
		if got := lastLine(tc.in); got != tc.want {
			t.Errorf("lastLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
