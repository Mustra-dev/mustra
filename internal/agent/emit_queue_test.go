package agent

import (
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// A command whose output is slow to record must still finish cleanly:
// the pipe drains into the queue and every line is kept, in order.
func TestEmitQueueSlowConsumer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell integration")
	}
	q := newEmitQueue()
	var mu sync.Mutex
	var got []string
	out := &actionOutput{emit: func(line string) {
		q.add(func() {
			time.Sleep(time.Millisecond)
			mu.Lock()
			got = append(got, line)
			mu.Unlock()
		})
	}}
	cmd := exec.Command("sh", "-c", "i=0; while [ $i -lt 3000 ]; do echo line $i; i=$((i+1)); done")
	cmd.Stdout = out
	cmd.WaitDelay = 50 * time.Millisecond
	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed while output was still being recorded: %v", err)
	}
	out.flush()
	q.close()
	q.close()
	if len(got) != 3000 || got[0] != "line 0" || got[2999] != "line 2999" || !strings.HasPrefix(got[1500], "line 1500") {
		t.Fatalf("got %d lines, first %q", len(got), got[:1])
	}
}
