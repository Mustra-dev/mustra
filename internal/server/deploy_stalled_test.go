package server

import (
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// A job is stalled when the endpoint it was sent to has stopped answering
// while the job is still outstanding. The case that matters is an agent
// update that takes the agent down: the job stays queued or running forever
// and nothing else reports the connection between the two.
func TestDeployJobStalled(t *testing.T) {
	const stale = 2 * time.Minute
	ago := func(d time.Duration) *time.Time { t := time.Now().Add(-d); return &t }

	cases := []struct {
		name      string
		status    string
		heartbeat *time.Time
		created   time.Duration // how long ago the job was created
		want      bool
	}{
		{"running, endpoint answering", "running", ago(10 * time.Second), time.Minute, false},
		{"running, endpoint silent", "running", ago(30 * time.Minute), time.Hour, true},
		{"queued, endpoint silent -- the update that killed the agent", "queued", ago(30 * time.Minute), time.Hour, true},
		{"held is not dispatched, so silence means nothing", "held", ago(30 * time.Minute), time.Hour, false},
		{"finished jobs are never stalled", "succeeded", ago(30 * time.Minute), time.Hour, false},
		{"failed jobs are never stalled", "failed", ago(30 * time.Minute), time.Hour, false},
		{"never seen, but only just dispatched", "queued", nil, 5 * time.Second, false},
		{"never seen, long enough that it should have answered", "queued", nil, time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := store.DeployJobRecord{
				Status:        tc.status,
				LastHeartbeat: tc.heartbeat,
				Job:           proto.DeployJob{CreatedAt: time.Now().Add(-tc.created)},
			}
			silent, got := deployJobStalled(record, stale)
			if got != tc.want {
				t.Fatalf("stalled = %v, want %v (silent %s)", got, tc.want, silent)
			}
			if got && silent <= stale {
				t.Fatalf("reported stalled after only %s, which is inside the %s window", silent, stale)
			}
		})
	}
}
