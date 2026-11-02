package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Failing since is the first failure of an unbroken run: kept across
// failures, cleared by a check that works. The Patch page flags the device
// only while its last check is newer than its list.
func TestPatchCheckFailuresAreKeptAndShown(t *testing.T) {
	s, st, agent := threatRemediationFixture(t, "0.58.0")
	ctx := context.Background()
	t0 := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	record := func(at time.Time, ok bool) proto.PatchStatus {
		s.recordPatchStatus(ctx, agent, proto.PatchStatus{OK: ok, Error: map[bool]string{false: "apt-get update: could not resolve deb.debian.org"}[ok], CheckedAt: at})
		row, err := st.GetSensorData(ctx, agent, string(proto.SensorPatchStatus))
		if err != nil || row == nil {
			t.Fatalf("status not stored: %v", err)
		}
		var got proto.PatchStatus
		_ = json.Unmarshal(row.Data, &got)
		return got
	}
	if got := record(t0, false); got.FailingSince == nil || !got.FailingSince.Equal(t0) {
		t.Fatalf("first failure: %+v", got)
	}
	if got := record(t0.Add(15*time.Minute), false); got.FailingSince == nil || !got.FailingSince.Equal(t0) {
		t.Fatalf("second failure moved failing_since: %+v", got)
	}

	summary := func() patchAgentSummary {
		w := httptest.NewRecorder()
		s.handlePatchesSummary(w, httptest.NewRequest(http.MethodGet, "/api/patches", nil))
		var resp patchesSummaryResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		for _, a := range resp.Agents {
			if a.AgentID == agent {
				return a
			}
		}
		t.Fatal("device missing from the summary")
		return patchAgentSummary{}
	}
	if a := summary(); a.CheckError == "" || a.CheckFailingSince != t0.Format(time.RFC3339) || a.PatchCount != 2 {
		t.Fatalf("failing device: %+v", a)
	}
	if got := record(t0.Add(30*time.Minute), true); got.FailingSince != nil {
		t.Fatalf("a working check kept failing_since: %+v", got)
	}
	if a := summary(); a.CheckError != "" {
		t.Fatalf("recovered device still flagged: %+v", a)
	}
}
