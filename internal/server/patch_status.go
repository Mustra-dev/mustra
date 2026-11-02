package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// An endpoint whose check for pending updates fails keeps showing its last
// good list, which is indistinguishable from an up-to-date machine unless
// something says the list is stale. Agents publish the outcome of every
// check as the patch_status sensor; the server stores it next to the
// patches snapshot and the Patch page flags the devices whose last check
// failed, with since when.

// carryPatchFailingSince fills in FailingSince from the stored status: the
// time of the first failure in an unbroken run of them, so it survives
// agent restarts and is cleared by the first check that works.
func (s *Server) carryPatchFailingSince(ctx context.Context, agentID string, data json.RawMessage) json.RawMessage {
	var st proto.PatchStatus
	if json.Unmarshal(data, &st) != nil {
		return data
	}
	st.FailingSince = nil
	if !st.OK {
		since := st.CheckedAt
		if prev, err := s.store.GetSensorData(ctx, agentID, string(proto.SensorPatchStatus)); err == nil && prev != nil {
			var p proto.PatchStatus
			if json.Unmarshal(prev.Data, &p) == nil && !p.OK && p.FailingSince != nil && p.FailingSince.Before(since) {
				since = *p.FailingSince
			}
		}
		if since.IsZero() {
			since = time.Now().UTC()
		}
		st.FailingSince = &since
	}
	out, err := json.Marshal(st)
	if err != nil {
		return data
	}
	return out
}

// recordPatchStatus stores a check's outcome observed by the server itself
// (Rescan now, for agents too old to publish patch_status).
func (s *Server) recordPatchStatus(ctx context.Context, agentID string, st proto.PatchStatus) {
	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	raw = s.carryPatchFailingSince(ctx, agentID, raw)
	if err := s.store.UpsertSensorData(ctx, agentID, string(proto.SensorPatchStatus), st.CheckedAt, raw); err != nil {
		s.logger.Warn("record patch check status failed", "agent_id", agentID, "error", err)
	}
}

// patchStatusRow is an endpoint's last patch check outcome, with the
// inventory columns of its sensor row.
type patchStatusRow struct {
	proto.PatchStatus
	row store.AgentSensorRow
}

// patchStatuses loads every endpoint's last patch check outcome.
func (s *Server) patchStatuses(ctx context.Context) map[string]patchStatusRow {
	out := map[string]patchStatusRow{}
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorPatchStatus))
	if err != nil {
		return out
	}
	for _, r := range rows {
		var st proto.PatchStatus
		if json.Unmarshal(r.Data, &st) == nil {
			out[r.AgentID] = patchStatusRow{st, r}
		}
	}
	return out
}

// applyCheckFailure fills a device row's check fields from a failed status.
func (a *patchAgentSummary) applyCheckFailure(st proto.PatchStatus) {
	a.CheckError = firstNonEmpty(st.Error, "the check failed")
	if st.TimedOut {
		a.CheckError = "timed out: " + a.CheckError
	}
	if st.FailingSince != nil {
		a.CheckFailingSince = st.FailingSince.UTC().Format(time.RFC3339)
	}
}
