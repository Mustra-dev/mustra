package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// File integrity: the server diffs consecutive snapshots.
//
// Change detection lives here rather than on the endpoint for a reason
// worth stating: an attacker who can rewrite /etc/sudoers can also rewrite
// a baseline file sitting next to it. Keeping the previous state on the
// server means the comparison is made somewhere the endpoint cannot reach.
//
// The other half of making FIM usable is suppressing expected change. A
// file that changed during a deployment mustra itself ran is not a finding
// — it is the deployment working. Those are labelled rather than hidden,
// so the record stays complete but the list stays readable.

type integrityChange struct {
	AgentID        string     `json:"agent_id"`
	Hostname       string     `json:"hostname"`
	Path           string     `json:"path"`
	Kind           string     `json:"kind"` // added | removed | modified
	What           string     `json:"what"` // which attribute changed
	Was            string     `json:"was,omitempty"`
	Now            string     `json:"now,omitempty"`
	DetectedAt     time.Time  `json:"detected_at"`
	Expected       bool       `json:"expected"`
	Because        string     `json:"because,omitempty"`
	ID             string     `json:"id"`
	Labels         []string   `json:"labels"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
}

// integrityResponse is what GET /api/integrity answers.
type integrityResponse struct {
	Changes            []integrityChange      `json:"changes"`
	Coverage           integrityCoverage      `json:"coverage"`
	Metrics            store.IntegrityMetrics `json:"metrics"`
	ReportingEndpoints int                    `json:"reporting_endpoints"`
	Unexpected         int                    `json:"unexpected"`
	WatchedFiles       int                    `json:"watched_files"`
}

// integrityCoverage counts the endpoints reporting watch status, those
// with a watch list, and those that have applied it.
type integrityCoverage struct {
	Applied   int `json:"applied"`
	Monitored int `json:"monitored"`
	Total     int `json:"total"`
}

func (s *Server) handleIntegrity(w http.ResponseWriter, r *http.Request) {
	changes, err := s.store.ListIntegrityChanges(r.Context(), 500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := s.store.ListSensorDataForSensor(r.Context(), string(proto.SensorIntegrity))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	watched, reporting := 0, 0
	for _, row := range rows {
		var files []proto.IntegrityFile
		if err := json.Unmarshal(row.Data, &files); err != nil {
			continue
		}
		reporting++
		watched += len(files)
	}

	out := make([]integrityChange, 0, len(changes))
	unexpected := 0
	for _, c := range changes {
		out = append(out, integrityChange{
			AgentID: c.AgentID, Hostname: c.Hostname, Path: c.Path, Kind: c.Kind,
			What: c.What, Was: c.Was, Now: c.Now, DetectedAt: c.DetectedAt,
			Expected: c.Expected, Because: c.Because,
			ID: c.ID, Labels: c.Labels, AcknowledgedAt: c.AcknowledgedAt, AcknowledgedBy: c.AcknowledgedBy,
		})
		if !c.Expected {
			unexpected++
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DetectedAt.After(out[j].DetectedAt) })
	metrics, err := s.store.IntegrityMetricsSince(r.Context(), time.Now().Add(-7*24*time.Hour))
	if err != nil {
		s.logger.Warn("integrity metrics", "error", err)
	}
	monitored, applied, total := 0, 0, 0
	if status, err := s.watchStatus(r.Context()); err == nil {
		total = len(status)
		for _, row := range status {
			if row.WantRevision != "" {
				monitored++
				if row.Applied {
					applied++
				}
			}
		}
	}
	writeJSONResponse(w, integrityResponse{
		Changes: out, Unexpected: unexpected,
		WatchedFiles: watched, ReportingEndpoints: reporting,
		Metrics: metrics, Coverage: integrityCoverage{Total: total, Monitored: monitored, Applied: applied},
	})
}

// diffIntegritySnapshot compares a newly-arrived snapshot with the stored
// one and records what changed. Called from the sensor ingest path so a
// change is recorded once, when it arrives, rather than recomputed on
// every page load.
func (s *Server) diffIntegritySnapshot(ctx context.Context, agentID string, incoming []byte) {
	prev, err := s.store.GetSensorData(ctx, agentID, string(proto.SensorIntegrity))
	if err != nil || prev == nil {
		return // first snapshot is the baseline, not a set of changes
	}
	var before, after []proto.IntegrityFile
	if json.Unmarshal(prev.Data, &before) != nil || json.Unmarshal(incoming, &after) != nil {
		return
	}

	byPath := make(map[string]proto.IntegrityFile, len(before))
	for _, f := range before {
		byPath[f.Path] = f
	}
	seen := make(map[string]bool, len(after))

	// A deployment mustra ran recently explains a lot of change. Look it up
	// once for the whole diff rather than per file.
	expected, because := s.recentChangeWindow(ctx, agentID)

	var changes []store.IntegrityChange
	now := time.Now()
	add := func(path, kind, what, was, nowValue string) {
		c := store.IntegrityChange{
			AgentID: agentID, Path: path, Kind: kind, What: what,
			Was: was, Now: nowValue, Expected: expected, Because: because,
		}
		// Labels: any that match tag the change; one marked expected
		// classifies it, unless a deployment already did.
		labels, exp, why := s.labelChange(ctx, agentID, path, kind, now)
		c.Labels = labels
		if exp && !c.Expected {
			c.Expected, c.Because = true, why
		}
		changes = append(changes, c)
	}

	// Roots that became watched since the last snapshot: what appears under
	// them is the baseline for that root, not a change. Without this, adding
	// a watchlist reports every file it covers as "added" on every endpoint.
	fresh, dropped := s.changedWatchRoots(ctx, agentID)
	for _, f := range after {
		seen[f.Path] = true
		old, existed := byPath[f.Path]
		if !existed {
			if len(fresh) > 0 && underAnyRoot(f.Path, fresh) {
				continue
			}
			add(f.Path, "added", "file", "", f.Hash)
			continue
		}
		switch {
		case old.Hash != "" && f.Hash != "" && old.Hash != f.Hash:
			add(f.Path, "modified", "contents", old.Hash, f.Hash)
		case old.Mode != f.Mode:
			add(f.Path, "modified", "permissions", old.Mode, f.Mode)
		case old.Owner != f.Owner || old.Group != f.Group:
			add(f.Path, "modified", "ownership", old.Owner+":"+old.Group, f.Owner+":"+f.Group)
		case old.SymlinkTarget != f.SymlinkTarget:
			add(f.Path, "modified", "symlink target", old.SymlinkTarget, f.SymlinkTarget)
		case old.Hash == "" && f.Hash == "" && old.Size != f.Size:
			// Files too large to hash still report size, which catches the
			// common case rather than reporting nothing at all.
			add(f.Path, "modified", "size", itoa(old.Size), itoa(f.Size))
		}
	}
	for _, f := range before {
		if !seen[f.Path] {
			if len(dropped) > 0 && underAnyRoot(f.Path, dropped) {
				continue // the watch ended; the file did not go anywhere
			}
			add(f.Path, "removed", "file", f.Hash, "")
		}
	}
	if len(changes) == 0 {
		return
	}
	if err := s.store.RecordIntegrityChanges(ctx, changes); err != nil {
		s.logger.Warn("recording integrity changes failed", "agent_id", agentID, "error", err)
		return
	}
	s.logger.Info("file integrity changes detected", "agent_id", agentID,
		"changes", len(changes), "expected", expected)
}

// recentChangeWindow reports whether mustra itself touched this endpoint
// recently enough to explain file changes. This is what keeps FIM usable:
// without it, every patch run produces a wall of findings that are simply
// the patch run.
func (s *Server) recentChangeWindow(ctx context.Context, agentID string) (bool, string) {
	actions, err := s.store.ListAgentActions(ctx, agentID, 5)
	if err != nil || len(actions) == 0 {
		return false, ""
	}
	for _, a := range actions {
		end := a.StartedAt
		if a.FinishedAt != nil {
			end = *a.FinishedAt
		}
		if time.Since(end) <= 2*time.Hour {
			return true, a.Summary
		}
	}
	return false, ""
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
