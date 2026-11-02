package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/patchpolicy"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// This file backs the Patches tab: an aggregate, fleet-wide view built
// entirely from each agent's cached "patches" sensor snapshot (no live
// query fan-out needed just to render the page — same "keep an answer
// fresh centrally" model as processes/services/installed_apps), plus the
// action to apply them to one agent.

type patchAgentSummary struct {
	AgentID     string `json:"agent_id"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Site        string `json:"site"`
	PatchCount  int    `json:"patch_count"`
	CollectedAt string `json:"collected_at"`
	// Patching is the status of a patch job still open on this endpoint
	// ("installing", "waiting"…), empty when none is.
	Patching      string `json:"patching,omitempty"`
	PatchingSince string `json:"patching_since,omitempty"`
	// ApplyElsewhere says where this endpoint's updates are installed when
	// it is not from here (Home Assistant OS); the page shows that instead
	// of an Apply button whose job could only be skipped.
	ApplyElsewhere string `json:"apply_elsewhere,omitempty"`
	// Platform and its version name the system the device runs (Debian
	// 13.7, Ubuntu 25.10, Windows 11 Pro), as the Home page does.
	Platform        string `json:"platform,omitempty"`
	PlatformVersion string `json:"platform_version,omitempty"`
	// Distro is every device's actual system (debian, raspbian, ubuntu,
	// darwin, the Windows edition), for the overview charts; Platform above
	// stays limited to what the Devices table's OS column should name.
	Distro string `json:"distro,omitempty"`
	// CheckError is set when the device's last check for pending updates
	// failed, so PatchCount and CollectedAt describe an older check;
	// CheckFailingSince is when the failures began.
	CheckError        string `json:"check_error,omitempty"`
	CheckFailingSince string `json:"check_failing_since,omitempty"`
}

type patchAffectedAgent struct {
	AgentID        string `json:"agent_id"`
	Hostname       string `json:"hostname"`
	CurrentVersion string `json:"current_version,omitempty"`
	NewVersion     string `json:"new_version,omitempty"`
}

type patchGroupEntry struct {
	OS       string `json:"os"`
	Name     string `json:"name"`
	Severity string `json:"severity,omitempty"`
	// NewVersion splits a package into one row per pending version, so a
	// version some endpoint has already moved past can be flagged
	// superseded (replaced the moment one endpoint reports
	// the replacement). Empty on platforms that do not version updates.
	NewVersion string `json:"new_version,omitempty"`
	Superseded bool   `json:"superseded,omitempty"`
	// RestartRequired: installing it restarts the machine (macOS says so).
	RestartRequired bool                 `json:"restart_required,omitempty"`
	FirstSeen       string               `json:"first_seen,omitempty"`
	AgeDays         int                  `json:"age_days"`
	AffectedCount   int                  `json:"affected_count"`
	AffectedAgents  []patchAffectedAgent `json:"affected_agents"`
}

type patchesSummaryResponse struct {
	Agents  []patchAgentSummary `json:"agents"`
	Patches []patchGroupEntry   `json:"patches"`
}

// handlePatchesSummary reads every agent's cached patches sensor and
// groups by (OS, patch name) so the console can show "this patch is
// missing on 4 of your 6 Linux boxes" without the browser doing the
// aggregation itself.
func (s *Server) handlePatchesSummary(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListSensorDataForSensor(r.Context(), string(proto.SensorPatches))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	agents := make([]patchAgentSummary, 0, len(rows))
	type groupKey struct{ os, name, version string }
	groups := map[groupKey]*patchGroupEntry{}
	var order []groupKey
	seen, _ := s.store.ListPatchObservations(r.Context())
	open, _ := s.store.OpenPatchJobs(r.Context())
	statuses := s.patchStatuses(r.Context())
	now := time.Now()

	for _, row := range rows {
		var patches []proto.PatchInfo
		if err := json.Unmarshal(row.Data, &patches); err != nil {
			s.logger.Warn("skipping unparsable patches sensor row", "agent_id", row.AgentID, "error", err)
			continue
		}
		agents = append(agents, patchAgentSummary{
			AgentID: row.AgentID, Hostname: row.Hostname, OS: row.OS, Site: row.Site,
			PatchCount: len(patches), CollectedAt: row.CollectedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			Patching: open[row.AgentID].Status, PatchingSince: openSince(open[row.AgentID]),
			ApplyElsewhere: patchUnsupportedReason(store.AgentRecord{Platform: row.Platform}),
			Distro:         row.Platform,
		})
		agents[len(agents)-1].Platform, agents[len(agents)-1].PlatformVersion = row.Platform, row.PlatformVersion
		// A status older than the list it would describe is history: a
		// later check worked even if its status never arrived.
		if st, ok := statuses[row.AgentID]; ok && !st.OK && !st.CheckedAt.Before(row.CollectedAt) {
			agents[len(agents)-1].applyCheckFailure(st.PatchStatus)
		}
		delete(statuses, row.AgentID)
		for _, p := range patches {
			k := groupKey{os: row.OS, name: p.Name, version: p.NewVersion}
			g, ok := groups[k]
			if !ok {
				g = &patchGroupEntry{OS: row.OS, Name: p.Name, Severity: p.Severity, NewVersion: p.NewVersion}
				if o, ok := seen[store.PatchObservationKey{OS: row.OS, Name: p.Name, NewVersion: p.NewVersion}]; ok {
					g.FirstSeen = o.FirstSeen.UTC().Format(time.RFC3339)
					g.AgeDays = int(now.Sub(o.FirstSeen).Hours() / 24)
				}
				groups[k] = g
				order = append(order, k)
			}
			if g.Severity == "" && p.Severity != "" {
				g.Severity = p.Severity
			}
			if p.RestartRequired {
				g.RestartRequired = true
			}
			g.AffectedCount++
			g.AffectedAgents = append(g.AffectedAgents, patchAffectedAgent{
				AgentID: row.AgentID, Hostname: row.Hostname, CurrentVersion: p.CurrentVersion, NewVersion: p.NewVersion,
			})
		}
	}

	// A device whose checks have never worked has no list at all; without
	// this it would be missing from the page rather than flagged.
	for id, st := range statuses {
		if st.OK {
			continue
		}
		a := patchAgentSummary{AgentID: id, Hostname: st.row.Hostname, OS: st.row.OS, Site: st.row.Site,
			Patching: open[id].Status, PatchingSince: openSince(open[id]),
			ApplyElsewhere: patchUnsupportedReason(store.AgentRecord{Platform: st.row.Platform}),
			Platform:       st.row.Platform, PlatformVersion: st.row.PlatformVersion, Distro: st.row.Platform}
		a.applyCheckFailure(st.PatchStatus)
		agents = append(agents, a)
	}

	patchList := make([]patchGroupEntry, 0, len(order))
	flags := make([]patchpolicy.Patch, 0, len(order))
	for _, k := range order {
		patchList = append(patchList, *groups[k])
		flags = append(flags, patchpolicy.Patch{OS: k.os, Name: k.name, NewVersion: k.version})
	}
	patchpolicy.MarkSuperseded(flags)
	for i := range patchList {
		patchList[i].Superseded = flags[i].Superseded
	}
	writeJSONResponse(w, patchesSummaryResponse{Agents: agents, Patches: patchList})
}

// applyPatchesRequest is the body of POST /api/agents/{id}/apply-patches.
type applyPatchesRequest struct {
	OverrideWindows bool `json:"override_windows"`
	patchRestart
}

// applyPatchesResponse is what POST /api/agents/{id}/apply-patches answers.
type applyPatchesResponse struct {
	Message string `json:"message"`
	OK      bool   `json:"ok"`
	RunID   string `json:"run_id"`
}

// handleApplyPatches sends the apply_patches command to one agent.
// Request/reply just confirms the agent accepted the job (see
// proto.AgentCommand's doc comment) — actually installing updates can take
// minutes, so the console re-polls the cached patches sensor afterward
// rather than this request blocking.
func (s *Server) handleApplyPatches(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u := auth.CurrentUser(r.Context())
	s.logger.Info("apply patches requested", "agent_id", id, "requested_by", u.Username)

	// Refused before a run is recorded, so a second click leaves no empty
	// deployment behind it.
	if open, err := s.store.OpenPatchJobs(r.Context()); err == nil {
		if j, busy := open[id]; busy {
			http.Error(w, fmt.Sprintf("already patching (%s, began %s ago); wait for that job to finish",
				j.Status, shortAgo(j.StartedAt)), http.StatusConflict)
			return
		}
	}
	// The same path a bulk deployment takes per endpoint: patch lists,
	// maintenance window, agent capability, dispatch, one action row.
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var target *store.AgentRecord
	for i := range agents {
		if agents[i].AgentID == id {
			target = &agents[i]
			break
		}
	}
	if target == nil {
		http.Error(w, "unknown endpoint", http.StatusNotFound)
		return
	}
	var req applyPatchesRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if !s.requireOverride(w, r, req.OverrideWindows) {
		return
	}
	restart, err := req.patchRestart.clean()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Recorded before dispatch: a single-device apply used to leave no
	// trace anywhere, so "I patched that box an hour ago" was unverifiable.
	// A one-off apply is a deployment too — it gets a run ID so it appears
	// in Deployments alongside bulk and scheduled jobs, rather than being
	// the one kind of patch job with no record to open. Only a request
	// that passed every check above gets one, so a refusal leaves no empty
	// deployment behind.
	runID := idgen.New("run-")
	if err := s.store.RecordPatchJobRun(r.Context(), store.PatchJobRun{
		ID: runID, TargetDesc: "device: " + target.Hostname, AgentCount: 1, TriggeredBy: u.Username,
	}); err != nil {
		s.logger.Warn("record patch job run failed", "agent_id", id, "error", err)
	}
	started, failed := s.deployPatchesToAgents(context.WithoutCancel(r.Context()), []store.AgentRecord{*target}, u.Username, runID, req.OverrideWindows, restart, nil)
	if reason, bad := failed[id]; bad {
		http.Error(w, reason, http.StatusBadGateway)
		return
	}
	_ = started
	writeJSONResponse(w, applyPatchesResponse{
		OK: true, RunID: runID,
		Message: "patch job started — check back in a few minutes",
	})
}

// --- Bulk "deploy now" ---

type deployPatchesRequest struct {
	TargetOS     string `json:"target_os,omitempty"`
	TargetSite   string `json:"target_site,omitempty"`
	TargetAgent  string `json:"target_agent,omitempty"`
	TargetVulnID string `json:"target_vuln_id,omitempty"`
	// TargetAgents names an explicit set of endpoints, which is how the
	// Remediation view deploys to "the ones that offer an update for this
	// package" rather than to an OS or a site.
	TargetAgents []string `json:"target_agents,omitempty"`
	// OverrideWindows patches endpoints whose maintenance windows are
	// closed. Needs deploy.override_windows.
	OverrideWindows bool `json:"override_windows,omitempty"`
	// OnlyPackages narrows the run to these packages, by endpoint ID: each
	// endpoint installs only the pending updates for the packages listed
	// for it (a remediation from a threat briefing), within what the patch
	// lists allow. Needs target_agents, and an endpoint not listed is not
	// patched. Omitted, every pending update is installed.
	OnlyPackages map[string][]string `json:"only_packages,omitempty"`
	patchRestart
}

type deployPatchesResponse struct {
	RunID      string            `json:"run_id"`
	TargetDesc string            `json:"target_desc"`
	Matched    int               `json:"matched"`
	Started    []string          `json:"started"`
	Failed     map[string]string `json:"failed"`
}

// handleDeployPatchesBulk is "Deploy now": fires apply_patches at every
// online agent matching the filter, immediately, once — not a schedule.
// Reuses the exact same targeting/dispatch code a scheduled deployment
// uses (patch_scheduler.go), just triggered by this request instead of a
// timer.
//
// It is audited the way the other endpoint actions are. A request refused
// as malformed, or for want of the override-windows permission, leaves no
// row. A refusal for endpoints out of reach is patches.denied, one an
// approval policy parks is patches.approval_requested, and only a run
// that starts is patches.deploy, naming the endpoints it was aimed at.
func (s *Server) handleDeployPatchesBulk(w http.ResponseWriter, r *http.Request) {
	var req deployPatchesRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	agents, err := s.resolvePatchTargets(r.Context(), req.TargetOS, req.TargetSite, req.TargetAgent, req.TargetVulnID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(agents) == 0 {
		http.Error(w, "no online agents match that target", http.StatusBadRequest)
		return
	}

	u := auth.CurrentUser(r.Context())
	if !s.requireOverride(w, r, req.OverrideWindows) {
		return
	}
	if len(req.OnlyPackages) > 0 && len(req.TargetAgents) == 0 {
		http.Error(w, "only_packages needs target_agents", http.StatusBadRequest)
		return
	}
	restart, err := req.patchRestart.clean()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	targetDesc := describePatchTarget(req.TargetOS, req.TargetSite, req.TargetAgent, req.TargetVulnID)
	if len(req.TargetAgents) > 0 {
		agents = filterToAgents(agents, req.TargetAgents)
		if len(agents) == 0 {
			http.Error(w, "none of the selected endpoints are online", http.StatusBadRequest)
			return
		}
		targetDesc = fmt.Sprintf("%d selected endpoint(s)", len(agents))
	}
	// A fleet-wide patch run names no endpoints, so what falls outside the
	// caller's management rights or the patches action group is dropped
	// and counted rather than refused — refusing "every Debian box"
	// because one of them is off-limits would be unusable.
	if len(req.TargetAgents) > 0 {
		ids := make([]string, 0, len(agents))
		for _, a := range agents {
			ids = append(ids, a.AgentID)
		}
		if !s.checkTargets(w, r, "patches", ids) {
			return
		}
	} else {
		ids := make([]string, 0, len(agents))
		for _, a := range agents {
			ids = append(ids, a.AgentID)
		}
		kept, dropped, err := s.narrowTargets(r.Context(), "patches", ids)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if dropped > 0 {
			keep := map[string]bool{}
			for _, id := range kept {
				keep[id] = true
			}
			narrowed := agents[:0:0]
			for _, a := range agents {
				if keep[a.AgentID] {
					narrowed = append(narrowed, a)
				}
			}
			agents = narrowed
			s.logger.Info("patch targets narrowed by access control", "dropped", dropped, "remaining", len(agents))
			targetDesc += fmt.Sprintf(" (%d outside your scope, skipped)", dropped)
		}
		if len(agents) == 0 {
			// Recorded like checkTargets' refusal of a named endpoint: being
			// refused everything is as much a denial as being refused one.
			// narrowTargets counts both reasons together, so the row has one
			// count, not authorizeEndpointAction's outside_rights and
			// outside_action_group pair.
			s.audit(r.Context(), auditEvent{Action: "patches.denied", Actor: u.Username, Target: targetDesc,
				Outcome: "denied", Severity: "warning", Detail: map[string]any{"outside_rights_or_action_group": dropped}})
			http.Error(w, "every matching endpoint is outside your management rights or the patches action group", http.StatusForbidden)
			return
		}
	}
	{
		ids := make([]string, 0, len(agents))
		for _, a := range agents {
			ids = append(ids, a.AgentID)
		}
		if s.requireApproval(w, r, "patches", "patches.deploy",
			fmt.Sprintf("patch %s", targetDesc), ids, req) {
			return
		}
	}
	s.logger.Info("bulk patch deploy requested", "target", targetDesc, "matched", len(agents), "requested_by", u.Username)

	runID := idgen.New("run-")
	if err := s.store.RecordPatchJobRun(r.Context(), store.PatchJobRun{
		ID: runID, TargetDesc: targetDesc, AgentCount: len(agents), TriggeredBy: u.Username,
	}); err != nil {
		s.logger.Warn("record patch job run failed", "error", err)
	}
	// Written before anything is sent: what was asked for is worth
	// recording even if no endpoint answers. Unlike software deployment,
	// which sends operator code and refuses to start without its row, a
	// failed write here does not stop the run; the deferred write this
	// replaced never blocked it either. Detached, because a fleet-wide
	// patch deploy is exactly the event that must survive the browser
	// giving up on it. Per-endpoint outcomes are on the run, not here.
	ev := auditEvent{
		Action: "patches.deploy", Actor: u.Username, Target: targetDesc, Severity: "notice",
		Detail: map[string]any{"run_id": runID, "endpoints": len(agents),
			"override_windows": req.OverrideWindows, "restart_mode": restart.Mode},
	}
	if len(agents) == 1 {
		ev.AgentID = agents[0].AgentID
	}
	s.audit(context.WithoutCancel(r.Context()), ev)
	// Detached from the request. This fans out 16-wide with a 5s timeout per
	// agent, so a large fleet runs for minutes — past the 100s origin limit
	// the tunnel in front of this console imposes. On the request context a
	// disconnect there did not merely lose the reply: every queued goroutine
	// got "context canceled", marked its agent as not responding, and then
	// failed to write even that, leaving actions open to age into stalled
	// while the undispatched half of the fleet was never patched at all.
	//
	// The work completes now whether or not anyone is still listening. A
	// client that times out loses the summary, not the deployment, and the
	// run is on the Deployments page either way.
	bg := context.WithoutCancel(r.Context())
	started, failed := s.deployPatchesToAgents(bg, agents, u.Username, runID, req.OverrideWindows, restart, req.OnlyPackages)
	writeJSONResponse(w, deployPatchesResponse{
		RunID: runID, TargetDesc: targetDesc, Matched: len(agents), Started: started, Failed: failed,
	})
}

// --- Schedules ---

// listPatchSchedulesResponse is what GET /api/patches/schedules answers.
type listPatchSchedulesResponse struct {
	Schedules []store.PatchSchedule `json:"schedules"`
}

func (s *Server) handleListPatchSchedules(w http.ResponseWriter, r *http.Request) {
	schedules, err := s.store.ListPatchSchedules(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listPatchSchedulesResponse{Schedules: schedules})
}

type createPatchScheduleRequest struct {
	Name         string `json:"name" api:"required"`
	TargetOS     string `json:"target_os,omitempty"`
	TargetSite   string `json:"target_site,omitempty"`
	TargetAgent  string `json:"target_agent,omitempty"`
	TargetVulnID string `json:"target_vuln_id,omitempty"`
	// TargetAgents freezes the schedule to a named set of endpoints, the
	// same shape "Deploy now" takes. Resolved at fire time like every other
	// target, so a machine that is offline that night is simply skipped.
	TargetAgents []string   `json:"target_agents,omitempty"`
	Kind         string     `json:"kind" api:"required"` // "once" | "daily" | "weekly"
	RunAt        *time.Time `json:"run_at,omitempty"`
	TimeOfDay    string     `json:"time_of_day,omitempty"`
	Weekday      *int       `json:"weekday,omitempty"`
}

func (s *Server) handleCreatePatchSchedule(w http.ResponseWriter, r *http.Request) {
	var req createPatchScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	var nextRunAt *time.Time
	switch req.Kind {
	case "once":
		if req.RunAt == nil {
			http.Error(w, "run_at is required for a one-time schedule", http.StatusBadRequest)
			return
		}
		at := req.RunAt.UTC()
		nextRunAt = &at
	case "daily", "weekly":
		next, err := computeNextRun(req.Kind, req.TimeOfDay, req.Weekday, time.Now().UTC())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		nextRunAt = next
	default:
		http.Error(w, `kind must be "once", "daily", or "weekly"`, http.StatusBadRequest)
		return
	}

	u := auth.CurrentUser(r.Context())
	sched, err := s.store.CreatePatchSchedule(r.Context(), store.PatchSchedule{
		ID: idgen.New("psched-"), Name: req.Name, TargetOS: req.TargetOS, TargetSite: req.TargetSite,
		TargetAgent: req.TargetAgent, TargetAgents: req.TargetAgents, TargetVulnID: req.TargetVulnID,
		Kind: req.Kind, RunAt: req.RunAt, TimeOfDay: req.TimeOfDay,
		Weekday: req.Weekday, Enabled: true, NextRunAt: nextRunAt, CreatedBy: u.Username,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("patch schedule created", "name", sched.Name, "kind", sched.Kind, "created_by", u.Username)
	writeJSONResponse(w, sched)
}

type setScheduleEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleSetPatchScheduleEnabled(w http.ResponseWriter, r *http.Request) {
	var req setScheduleEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	sched, err := s.store.GetPatchSchedule(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sched == nil {
		http.Error(w, "no such schedule", http.StatusNotFound)
		return
	}

	// Re-arm from now, not from whenever it was paused. See
	// SetPatchScheduleEnabled: leaving the stale next_run_at in place meant
	// re-enabling a paused daily schedule patched the fleet within the
	// minute, whatever time of day it happened to be.
	var next *time.Time
	if req.Enabled {
		computed, cerr := computeNextRun(sched.Kind, sched.TimeOfDay, sched.Weekday, time.Now().UTC())
		if cerr != nil {
			http.Error(w, cerr.Error(), http.StatusBadRequest)
			return
		}
		if sched.Kind == "once" && sched.LastRunAt != nil {
			// Already fired. Re-enabling cannot resurrect it, and pretending
			// otherwise leaves a schedule the console shows as armed and the
			// scheduler can never select.
			http.Error(w, "this one-off schedule has already run — create a new one", http.StatusBadRequest)
			return
		}
		if sched.Kind == "once" {
			next = sched.RunAt
		} else {
			next = computed
		}
	}
	if err := s.store.SetPatchScheduleEnabled(r.Context(), id, req.Enabled, next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	s.logger.Info("patch schedule toggled", "schedule", sched.Name,
		"enabled", req.Enabled, "next_run", next, "by", who)
	// Turning a schedule back on re-arms patching of its endpoints, which
	// is as much worth a row as creating it was.
	s.audit(r.Context(), auditEvent{Action: "patch_schedule.enabled", Actor: who, Target: sched.Name, Severity: "notice",
		Detail: map[string]any{"id": sched.ID, "enabled": req.Enabled, "next_run_at": next,
			"targets": describePatchTarget(sched.TargetOS, sched.TargetSite, sched.TargetAgent, sched.TargetVulnID), "selected": len(sched.TargetAgents)}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeletePatchSchedule(w http.ResponseWriter, r *http.Request) {
	sched, err := s.store.GetPatchSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sched == nil {
		http.Error(w, "no such schedule", http.StatusNotFound)
		return
	}
	if err := s.store.DeletePatchSchedule(r.Context(), sched.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "patch_schedule.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: sched.Name, Severity: "notice", Detail: map[string]any{"id": sched.ID, "created_by": sched.CreatedBy}})
	w.WriteHeader(http.StatusNoContent)
}

// listPatchHistoryResponse is what GET /api/patches/history answers.
type listPatchHistoryResponse struct {
	Runs []store.PatchJobRun `json:"runs"`
}

func (s *Server) handleListPatchHistory(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListPatchJobRuns(r.Context(), 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listPatchHistoryResponse{Runs: runs})
}

func openSince(j store.OpenPatchJob) string {
	if j.StartedAt.IsZero() {
		return ""
	}
	return j.StartedAt.UTC().Format(time.RFC3339)
}

// shortAgo is a duration as people write it: "3h2m", "45m", "1m".
func shortAgo(t time.Time) string {
	d := time.Since(t).Round(time.Minute)
	if d < time.Minute {
		return "less than a minute"
	}
	return strings.TrimSuffix(d.String(), "0s")
}
