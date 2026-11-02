package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// This file is the engine behind both "Deploy now" (an ad-hoc bulk push,
// fired immediately from the API handler) and scheduled/recurring patch
// deployments (patchSchedulerLoop, ticking once a minute) — they share
// exactly the same targeting and dispatch logic; a schedule firing is just
// an ad-hoc deploy whose trigger was a timer instead of a click.

// resolvePatchTargets returns every online agent matching the given
// filter. Empty os/site/agentID/vulnID means "no restriction on that
// axis" — all empty together means every online agent in the fleet.
// Priority when more than one is set: agentID overrides everything (a
// single-agent schedule/deploy); vulnID next (a Risk & Compliance CVE's
// "Deploy"/"Schedule" button — resolved fresh against current scan data
// every time this runs, not a frozen host list, so a schedule stays
// correct as the fleet's exposure changes); otherwise os/site.
func (s *Server) resolvePatchTargets(ctx context.Context, os, site, agentID, vulnID string) ([]store.AgentRecord, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}

	if agentID != "" {
		for _, a := range agents {
			if a.AgentID == agentID && a.Online {
				return []store.AgentRecord{a}, nil
			}
		}
		return nil, nil
	}

	if vulnID != "" {
		affected, err := s.store.ListAgentIDsAffectedByVuln(ctx, vulnID)
		if err != nil {
			return nil, err
		}
		affectedSet := make(map[string]bool, len(affected))
		for _, id := range affected {
			affectedSet[id] = true
		}
		var out []store.AgentRecord
		for _, a := range agents {
			if a.Online && affectedSet[a.AgentID] {
				out = append(out, a)
			}
		}
		return out, nil
	}

	var out []store.AgentRecord
	for _, a := range agents {
		if !a.Online {
			continue
		}
		// A broad target (all Linux, a site) leaves out endpoints that
		// cannot be patched at all rather than adding a guaranteed skip
		// for each; naming one directly still records why it was skipped.
		if patchUnsupportedReason(a) != "" {
			continue
		}
		if os != "" && a.OS != os {
			continue
		}
		if site != "" && a.Site != site {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// filterToAgents narrows a resolved target set to an explicit list of
// endpoints. "Deploy now", a saved schedule and the deploy preview all
// accept the same "specific endpoints" shape, and each one still resolves
// through resolvePatchTargets first, so an offline or unknown ID in the
// list drops out here rather than becoming a target nobody can see.
// An empty list means no explicit set was given, not "nothing".
func filterToAgents(agents []store.AgentRecord, ids []string) []store.AgentRecord {
	if len(ids) == 0 {
		return agents
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := agents[:0:0]
	for _, a := range agents {
		if want[a.AgentID] {
			out = append(out, a)
		}
	}
	return out
}

func describePatchTarget(os, site, agentID, vulnID string) string {
	if agentID != "" {
		return "agent:" + agentID
	}
	if vulnID != "" {
		return "cve:" + vulnID
	}
	var parts []string
	if os != "" {
		parts = append(parts, "os="+os)
	}
	if site != "" {
		parts = append(parts, "site="+site)
	}
	if len(parts) == 0 {
		return "all agents"
	}
	return strings.Join(parts, ", ")
}

// deployPatchesToAgents fires the apply_patches command at every given
// agent concurrently (bounded — same pattern as netscan.go's subnet
// sweep) and reports which accepted the job vs. which didn't respond or
// rejected it. Each command's reply only confirms the job started (see
// proto.AgentCommand's doc comment), not that patching finished.
// patchRestart is how a patch job restarts the endpoint once the updates
// installed: Mode "" (no restart), "if_required" or "always", after
// WarnMinutes of the operating system's own countdown.
type patchRestart struct {
	Mode        string `json:"restart_mode"`
	WarnMinutes int    `json:"restart_warn_minutes"`
}

// patchRestartAgentVersion is the first agent that acts on a restart.
const patchRestartAgentVersion = "0.57.2"

// unsupportedReason refuses a restart an agent would ignore: older agents
// drop the field and install without restarting, which is worse than
// saying so.
func (r patchRestart) unsupportedReason(a store.AgentRecord) string {
	if r.Mode == "" || !versionIsNewer(patchRestartAgentVersion, a.AgentVersion) {
		return ""
	}
	return fmt.Sprintf("agent %s cannot restart after patching (needs %s or newer); update the agent, or apply without a restart", a.AgentVersion, patchRestartAgentVersion)
}

// clean keeps a restart choice to what the agent understands.
func (r patchRestart) clean() (patchRestart, error) {
	switch r.Mode {
	case "", "none":
		return patchRestart{}, nil
	case "if_required", "always":
	default:
		return r, fmt.Errorf("restart_mode must be none, if_required or always")
	}
	if r.WarnMinutes < 1 {
		r.WarnMinutes = 1
	}
	if r.WarnMinutes > 240 {
		return r, fmt.Errorf("restart warning must be 1–240 minutes")
	}
	return r, nil
}

// only, when not nil, narrows each endpoint's job to the packages named
// for it (patch_only.go); an endpoint it names nothing for is not patched.
func (s *Server) deployPatchesToAgents(ctx context.Context, agents []store.AgentRecord, requestedBy, runID string, overrideWindows bool, restart patchRestart, only map[string][]string) (started []string, failed map[string]string) {
	failed = map[string]string{}
	if len(agents) == 0 {
		return started, failed
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	now := time.Now()
	// One patch job per endpoint at a time: a second click, or a bulk run
	// overlapping a single one, would start the same updates twice.
	open, err := s.store.OpenPatchJobs(ctx)
	if err != nil {
		s.logger.Warn("list open patch jobs", "error", err)
	}

	for _, a := range agents {
		wg.Add(1)
		go func(a store.AgentRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Recorded per agent so a device's own history shows the bulk
			// job that touched it, not just the fleet-level run. It is
			// opened *before* dispatch because its ID has to travel with
			// the command for the agent to report against it.
			actionID := idgen.New("act-")
			action := store.AgentAction{
				ID: actionID, RunID: runID, AgentID: a.AgentID, Kind: "patch_apply",
				Summary: "Apply pending patches (bulk deployment)", RequestedBy: requestedBy,
			}
			var pkgs []string
			if only != nil {
				pkgs = only[a.AgentID]
				if len(pkgs) == 0 {
					mu.Lock()
					failed[a.AgentID] = "no affected package was named for this endpoint"
					mu.Unlock()
					return
				}
				action.Summary = "Update " + strings.Join(pkgs, ", ")
			}
			// An endpoint whose maintenance window is closed is not
			// skipped but held: the action opens as "waiting" with the
			// reason, and patchWaitLoop dispatches it when the window
			// opens (or expires it after a day).
			if j, busy := open[a.AgentID]; busy {
				mu.Lock()
				failed[a.AgentID] = fmt.Sprintf("already patching (%s, began %s ago); wait for that job to finish",
					j.Status, shortAgo(j.StartedAt))
				mu.Unlock()
				return
			}
			// Refused before any hold, so an outdated agent hears "no"
			// now rather than when its window opens hours later.
			if why := restart.unsupportedReason(a); why != "" {
				if err := s.store.StartAgentAction(ctx, action); err == nil {
					_ = s.store.FinishAgentAction(ctx, a.AgentID, actionID, "failed", why)
				}
				mu.Lock()
				failed[a.AgentID] = why
				mu.Unlock()
				return
			}
			if !overrideWindows {
				if v := s.windowCheck(ctx, a.AgentID, "patch", now); !v.Allowed {
					if err := s.store.StartAgentActionWithStatus(ctx, action, "waiting", v.Reason); err != nil {
						s.logger.Warn("record waiting patch action failed", "agent_id", a.AgentID, "error", err)
					}
					// The held job keeps its restart choice and its package
					// list for when the window opens and patchWaitLoop
					// dispatches it.
					if restart.Mode != "" {
						if err := s.store.SetActionRestart(ctx, actionID, restart.Mode, restart.WarnMinutes); err != nil {
							s.logger.Warn("record patch restart choice failed", "agent_id", a.AgentID, "error", err)
						}
					}
					if pkgs != nil {
						if err := s.store.SetActionPatchOnly(ctx, actionID, pkgs); err != nil {
							// Unrecorded, the held job would later patch
							// everything; end it instead.
							_ = s.store.FinishAgentAction(ctx, a.AgentID, actionID, "failed", "could not record which packages to update: "+err.Error())
							mu.Lock()
							failed[a.AgentID] = "could not record which packages to update"
							mu.Unlock()
							return
						}
					}
					mu.Lock()
					started = append(started, a.AgentID)
					mu.Unlock()
					return
				}
			}
			if err := s.store.StartAgentAction(ctx, action); err != nil {
				s.logger.Warn("record bulk patch action failed", "agent_id", a.AgentID, "error", err)
			}
			// Only a dispatch failure is terminal here. An agent that took
			// the job leaves its action open until it publishes an
			// AgentActionResult, so the deployment reflects what the
			// devices are actually doing rather than reporting success the
			// moment the command was accepted.
			if restart.Mode != "" {
				if err := s.store.SetActionRestart(ctx, actionID, restart.Mode, restart.WarnMinutes); err != nil {
					s.logger.Warn("record patch restart choice failed", "agent_id", a.AgentID, "error", err)
				}
			}
			if pkgs != nil {
				if err := s.store.SetActionPatchOnly(ctx, actionID, pkgs); err != nil {
					s.logger.Warn("record patch package list failed", "agent_id", a.AgentID, "error", err)
				}
			}
			ok, reason := s.dispatchPatchApply(ctx, a, runID, actionID, restart, pkgs)
			mu.Lock()
			if ok {
				started = append(started, a.AgentID)
			} else {
				failed[a.AgentID] = reason
			}
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	return started, failed
}

// computeNextRun returns the next UTC time a daily/weekly schedule should
// fire, strictly after `from` (last-run time, or the schedule's creation
// time for its first occurrence). Returns nil for "once" — those don't
// repeat, so there is no next run once they've fired.
func computeNextRun(kind, timeOfDay string, weekday *int, from time.Time) (*time.Time, error) {
	from = from.UTC()
	switch kind {
	case "once":
		return nil, nil
	case "daily":
		hh, mm, err := parseHHMM(timeOfDay)
		if err != nil {
			return nil, err
		}
		next := time.Date(from.Year(), from.Month(), from.Day(), hh, mm, 0, 0, time.UTC)
		if !next.After(from) {
			next = next.AddDate(0, 0, 1)
		}
		return &next, nil
	case "weekly":
		if weekday == nil || *weekday < 0 || *weekday > 6 {
			return nil, fmt.Errorf("weekly schedule needs a weekday (0=Sunday..6=Saturday)")
		}
		hh, mm, err := parseHHMM(timeOfDay)
		if err != nil {
			return nil, err
		}
		next := time.Date(from.Year(), from.Month(), from.Day(), hh, mm, 0, 0, time.UTC)
		for int(next.Weekday()) != *weekday || !next.After(from) {
			next = next.AddDate(0, 0, 1)
		}
		return &next, nil
	default:
		return nil, fmt.Errorf("unknown schedule kind: %q (want once, daily, or weekly)", kind)
	}
}

func parseHHMM(s string) (hour, minute int, err error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, 0, fmt.Errorf("time_of_day must be HH:MM (24-hour, UTC): %w", err)
	}
	return t.Hour(), t.Minute(), nil
}

// patchSchedulerLoop polls for due schedules once a minute and fires them.
// A minute of slop on "daily at 03:00" is a fine tradeoff for not needing
// a precise timer-per-schedule — patch deployment windows are never
// second-sensitive.
func (s *Server) patchSchedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDuePatchSchedules(ctx)
		}
	}
}

func (s *Server) runDuePatchSchedules(ctx context.Context) {
	due, err := s.store.DuePatchSchedules(ctx, time.Now().UTC())
	if err != nil {
		s.logger.Warn("check due patch schedules failed", "error", err)
		return
	}
	for _, sched := range due {
		agents, err := s.resolvePatchTargets(ctx, sched.TargetOS, sched.TargetSite, sched.TargetAgent, sched.TargetVulnID)
		if err != nil {
			s.logger.Warn("resolve patch schedule targets failed", "schedule", sched.Name, "error", err)
			continue
		}
		targetDesc := describePatchTarget(sched.TargetOS, sched.TargetSite, sched.TargetAgent, sched.TargetVulnID)
		if len(sched.TargetAgents) > 0 {
			agents = filterToAgents(agents, sched.TargetAgents)
			targetDesc = fmt.Sprintf("%d selected endpoint(s)", len(sched.TargetAgents))
		}
		// Access control at every firing, as the deploy scheduler does: the
		// run acts with its author's management rights, which may have
		// shrunk since the schedule was saved, and inside the patches
		// action group, which binds everyone. A schedule whose author is
		// gone or inactive is paused rather than run under nobody.
		agents, paused := s.narrowPatchScheduleTargets(ctx, sched, agents)
		if paused {
			continue
		}
		if len(agents) == 0 {
			// Nothing in reach this time; the schedule keeps its cadence
			// rather than being retried every minute.
			if next, err := computeNextRun(sched.Kind, sched.TimeOfDay, sched.Weekday, time.Now().UTC()); err == nil {
				if err := s.store.MarkPatchScheduleRun(ctx, sched.ID, time.Now().UTC(), next); err != nil {
					s.logger.Warn("mark patch schedule run failed", "schedule", sched.Name, "error", err)
				}
			}
			s.logger.Info("patch schedule fired with nothing in its author's reach", "schedule", sched.Name, "target", targetDesc)
			continue
		}
		runID := idgen.New("run-")
		if err := s.store.RecordPatchJobRun(ctx, store.PatchJobRun{
			ID: runID, ScheduleID: sched.ID, ScheduleName: sched.Name,
			TargetDesc: targetDesc, AgentCount: len(agents), TriggeredBy: "scheduler",
		}); err != nil {
			s.logger.Warn("record patch job run failed", "schedule", sched.Name, "error", err)
		}
		started, failed := s.deployPatchesToAgents(ctx, agents, "scheduler", runID, false, patchRestart{}, nil)
		next, err := computeNextRun(sched.Kind, sched.TimeOfDay, sched.Weekday, time.Now().UTC())
		if err != nil {
			s.logger.Warn("compute next patch schedule run failed", "schedule", sched.Name, "error", err)
			next = nil
		}
		if err := s.store.MarkPatchScheduleRun(ctx, sched.ID, time.Now().UTC(), next); err != nil {
			s.logger.Warn("mark patch schedule run failed", "schedule", sched.Name, "error", err)
		}
		s.logger.Info("patch schedule fired", "schedule", sched.Name, "target", targetDesc, "started", len(started), "failed", len(failed))
	}
}

// narrowPatchScheduleTargets applies the schedule author's current reach
// and the patches action group to a firing, returning what may still be
// patched. paused is true when the schedule was disabled because its
// author no longer exists or is inactive, with the reason recorded.
func (s *Server) narrowPatchScheduleTargets(ctx context.Context, sched store.PatchSchedule, agents []store.AgentRecord) (kept []store.AgentRecord, paused bool) {
	pctx, ok := s.endpointActionPrincipal(ctx, sched.CreatedBy)
	if !ok {
		s.logger.Warn("patch schedule paused: its author no longer exists or is inactive",
			"schedule", sched.Name, "created_by", sched.CreatedBy)
		if err := s.store.SetPatchScheduleEnabled(ctx, sched.ID, false, nil); err != nil {
			s.logger.Warn("pausing patch schedule failed", "schedule", sched.Name, "error", err)
		}
		s.audit(ctx, auditEvent{Action: "patch_schedule.paused", Actor: "system", Target: sched.Name, Severity: "warning",
			Detail: map[string]any{"id": sched.ID, "created_by": sched.CreatedBy,
				"reason": "the schedule's author no longer exists or is inactive; save it again under an active account"}})
		return nil, true
	}
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.AgentID)
	}
	allowed, dropped, err := s.narrowTargets(pctx, "patches", ids)
	if err != nil {
		// Fail closed: a run whose rights could not be checked does not run.
		s.logger.Warn("checking patch schedule targets failed; not running", "schedule", sched.Name, "error", err)
		return nil, false
	}
	if dropped == 0 {
		return agents, false
	}
	keep := make(map[string]bool, len(allowed))
	for _, id := range allowed {
		keep[id] = true
	}
	narrowed := agents[:0:0]
	for _, a := range agents {
		if keep[a.AgentID] {
			narrowed = append(narrowed, a)
		}
	}
	s.logger.Info("patch schedule targets narrowed by access control", "schedule", sched.Name,
		"created_by", sched.CreatedBy, "dropped", dropped, "remaining", len(narrowed))
	s.audit(ctx, auditEvent{Action: "patch_schedule.narrowed", Actor: "system", Target: sched.Name, Severity: "notice",
		Detail: map[string]any{"id": sched.ID, "created_by": sched.CreatedBy, "dropped": dropped, "remaining": len(narrowed)}})
	return narrowed, false
}
