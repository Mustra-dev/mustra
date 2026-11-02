package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Scheduled actions: run a package on a cadence.
//
// Patch schedules already existed, which quietly said recurring work was a
// patching concern. It is not — restarting a service every Sunday, clearing
// a cache nightly, re-running a compliance script weekly are the same shape,
// and doing any of them meant somebody remembering to click Deploy.
//
// Firing one goes through exactly the same path as an interactive deploy:
// applicability is evaluated fresh, parameters are resolved and validated,
// files are staged, and the result is a deployment like any other. A
// schedule that took its own shortcut would be a second code path with
// second bugs, and the one running unattended at 3am is the worst place to
// discover them.

// listScheduledActionsResponse is what GET /api/schedules answers.
type listScheduledActionsResponse struct {
	Schedules []store.ScheduledAction `json:"schedules"`
}

func (s *Server) handleListScheduledActions(w http.ResponseWriter, r *http.Request) {
	acts, err := s.store.ListScheduledActions(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if acts == nil {
		acts = []store.ScheduledAction{}
	}
	writeJSONResponse(w, listScheduledActionsResponse{Schedules: acts})
}

func (s *Server) handleUpsertScheduledAction(w http.ResponseWriter, r *http.Request) {
	var body store.ScheduledAction
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		http.Error(w, "a name is required", http.StatusBadRequest)
		return
	}
	pkg, err := s.store.GetSoftwarePackage(r.Context(), body.PackageID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pkg == nil {
		http.Error(w, "no such package", http.StatusNotFound)
		return
	}
	if pkg.DeployRevision != "" && !body.FollowLatest && body.RevisionID == "" {
		body.RevisionID = pkg.DeployRevision
	}
	if pkg.Kind == store.KindAction && pkg.DeployRevision != "" {
		body.Operation = "run"
	}
	switch body.Operation {
	case "install", "update", "remove", "run":
	default:
		body.Operation = "install"
	}
	if pkg.DeployRevision != "" {
		revisionID := body.RevisionID
		if body.FollowLatest {
			revisionID = pkg.DeployRevision
		}
		rev, e := s.store.GetDeployRevision(r.Context(), revisionID)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		if rev == nil || !rev.Published || rev.Retired || rev.PackageID != pkg.ID {
			http.Error(w, "select a published revision of this package", 400)
			return
		}
		if e = validateRevisionInputs(rev.Definition, body.Operation, body.TargetOS, body.Parameters); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}

	}
	switch body.Kind {
	case "once", "daily", "weekly":
	default:
		body.Kind = "daily"
	}
	if body.TimeOfDay == "" {
		body.TimeOfDay = "03:00"
	}
	if body.ExpireSeconds < 0 || body.ExpireSeconds > 31536000 {
		http.Error(w, "expiry must be 0–31536000 seconds", http.StatusBadRequest)
		return
	}
	if !s.requireOverride(w, r, body.OverrideWindows) {
		return
	}
	if body.NotifyMessageID != "" {
		if m, e := s.store.GetEUNMessage(r.Context(), body.NotifyMessageID); e != nil || m == nil {
			http.Error(w, "no such end-user notification", http.StatusBadRequest)
			return
		}
	}
	body.AgentIDs, body.GroupIDs = cleanIDs(body.AgentIDs), cleanIDs(body.GroupIDs)
	if len(body.AgentIDs) > 5000 || len(body.GroupIDs) > 200 {
		http.Error(w, "too many targets for one schedule", http.StatusBadRequest)
		return
	}

	// Validated now rather than at 3am. A parameterised package whose values
	// are wrong should fail while somebody is looking at the form, not
	// silently every night until someone notices.
	if len(pkg.Parameters) > 0 {
		if _, perr := resolveParameters(pkg.Parameters, body.Parameters); perr != nil {
			http.Error(w, perr.Error(), http.StatusBadRequest)
			return
		}
	}

	next, err := computeNextRun(body.Kind, body.TimeOfDay, body.Weekday, time.Now().UTC())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Kind == "once" {
		if body.RunAt == nil {
			http.Error(w, "a one-off schedule needs a date and time", http.StatusBadRequest)
			return
		}
		next = body.RunAt
	}
	body.NextRunAt = next

	if id := r.PathValue("id"); id != "" {
		body.ID = id
	}
	if body.ID == "" {
		body.ID = idgen.New("sch-")
		body.CreatedBy = auth.CurrentUser(r.Context()).Username
	}

	out, err := s.store.UpsertScheduledAction(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "schedule.save", Actor: auth.CurrentUser(r.Context()).Username,
		Target: out.Name, Severity: "notice",
		Detail: map[string]any{"package": pkg.Name, "kind": out.Kind, "next": out.NextRunAt},
	})
	writeJSONResponse(w, out)
}

func (s *Server) handleDeleteScheduledAction(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteScheduledAction(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// runScheduledActionNowResponse is what POST /api/schedules/{id}/run
// answers.
type runScheduledActionNowResponse struct {
	RunID   string `json:"run_id"`
	Targets int    `json:"targets"`
}

// handleRunScheduledActionNow fires a schedule immediately without touching
// its cadence — the only honest way to find out whether it does what its
// author thinks before waiting a week to see.
func (s *Server) handleRunScheduledActionNow(w http.ResponseWriter, r *http.Request) {
	act, err := s.store.GetScheduledAction(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if act == nil {
		http.Error(w, "no such schedule", http.StatusNotFound)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	runID, targets, ferr := s.fireScheduledAction(context.WithoutCancel(r.Context()), *act, who)
	if ferr != nil {
		http.Error(w, ferr.Error(), http.StatusBadRequest)
		return
	}
	writeJSONResponse(w, runScheduledActionNowResponse{RunID: runID, Targets: targets})
}

// fireScheduledAction resolves the schedule into a real deployment. Shared
// by the timer and the "run now" button so there is exactly one description
// of what firing means.
func (s *Server) fireScheduledAction(ctx context.Context, act store.ScheduledAction, who string) (string, int, error) {
	pkg, err := s.store.GetSoftwarePackage(ctx, act.PackageID)
	if err != nil {
		return "", 0, err
	}
	if pkg == nil {
		return "", 0, errPackageGone
	}

	if pkg.DeployRevision != "" {
		id := pkg.DeployRevision
		if !act.FollowLatest && act.RevisionID != "" {
			id = act.RevisionID
		}
		rev, e := s.store.GetDeployRevision(ctx, id)
		if e != nil {
			return "", 0, e
		}
		if rev == nil || !rev.Published || rev.Retired || rev.PackageID != pkg.ID {
			return "", 0, scheduleError("Selected package version is unavailable or retired; update the schedule reference")
		}
	}
	pkg.DeployParameters = act.Parameters
	if pkg.DeployRevision != "" && !act.FollowLatest && act.RevisionID != "" {
		rev, e := s.store.GetDeployRevision(ctx, act.RevisionID)
		if e != nil {
			return "", 0, e
		}
		if rev == nil || !rev.Published || rev.Retired || rev.PackageID != pkg.ID {
			return "", 0, errPackageGone
		}
		pkg.DeployRevision = rev.ID
		pkg.DeployDefinition = &rev.Definition
	}
	// Parameters resolved at fire time, not at save time: a package's
	// declared defaults may have changed since, and the schedule should run
	// what the package means today.
	if len(pkg.Parameters) > 0 {
		values, perr := resolveParameters(pkg.Parameters, act.Parameters)
		if perr != nil {
			return "", 0, perr
		}
		substituted := make(map[string]store.SoftwareOps, len(pkg.Commands))
		for os, ops := range pkg.Commands {
			substituted[os] = store.SoftwareOps{
				Install: substituteParameters(ops.Install, values),
				Update:  substituteParameters(ops.Update, values),
				Remove:  substituteParameters(ops.Remove, values),
			}
		}
		pkg.Commands = substituted
	}

	rows, _, err := s.applicability(ctx, *pkg)
	if err != nil {
		return "", 0, err
	}
	// Hand-picked endpoints and groups (groups resolved now, at firing, so
	// membership changes since the schedule was saved are followed).
	var picked map[string]bool
	if len(act.AgentIDs) > 0 || len(act.GroupIDs) > 0 {
		picked = map[string]bool{}
		for _, id := range act.AgentIDs {
			picked[id] = true
		}
		if len(act.GroupIDs) > 0 {
			members, gerr := s.groupMembers(ctx, act.GroupIDs)
			if gerr != nil {
				return "", 0, gerr
			}
			for _, id := range members {
				picked[id] = true
			}
		}
	}
	var targets []applicabilityRow
	for _, row := range rows {
		if !row.Online {
			continue
		}
		if picked != nil && !picked[row.AgentID] {
			continue
		}
		if act.TargetOS != "" && row.OS != act.TargetOS {
			continue
		}
		if act.TargetSite != "" && row.Site != act.TargetSite {
			continue
		}
		if act.TargetAgent != "" && row.AgentID != act.TargetAgent {
			continue
		}
		if !operationApplies(*pkg, act.Operation, row.State) {
			continue
		}
		targets = append(targets, row)
	}
	if len(targets) == 0 {
		return "", 0, errNoTargets
	}
	// Access control at every firing, not only when the schedule was saved:
	// an unattended run acts with its author's management rights and content
	// sets (which may have shrunk since), and inside the deploy action group,
	// which binds everyone. A schedule whose author is gone does not run.
	pctx := ctx
	if auth.CurrentUser(ctx) == nil {
		var ok bool
		if pctx, ok = s.endpointActionPrincipal(ctx, act.CreatedBy); !ok {
			return "", 0, scheduleError("The schedule's author no longer exists or is inactive; save it again under an active account")
		}
	}
	if allowed, cerr := s.contentAllowed(pctx, "packages", pkg.ID); cerr != nil {
		return "", 0, cerr
	} else if !allowed {
		return "", 0, scheduleError("The package is no longer in a content set the schedule's author holds")
	}
	ids := make([]string, 0, len(targets))
	for _, t := range targets {
		ids = append(ids, t.AgentID)
	}
	kept, dropped, err := s.narrowTargets(pctx, "deploy", ids)
	if err != nil {
		return "", 0, err
	}
	if dropped > 0 {
		keep := map[string]bool{}
		for _, id := range kept {
			keep[id] = true
		}
		narrowed := targets[:0:0]
		for _, t := range targets {
			if keep[t.AgentID] {
				narrowed = append(narrowed, t)
			}
		}
		targets = narrowed
		s.logger.Info("scheduled action targets narrowed by access control", "schedule", act.Name, "dropped", dropped)
		if len(targets) == 0 {
			return "", 0, errNoTargets
		}
	}

	if pkg.DeployRevision != "" {
		rev, e := s.store.GetDeployRevision(ctx, pkg.DeployRevision)
		if e != nil {
			return "", 0, e
		}
		if rev == nil || !rev.Published || rev.Retired || rev.PackageID != pkg.ID {
			return "", 0, errPackageGone
		}
		agents, e := s.store.ListAgents(ctx, s.staleAfter())
		if e != nil {
			return "", 0, e
		}
		runID := idgen.New("run-")
		jobs := []proto.DeployJob{}
		for _, target := range targets {
			for _, agent := range agents {
				if target.AgentID != agent.AgentID {
					continue
				}
				job, e := s.planDeploy(ctx, *pkg, *rev, agent, deployRequest{Operation: act.Operation, Parameters: act.Parameters,
					AllowReboot: act.AllowReboot, ForceRemove: act.ForceRemove, ExpireSeconds: act.ExpireSeconds, OverrideWindows: act.OverrideWindows})
				if e != nil {
					return "", 0, e
				}
				job.RunID = runID
				jobs = append(jobs, job)
			}
		}
		e = s.store.CreateDeployRun(ctx, store.PatchJobRun{ID: runID, TargetDesc: describeScheduleTarget(act), ScheduleName: act.Name, TriggeredBy: who, NotifyOnFinish: act.NotifyOnFinish}, jobs)
		if e == nil && act.NotifyMessageID != "" {
			ids := make([]string, 0, len(jobs))
			for _, j := range jobs {
				ids = append(ids, j.AgentID)
			}
			s.sendDeployNotice(ctx, act.NotifyMessageID, ids, who, act.Name)
		}
		return runID, len(jobs), e
	}
	runID := idgen.New("run-")
	if err := s.store.RecordPatchJobRun(ctx, store.PatchJobRun{
		ID: runID, TargetDesc: describeScheduleTarget(act), AgentCount: len(targets),
		ScheduleName: act.Name, TriggeredBy: who,
	}); err != nil {
		s.logger.Warn("record scheduled action run failed", "error", err)
	}
	go s.runSoftwareDeployment(ctx, *pkg, act.Operation, targets, runID, who, false)
	return runID, len(targets), nil
}

func describeScheduleTarget(a store.ScheduledAction) string {
	parts := []string{}
	if a.TargetOS != "" {
		parts = append(parts, "os="+a.TargetOS)
	}
	if a.TargetSite != "" {
		parts = append(parts, "site="+a.TargetSite)
	}
	if a.TargetAgent != "" {
		parts = append(parts, "device")
	}
	if n := len(a.AgentIDs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d endpoint(s)", n))
	}
	if n := len(a.GroupIDs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d group(s)", n))
	}
	if len(parts) == 0 {
		return "scheduled: all applicable endpoints"
	}
	return "scheduled: " + strings.Join(parts, ", ")
}

// scheduledActionLoop fires due schedules once a minute, mirroring the patch
// scheduler rather than inventing a second cadence.
func (s *Server) scheduledActionLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDueScheduledActions(ctx)
		}
	}
}

func (s *Server) runDueScheduledActions(ctx context.Context) {
	now := time.Now().UTC()
	due, err := s.store.DueScheduledActions(ctx, now)
	if err != nil {
		s.logger.Warn("could not load due scheduled actions", "error", err)
		return
	}
	for _, act := range due {
		// The next run is written BEFORE firing. If the deployment or the
		// process dies midway, the schedule has still moved on — the
		// alternative is a schedule that re-fires every minute forever
		// because it never got to record that it ran.
		var next *time.Time
		if act.Kind != "once" {
			if n, cerr := computeNextRun(act.Kind, act.TimeOfDay, act.Weekday, now); cerr == nil {
				next = n
			}
		}
		if err := s.store.MarkScheduledActionRun(ctx, act.ID, now, next); err != nil {
			s.logger.Warn("could not advance schedule", "id", act.ID, "error", err)
			continue
		}

		runID, targets, ferr := s.fireScheduledAction(ctx, act, "schedule: "+act.Name)
		if ferr != nil {
			// A schedule that matched nothing is normal and quiet; anything
			// else is worth telling somebody, since nobody is watching.
			if ferr == errNoTargets {
				s.logger.Info("scheduled action matched no endpoints", "schedule", act.Name)
				continue
			}
			s.logger.Error("scheduled action failed to fire", "schedule", act.Name, "error", ferr)
			s.notify(ctx, "warning", "Schedule", "Scheduled action could not run",
				act.Name+": "+ferr.Error(), "/software#schedules")
			continue
		}
		s.logger.Info("scheduled action fired", "schedule", act.Name, "run_id", runID, "targets", targets)
	}
}

type scheduleError string

func (e scheduleError) Error() string { return string(e) }

const (
	errNoTargets   = scheduleError("no online endpoint currently matches this schedule")
	errPackageGone = scheduleError("the package this schedule refers to no longer exists")
)

// cleanIDs trims, drops empties and de-duplicates a list of IDs.
func cleanIDs(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range in {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
