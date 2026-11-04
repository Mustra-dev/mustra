package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

type deployRequest struct {
	PlanID        string            `json:"plan_id,omitempty"`
	PackageID     string            `json:"package_id" api:"required"`
	RevisionID    string            `json:"revision_id"`
	Operation     string            `json:"operation" api:"required"`
	AgentIDs      []string          `json:"agent_ids"`
	Parameters    map[string]string `json:"parameters"`
	AllowReboot   bool              `json:"allow_reboot"`
	ForceRemove   bool              `json:"force_remove"`
	ExpireSeconds int               `json:"expire_seconds"`
	// OverrideWindows dispatches even when the endpoint's maintenance
	// windows are closed. Needs deploy.override_windows; see maintenance_api.go.
	OverrideWindows bool `json:"override_windows,omitempty"`
	// GroupIDs adds every current member of these computer groups to the
	// targets, alongside AgentIDs; they become explicit targets like any
	// hand-picked endpoint.
	GroupIDs []string `json:"group_ids,omitempty"`
	// NotifyMessageID is an end-user notification (eun) shown on each
	// online target as the run starts.
	NotifyMessageID string `json:"notify_message_id,omitempty"`
	// NotifyOnFinish raises one console notification when the run's last
	// job reaches a final state.
	NotifyOnFinish bool `json:"notify_on_finish,omitempty"`
}

// resolveDeployGroups folds req.GroupIDs into req.AgentIDs. A group that
// resolves to nobody contributes nobody: picking only empty groups is
// refused rather than read as "no targets given", which would mean the
// whole fleet.
func (s *Server) resolveDeployGroups(ctx context.Context, req *deployRequest) error {
	if len(req.GroupIDs) == 0 {
		return nil
	}
	members, e := s.groupMembers(ctx, req.GroupIDs)
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	ids := []string{}
	for _, id := range append(append([]string{}, req.AgentIDs...), members...) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return errNoGroupMembers
	}
	req.AgentIDs = ids
	return nil
}

var errNoGroupMembers = errors.New("the selected computer groups have no members")

// sendDeployNotice shows an end-user notification on the online endpoints
// a run targets, as its own recorded run, the way Send does on the
// notifications page. Best effort: a notice that cannot be sent never stops
// the deployment it announces.
func (s *Server) sendDeployNotice(ctx context.Context, msgID string, agentIDs []string, who, what string) {
	if msgID == "" || len(agentIDs) == 0 {
		return
	}
	msg, e := s.store.GetEUNMessage(ctx, msgID)
	if e != nil || msg == nil {
		s.logger.Warn("deploy notice not sent", "message", msgID, "error", e)
		return
	}
	agents, e := s.store.ListAgents(ctx, s.staleAfter())
	if e != nil {
		s.logger.Warn("deploy notice not sent", "error", e)
		return
	}
	want := map[string]bool{}
	for _, id := range agentIDs {
		want[id] = true
	}
	var targets []store.AgentRecord
	for _, a := range agents {
		if want[a.AgentID] && a.Online {
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		return
	}
	runID := idgen.New("run-")
	if e := s.store.RecordPatchJobRun(ctx, store.PatchJobRun{ID: runID, TargetDesc: "end-user notification for " + what + ": " + msg.Name, AgentCount: len(targets), ScheduleName: msg.Title, TriggeredBy: who}); e != nil {
		s.logger.Warn("record notification run failed", "error", e)
	}
	s.audit(ctx, auditEvent{Action: "eun.send", Actor: who, Target: msg.Name, Severity: "notice", Detail: map[string]any{"run_id": runID, "endpoints": len(targets), "kind": msg.Kind, "for": what}})
	go s.deliverEUN(context.WithoutCancel(ctx), *msg, targets, runID, who)
}

// notifyRunFinished raises the console notification a run asked for once
// its last job has finished. ClaimFinishedRun makes it exactly once.
func (s *Server) notifyRunFinished(ctx context.Context, runID string) {
	if runID == "" {
		return
	}
	s.announceRunCompleted(ctx, runID)
	run, counts, e := s.store.ClaimFinishedRun(ctx, runID)
	if e != nil {
		s.logger.Warn("finished-run notification failed", "run", runID, "error", e)
	}
	if run == nil {
		return
	}
	ok := counts["succeeded"] + counts["skipped"]
	total := 0
	for _, n := range counts {
		total += n
	}
	parts := []string{fmt.Sprintf("%d of %d succeeded", ok, total)}
	for _, st := range []string{"failed", "timed_out", "expired", "cancelled", "interrupted", "unsupported"} {
		if counts[st] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[st], strings.ReplaceAll(st, "_", " ")))
		}
	}
	severity := "info"
	if ok < total {
		severity = "warning"
	}
	s.notify(ctx, severity, "deploy", "Deployment finished: "+run.ScheduleName, strings.Join(parts, " · "), "/software?run="+url.QueryEscape(run.ID)+"#deployments")
}

func (s *Server) planDeploy(ctx context.Context, pkg store.SoftwarePackage, rev proto.DeployRevision, target store.AgentRecord, req deployRequest) (proto.DeployJob, error) {
	if rev.Retired {
		return proto.DeployJob{}, fmt.Errorf("revision %s is retired; update its reference to an active version", rev.Label)
	}
	settings, e := s.deploySettings(ctx)
	if e != nil {
		return proto.DeployJob{}, e
	}
	job := proto.DeployJob{ID: idgen.New("act-"), AgentID: target.AgentID, PackageID: pkg.ID, RevisionID: rev.ID, Operation: req.Operation, Settings: settings, AllowReboot: req.AllowReboot, ForceRemove: req.ForceRemove, OverrideWindows: req.OverrideWindows, CreatedAt: time.Now().UTC()}
	expiry := req.ExpireSeconds
	if expiry == 0 {
		expiry = pkg.ExpireSeconds
	}
	if expiry == 0 && req.Operation == "run" {
		expiry = 86400
	}
	if expiry > 0 {
		job.ExpiresAt = time.Now().Add(time.Duration(expiry) * time.Second)
	}
	visited := map[string]string{}
	resolvedInputs := map[string]string{}
	visiting := map[string]bool{}
	var resolve func(store.SoftwarePackage, proto.DeployRevision, string, map[string]string) error
	resolve = func(current store.SoftwarePackage, revision proto.DeployRevision, operation string, inputs map[string]string) error {
		raw, err := json.Marshal(revision.Definition)
		if err != nil {
			return err
		}
		var definition proto.DeployDefinition
		if err = json.Unmarshal(raw, &definition); err != nil {
			return err
		}
		revision.Definition = definition
		current.DeployDefinition = &definition
		if revision.Retired {
			return fmt.Errorf("revision %s is retired", revision.Label)
		}

		if visiting[current.ID] {
			return fmt.Errorf("dependency cycle at %s", current.Name)
		}
		if prev, ok := visited[current.ID]; ok {
			encodedInputs, _ := json.Marshal(inputs)
			if prev != revision.ID || resolvedInputs[current.ID] != string(encodedInputs) {
				return fmt.Errorf("conflicting dependency revisions for %s", current.Name)
			}
			return nil
		}
		if len(visited)+len(visiting) > 64 {
			return fmt.Errorf("dependency graph exceeds 64 packages")
		}
		visiting[current.ID] = true
		defer delete(visiting, current.ID)
		if !current.Enabled {
			return fmt.Errorf("package %s is disabled", current.Name)
		}
		rows, _, e := s.applicability(ctx, current)
		if e != nil {
			return e
		}
		allowed := false
		for _, row := range rows {
			if row.AgentID == target.AgentID && row.State != stateNotApplicable {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%s is outside package scope or applicability", current.Name)
		}
		variant, e := deploy.SelectVariant(revision.Definition, target.OS, target.Arch, target.Platform, target.PlatformVersion)
		if e != nil {
			return e
		}
		action, ok := variant.Actions[operation]
		if !ok {
			return fmt.Errorf("%s has no %s action on selected platform", current.Name, operation)
		}
		if definition.Kind == "action" {
			action.Files = append(append([]proto.DeployFile{}, definition.Files...), action.Files...)
			action.RequireFiles = len(action.Files) > 0
			selected := []proto.DeployFile{}
			ids := []string{}
			for _, f := range action.Files {
				if len(f.OS) > 0 && !slices.Contains(f.OS, target.OS) || len(f.Arch) > 0 && !slices.Contains(f.Arch, target.Arch) {
					continue
				}
				selected = append(selected, f)
				ids = append(ids, f.ID)
			}
			action.Files = selected
			action.Steps = append([]proto.DeployStep{}, action.Steps...)
			if len(action.Steps) != 1 {
				return fmt.Errorf("action must contain one command")
			}
			action.Steps[0].Files = ids
			variant.Actions = map[string]proto.DeployAction{"run": action}
		}
		defs := deploy.MergeParameters(revision.Definition.Parameters, variant.Parameters, action.Parameters)
		values, e := deploy.Parameters(defs, inputs)
		if e != nil {
			return e
		}
		if operation == "remove" && !req.ForceRemove {
			parents, e := s.store.DeployDependents(ctx, target.AgentID, current.ID)
			if e != nil {
				return e
			}
			if len(parents) > 0 {
				return fmt.Errorf("%s is required by %s", current.Name, strings.Join(parents, ", "))
			}
		}
		for _, dependency := range action.Dependencies {
			child, e := s.store.GetSoftwarePackage(ctx, dependency.PackageID)
			if e != nil {
				return e
			}
			if child == nil {
				return fmt.Errorf("dependency package was deleted")
			}
			depRev, e := s.store.GetDeployRevision(ctx, dependency.RevisionID)
			if e != nil {
				return e
			}
			if depRev == nil || !depRev.Published || depRev.PackageID != child.ID {
				return fmt.Errorf("dependency revision is unavailable")
			}
			depVariant, e := deploy.SelectVariant(depRev.Definition, target.OS, target.Arch, target.Platform, target.PlatformVersion)
			if e != nil {
				return e
			}
			valid, e := deploy.VersionMatches(depVariant.Version, dependency.Version)
			if e != nil {
				return e
			}
			if !valid {
				return fmt.Errorf("dependency release does not satisfy version constraint")
			}
			depInputs, e := deploy.Bind(dependency.Parameters, values)
			if e != nil {
				return e
			}
			if e = resolve(*child, *depRev, "install", depInputs); e != nil {
				return e
			}
		}
		plan := proto.DeployPackagePlan{PackageID: current.ID, RevisionID: revision.ID, Name: current.Name, Operation: operation, Variant: *variant, Parameters: values, Files: map[string]proto.PackageFileRef{}}
		for _, def := range defs {
			if def.Secret {
				plan.Secrets = append(plan.Secrets, values[def.Name])
			}
		}
		base, e := s.agentPublicURLOrEmpty(ctx)
		if e != nil {
			return e
		}
		for _, file := range action.Files {
			if !action.RequireFiles {
				break
			}
			if len(file.OS) > 0 && !slices.Contains(file.OS, target.OS) || len(file.Arch) > 0 && !slices.Contains(file.Arch, target.Arch) {
				continue
			}
			ref := proto.PackageFileRef{Name: file.Name, SHA256: file.SHA256, Size: file.Size, URL: file.URL}
			if ref.URL == "" {
				stored, e := s.store.GetPackageFile(ctx, file.ID)
				if e != nil {
					return e
				}
				if stored == nil || stored.PackageID != current.ID || !strings.EqualFold(stored.SHA256, file.SHA256) {
					return fmt.Errorf("required library file %s is missing or changed", file.Name)
				}
				if base == "" {
					return fmt.Errorf("agent console URL is not configured")
				}
				ref.URL = strings.TrimRight(base, "/") + "/deploy-files/" + job.ID + "/" + file.ID + "?t=" + idgen.New("dl-")
			}
			if file.CredentialID != "" {
				return fmt.Errorf("authenticated direct files must be imported into the server library")
			}
			plan.Files[file.ID] = ref
		}
		// Materialize only this endpoint's Go artifacts. Published source and sensor
		// schemas stay pinned; signed URLs are delivery credentials, not revisions.
		plan.Variant.Actions = map[string]proto.DeployAction{operation: plan.Variant.Actions[operation]}
		single := proto.DeployDefinition{Version: proto.DeployVersion, Variants: []proto.DeployVariant{plan.Variant}}
		e = walkDeployChecks(&single, func(c *proto.DeployCheck, os string) error {
			if c.Sensor == nil {
				return nil
			}
			def, ok := c.Sensor.Definitions[os]
			if !ok {
				return fmt.Errorf("sensor has no platform definition")
			}
			if def.Platform.Language == "go" {
				sensor := store.CustomSensor{Commands: map[string]string{os: def.Command}, Platforms: map[string]proto.SensorPlatform{os: def.Platform}}
				artifact, e := s.goSensorArtifact(ctx, sensor, os, target.Arch)
				if e != nil {
					return e
				}
				bindDeployArtifact(artifact, job.ID, base)
				def.Artifact = artifact
			}
			c.Sensor.Definitions = map[string]proto.CustomSensorDef{os: def}
			return nil
		}, func(script *proto.DeployScript, os string) error {
			if script.Language != "go" {
				return nil
			}
			sensor := store.CustomSensor{Commands: map[string]string{os: script.Source}, Platforms: map[string]proto.SensorPlatform{os: {Language: "go"}}}
			artifact, e := s.goSensorArtifact(ctx, sensor, os, target.Arch)
			bindDeployArtifact(artifact, job.ID, base)
			script.Artifact = artifact
			return e
		})
		if e != nil {
			return e
		}
		plan.Variant = single.Variants[0]
		// Do not send another action's commands or files to the endpoint.
		plan.Variant.Actions = map[string]proto.DeployAction{operation: plan.Variant.Actions[operation]}
		visited[current.ID] = revision.ID
		encodedInputs, _ := json.Marshal(inputs)
		resolvedInputs[current.ID] = string(encodedInputs)
		job.Packages = append(job.Packages, plan)
		return nil
	}
	allowed := map[string]bool{}
	for _, parameter := range rev.Definition.Parameters {
		allowed[parameter.Name] = true
	}
	for _, v := range rev.Definition.Variants {
		for _, parameter := range deploy.MergeParameters(v.Parameters, v.Actions[req.Operation].Parameters) {
			allowed[parameter.Name] = true
		}
	}
	for key := range req.Parameters {
		if !allowed[key] {
			return job, fmt.Errorf("unknown package parameter %s", key)
		}
	}
	variant, err := deploy.SelectVariant(rev.Definition, target.OS, target.Arch, target.Platform, target.PlatformVersion)
	if err != nil {
		return job, err
	}
	inputs := map[string]string{}
	for _, parameter := range deploy.MergeParameters(rev.Definition.Parameters, variant.Parameters, variant.Actions[req.Operation].Parameters) {
		if value, ok := req.Parameters[parameter.Name]; ok {
			inputs[parameter.Name] = value
		}
	}
	e = resolve(pkg, rev, req.Operation, inputs)
	if e == nil && s.nc != nil {
		data, _ := json.Marshal(job)
		if int64(len(data)+1024) > s.nc.MaxPayload() {
			e = fmt.Errorf("deployment plan exceeds broker payload limit; increase NATS max_payload or reduce package size")
		}
	}
	return job, e
}

// deployRunResponse is what POST /api/deploy/run and POST /api/deploy/test
// answer.
type deployRunResponse struct {
	RunID   string              `json:"run_id"`
	Skipped []map[string]string `json:"skipped"`
	Targets int                 `json:"targets"`
}

// deployPreviewResponse is what POST /api/deploy/preview answers: the jobs
// a run would send, without sending them.
type deployPreviewResponse struct {
	Plans   []map[string]any    `json:"plans"`
	Skipped []map[string]string `json:"skipped"`
	Targets int                 `json:"targets"`
}

func (s *Server) handleDeployRun(w http.ResponseWriter, r *http.Request) {
	var req deployRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req) != nil {
		http.Error(w, "invalid deployment", 400)
		return
	}
	if req.ExpireSeconds < 0 || req.ExpireSeconds > 31536000 {
		http.Error(w, "expiry must be 0–31536000 seconds", 400)
		return
	}
	if !slices.Contains([]string{"install", "update", "remove", "run"}, req.Operation) {
		http.Error(w, "invalid operation", 400)
		return
	}
	if !s.requireOverride(w, r, req.OverrideWindows) {
		return
	}
	if e := s.resolveDeployGroups(r.Context(), &req); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	if req.NotifyMessageID != "" {
		if m, e := s.store.GetEUNMessage(r.Context(), req.NotifyMessageID); e != nil || m == nil {
			http.Error(w, "no such end-user notification", 400)
			return
		}
	}
	pkg, e := s.store.GetSoftwarePackage(r.Context(), req.PackageID)
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if pkg == nil {
		http.NotFound(w, r)
		return
	}
	// Also here: handleDeploySoftware forwards to this handler, but
	// /api/deploy/run is its own route and is reachable directly.
	if explicitTargetsRequired(w, pkg, req.AgentIDs) {
		return
	}
	if req.RevisionID == "" {
		req.RevisionID = pkg.DeployRevision
	}
	rev, e := s.store.GetDeployRevision(r.Context(), req.RevisionID)
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if rev == nil || rev.Retired || rev.PackageID != pkg.ID {
		http.Error(w, "select a revision of this package", 400)
		return
	}
	test := strings.HasSuffix(r.URL.Path, "/test")
	preview := strings.HasSuffix(r.URL.Path, "/preview")
	if !rev.Published && !test && !preview {
		http.Error(w, "publish the revision before deployment", 400)
		return
	}
	if test && len(req.AgentIDs) != 1 {
		http.Error(w, "draft testing requires one explicit endpoint", 400)
		return
	}
	if !rev.Published {
		if e = deploy.ValidateDefinition(rev.Definition, true); e == nil {
			e = s.snapshotDeployChecks(r.Context(), &rev.Definition)
		}
		if e != nil {
			writeDefinitionError(w, e)
			return
		}
		pkg.Enabled = true
	}
	pkg.DeployDefinition = &rev.Definition
	targets, e := s.store.ListAgents(r.Context(), s.staleAfter())
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	// Validate all supplied values for selected platforms before any target is persisted.
	known := map[string]bool{}
	for _, v := range rev.Definition.Variants {
		for _, d := range deploy.MergeParameters(rev.Definition.Parameters, v.Parameters, v.Actions[req.Operation].Parameters) {
			known[d.Name] = true
		}
	}
	for name := range req.Parameters {
		if !known[name] {
			http.Error(w, "unknown parameter "+name, 400)
			return
		}
	}
	for _, target := range targets {
		if len(req.AgentIDs) > 0 && !slices.Contains(req.AgentIDs, target.AgentID) {
			continue
		}
		v, err := deploy.SelectVariant(rev.Definition, target.OS, target.Arch, target.Platform, target.PlatformVersion)
		if err != nil {
			continue
		}
		defs := deploy.MergeParameters(rev.Definition.Parameters, v.Parameters, v.Actions[req.Operation].Parameters)
		inputs := map[string]string{}
		for _, d := range defs {
			if value, ok := req.Parameters[d.Name]; ok {
				inputs[d.Name] = value
			}
		}
		if _, err = deploy.Parameters(defs, inputs); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	var plan *store.DeploymentPlan
	if req.PlanID != "" {
		plan, e = s.store.GetDeploymentPlan(r.Context(), req.PlanID)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		if plan == nil {
			http.Error(w, "no such deployment plan", 400)
			return
		}
	}
	var jobs []proto.DeployJob
	skipped := []map[string]string{}
	for _, target := range targets {
		if len(req.AgentIDs) > 0 && !slices.Contains(req.AgentIDs, target.AgentID) {
			continue
		}
		job, e := s.planDeploy(r.Context(), *pkg, *rev, target, req)
		if e != nil {
			skipped = append(skipped, map[string]string{"agent_id": target.AgentID, "reason": e.Error()})
			continue
		}
		jobs = append(jobs, job)
	}
	// The same access checks every endpoint action takes, on the final
	// list: management rights and the deploy action group (a named
	// endpoint out of reach is refused, a fleet-wide run is narrowed),
	// content sets, then approval policies. Here rather than only in the
	// route gate because handleDeploySoftware forwards to this handler
	// directly.
	jobIDs := make([]string, 0, len(jobs))
	for _, job := range jobs {
		jobIDs = append(jobIDs, job.AgentID)
	}
	act := endpointAction{
		Module: "deploy", Summary: fmt.Sprintf("%s %s on %d endpoint(s)", req.Operation, pkg.Name, len(jobs)),
		Explicit: req.AgentIDs, NarrowFleet: true,
		Fleet:    func(context.Context) ([]string, error) { return jobIDs, nil },
		Content:  []contentRef{{Kind: "packages", ID: pkg.ID, Name: pkg.Name}},
		Approval: &approvalRef{Handler: "deploy.run", Body: req},
		// A preview runs nothing, so it is never parked.
		ApprovalByCaller: preview,
	}
	allowed, ok := s.authorizeEndpointAction(w, r, act)
	if !ok {
		return
	}
	// nil means nothing restricted the run, so nothing was narrowed.
	if allowed != nil && len(req.AgentIDs) == 0 && len(allowed) < len(jobs) {
		keep := map[string]bool{}
		for _, id := range allowed {
			keep[id] = true
		}
		kept := jobs[:0:0]
		for _, job := range jobs {
			if keep[job.AgentID] {
				kept = append(kept, job)
			} else {
				skipped = append(skipped, map[string]string{"agent_id": job.AgentID, "reason": "outside your management rights or the deploy action group"})
			}
		}
		jobs = kept
	}
	if preview {
		writeJSONResponse(w, deployPreviewResponse{Targets: len(jobs), Skipped: skipped, Plans: redactedDeployJobs(jobs)})
		return
	}
	if len(jobs) == 0 {
		writeJSONStatus(w, 400, map[string]any{"error": "no eligible endpoints", "skipped": skipped})
		return
	}
	var ringTargets []applicabilityRow
	for _, job := range jobs {
		ringTargets = append(ringTargets, applicabilityRow{AgentID: job.AgentID})
	}
	if plan != nil {
		if _, _, err := s.planRings(r.Context(), *plan, ringTargets); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	who := auth.CurrentUser(r.Context()).Username
	runID := idgen.New("run-")
	for i := range jobs {
		jobs[i].RunID = runID
	}
	// Fail closed: a run that sends code to endpoints and cannot be written
	// to the audit log is not started.
	if e = s.auditStrict(r.Context(), auditEvent{Action: "software." + req.Operation, Actor: who, Target: pkg.Name, Severity: "notice", Detail: map[string]any{"run_id": runID, "revision": rev.ID, "targets": len(jobs), "override_windows": req.OverrideWindows}}); e != nil {
		http.Error(w, "the deployment could not be recorded in the audit log, so it was not started", http.StatusServiceUnavailable)
		return
	}
	if e = s.store.CreateDeployRun(r.Context(), store.PatchJobRun{ID: runID, TargetDesc: pkg.Name, ScheduleName: deploymentLabel(*pkg, req.Operation), TriggeredBy: who, NotifyOnFinish: req.NotifyOnFinish}, jobs, plan != nil); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if req.NotifyMessageID != "" {
		ids := make([]string, 0, len(jobs))
		for _, j := range jobs {
			ids = append(ids, j.AgentID)
		}
		s.sendDeployNotice(r.Context(), req.NotifyMessageID, ids, who, deploymentLabel(*pkg, req.Operation))
	}
	if plan != nil {
		pkg.PreparedDeployJobs = map[string]proto.DeployJob{}
		for _, job := range jobs {
			pkg.PreparedDeployJobs[job.AgentID] = job
		}
		go func() {
			ctx := context.WithoutCancel(r.Context())
			defer s.store.CancelHeldDeployJobs(ctx, runID, "Staged rollout ended before this endpoint was released")
			s.runStagedDeployment(ctx, *pkg, req.Operation, *plan, ringTargets, runID, who)
		}()
	}
	writeJSONResponse(w, deployRunResponse{RunID: runID, Targets: len(jobs), Skipped: skipped})
}
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func redactedDeployJobs(jobs []proto.DeployJob) []map[string]any {
	out := []map[string]any{}
	for _, j := range jobs {
		packages := []map[string]any{}
		for _, p := range j.Packages {
			files := []string{}
			for _, f := range p.Files {
				files = append(files, f.Name)
			}
			packages = append(packages, map[string]any{"name": p.Name, "revision": p.RevisionID, "variant": p.Variant.ID, "operation": p.Operation, "files": files, "identity": p.Variant.Actions[p.Operation].Identity, "username": p.Variant.Actions[p.Operation].Username, "success_mode": p.Variant.Actions[p.Operation].SuccessMode})
		}
		out = append(out, map[string]any{"id": j.ID, "agent_id": j.AgentID, "packages": packages})
	}
	return out
}
func (s *Server) persistDeployJob(ctx context.Context, j proto.DeployJob, name, who string) error {
	if e := s.store.StartAgentAction(ctx, store.AgentAction{ID: j.ID, RunID: j.RunID, AgentID: j.AgentID, Kind: "software_" + j.Operation, Summary: name, RequestedBy: who}); e != nil {
		return e
	}
	return s.store.CreateDeployJob(ctx, j)
}
func (s *Server) deployDispatchLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var lastMaintenance time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if time.Since(lastMaintenance) > time.Minute {
			s.maintainDeployLogs(ctx)
			lastMaintenance = time.Now()
		}
		jobs, e := s.store.ListDeployJobs(ctx, true, "")
		if e != nil {
			s.logger.Warn("read deployment queue", "error", e)
			continue
		}
		for _, record := range jobs {
			j := record.Job
			if (record.Status == "queued" || record.Status == "held") && (record.CancelRequested || !j.ExpiresAt.IsZero() && time.Now().After(j.ExpiresAt)) {
				status, detail := "expired", "Deployment expired before endpoint acceptance"
				if record.CancelRequested {
					status, detail = "cancelled", "Cancelled before dispatch"
				}
				_ = s.store.UpdateDeployJob(ctx, j.ID, j.AgentID, status, detail)
				_ = s.store.FinishAgentAction(ctx, j.AgentID, j.ID, status, detail)
				s.notifyRunFinished(ctx, j.RunID)
				continue
			}
			if record.Status == "held" {
				continue
			}
			// A queued job outside every maintenance window that covers its
			// endpoint stays queued, with the reason on the job so the
			// Deployment Progress view says what it is waiting for. The
			// expiry above still applies: a window that never opens before
			// the job expires is an expired job, not a silently dropped one.
			if record.Status == "queued" && !record.CancelRequested && !j.OverrideWindows {
				if v := s.windowCheck(ctx, j.AgentID, "deploy", time.Now()); !v.Allowed {
					if record.Detail != v.Reason {
						_ = s.store.UpdateDeployJob(ctx, j.ID, j.AgentID, "queued", v.Reason)
					}
					continue
				}
			}
			if settings, e := s.deploySettings(ctx); e == nil {
				j.Settings = settings
			}
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			command := proto.AgentCommand{Cmd: "run_deploy", Deploy: &j}
			if record.CancelRequested {
				command = proto.AgentCommand{Cmd: "cancel_deploy", ActionID: j.ID, Force: record.ForceCancel}
			}
			if record.Status == "queued" && !record.CancelRequested {
				capBytes, _ := json.Marshal(proto.AgentCommand{Cmd: "deploy_capabilities"})
				message, e := s.nc.RequestWithContext(cctx, bnats.Cmd(j.AgentID), capBytes)
				if e != nil {
					cancel()
					continue
				}
				var caps proto.AgentCommandResult
				if json.Unmarshal(message.Data, &caps) != nil || caps.DeployVersion < deploy.RequiredVersion(j) {
					cancel()
					_ = s.store.UpdateDeployJob(ctx, j.ID, j.AgentID, "unsupported", "Agent upgrade required for Deploy")
					_ = s.store.FinishAgentAction(ctx, j.AgentID, j.ID, "failed", "Agent upgrade required for Deploy")
					s.notifyRunFinished(ctx, j.RunID)
					continue
				}
			}
			bytes, _ := json.Marshal(command)
			message, e := s.nc.RequestWithContext(cctx, bnats.Cmd(j.AgentID), bytes)
			cancel()
			if e != nil {
				continue
			}
			var reply proto.AgentCommandResult
			if json.Unmarshal(message.Data, &reply) != nil {
				continue
			}
			if status, detail, refused := refusedDeploy(reply, record.CancelRequested); refused {
				_ = s.store.UpdateDeployJob(ctx, j.ID, j.AgentID, status, detail)
				_ = s.store.FinishAgentAction(ctx, j.AgentID, j.ID, status, detail)
				s.notifyRunFinished(ctx, j.RunID)
				continue
			}
			if !reply.OK {
				continue
			}
			if record.Status == "queued" {
				_ = s.store.UpdateDeployJob(ctx, j.ID, j.AgentID, "accepted", "Endpoint accepted and persisted the job")
			}
		}
	}
}

// refusedDeploy ends a job on an endpoint that refuses code from the server.
// Every other failed reply is retried, but this one won't change on its own, and
// retrying it would keep the job open until the mode came off and then run it.
func refusedDeploy(reply proto.AgentCommandResult, cancelRequested bool) (status, detail string, refused bool) {
	if reply.OK || reply.Error != proto.NoRemoteCodeRefusal {
		return "", "", false
	}
	if cancelRequested {
		return "cancelled", reply.Error, true
	}
	return "failed", reply.Error, true
}

func (s *Server) consumeDeployEvent(ctx context.Context, event proto.DeployEvent) error {
	record, e := s.store.GetDeployJob(ctx, event.JobID)
	if e != nil {
		return e
	}
	if record == nil || record.Job.AgentID != event.AgentID || record.Job.RunID != event.RunID {
		return fmt.Errorf("deployment event does not match a persisted target")
	}
	logs, e := s.deploySettings(ctx)
	if e != nil {
		return e
	}
	logDir, e := deployLogDir(event.AgentID)
	if e != nil {
		return e
	}
	log, e := deploylog.Open(logDir, logs.ServerLogs)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(event)
	if e != nil {
		return e
	}
	if _, e = log.Write(append(raw, '\n')); e != nil {
		return e
	}
	// A job that ends badly is recorded with why (deploy_failure.go), not
	// just the final event's "exit status 100".
	detail := event.Message
	ending := deploy.Terminal(event.Status) && !deploy.Terminal(record.Status)
	if ending && (event.Status == "failed" || event.Status == "timed_out") {
		detail = deployFailureDetail(ctx, logDir, record.Job, event)
	}
	if e = s.store.UpdateDeployJob(ctx, event.JobID, event.AgentID, event.Status, safeTruncate(detail, 8000)); e != nil {
		return e
	}
	if ending {
		status := event.Status
		if status == "skipped" {
			status = "succeeded"
		}
		if e = s.store.FinishAgentAction(ctx, event.AgentID, event.JobID, status, detail); e != nil {
			return e
		}
		s.notifyRunFinished(ctx, record.Job.RunID)
		s.afterRemediation(ctx, event.AgentID)
	}
	if event.Stage == "validated" && record.Job.Operation != "run" {
		for _, p := range record.Job.Packages {
			if p.PackageID == event.PackageID {
				return s.store.RecordDeployInstallation(ctx, event.AgentID, p)
			}
		}
	}
	return nil
}

// deployJobsResponse is what GET /api/deploy/jobs answers.
type deployJobsResponse struct {
	Jobs []map[string]any `json:"jobs"`
}

func (s *Server) handleDeployJobs(w http.ResponseWriter, r *http.Request) {
	records, e := s.store.ListDeployJobs(r.Context(), false, r.URL.Query().Get("run_id"))
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	stale := s.staleAfter()
	out := []map[string]any{}
	for _, record := range records {
		j := record.Job
		row := map[string]any{"id": j.ID, "run_id": j.RunID, "agent_id": j.AgentID, "package_id": j.PackageID, "revision_id": j.RevisionID, "operation": j.Operation, "status": record.Status, "detail": record.Detail, "created_at": j.CreatedAt, "expires_at": j.ExpiresAt, "packages": redactedDeployJobs([]proto.DeployJob{j})[0]["packages"]}
		if silent, stalled := deployJobStalled(record, stale); stalled {
			// A job whose endpoint has gone quiet is reported as such rather
			// than left showing "running", which is what an agent update
			// that killed the agent looked like: the job never finishes, and
			// nothing said the endpoint had stopped answering.
			row["stalled"] = true
			row["silent_seconds"] = int(silent.Seconds())
		}
		out = append(out, row)
	}
	writeJSONResponse(w, deployJobsResponse{Jobs: out})
}

// deployJobStalled reports how long the target endpoint has been silent and
// whether that is long enough to call the job stalled.
//
// Held jobs are excluded: they have deliberately not been sent, so an offline
// endpoint says nothing about them. Everything else that has not reached a
// terminal state counts, including a job still queued -- an update that takes
// the agent down before it acknowledges leaves the job exactly there, which
// is the case this exists for.
func deployJobStalled(record store.DeployJobRecord, stale time.Duration) (time.Duration, bool) {
	if record.Status == "held" || deploy.Terminal(record.Status) {
		return 0, false
	}
	if record.LastHeartbeat == nil {
		// Never heard from at all. Only interesting once the job has had
		// long enough that a working endpoint would have answered.
		silent := time.Since(record.Job.CreatedAt)
		return silent, silent > stale
	}
	silent := time.Since(*record.LastHeartbeat)
	return silent, silent > stale
}

// cancelDeployRequest is the body of POST /api/deploy/jobs/{job}/cancel.
type cancelDeployRequest struct {
	Force bool `json:"force"`
}

func (s *Server) handleCancelDeploy(w http.ResponseWriter, r *http.Request) {
	var body cancelDeployRequest
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		http.Error(w, "invalid cancellation", 400)
		return
	}
	if record, e := s.store.GetDeployJob(r.Context(), r.PathValue("job")); e != nil {
		http.Error(w, e.Error(), 500)
		return
	} else if record == nil {
		http.NotFound(w, r)
		return
	} else if record.Job.Operation == "run" {
		body.Force = true
	}
	if e := s.store.CancelDeployJob(r.Context(), r.PathValue("job"), body.Force); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "deploy.cancel", Actor: auth.CurrentUser(r.Context()).Username, Target: r.PathValue("job"), Severity: "notice", Detail: map[string]any{"force": body.Force}})
	if record, e := s.store.GetDeployJob(r.Context(), r.PathValue("job")); e == nil && record != nil && s.nc != nil {
		payload, _ := json.Marshal(proto.AgentCommand{Cmd: "cancel_deploy", ActionID: record.Job.ID, Force: body.Force})
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		_, _ = s.nc.RequestWithContext(ctx, bnats.Cmd(record.Job.AgentID), payload)
		cancel()
	}
	w.WriteHeader(204)
}

func (s *Server) runPublishedSoftware(ctx context.Context, pkg store.SoftwarePackage, operation string, targets []applicabilityRow, runID, who string) {
	revision, e := s.store.GetDeployRevision(ctx, pkg.DeployRevision)
	if e != nil || revision == nil || !revision.Published || revision.Retired || revision.PackageID != pkg.ID {
		s.logger.Error("published revision unavailable", "package", pkg.ID, "error", e)
		return
	}
	agents, e := s.store.ListAgents(ctx, s.staleAfter())
	if e != nil {
		return
	}
	var ids []string
	for _, target := range targets {
		for _, agent := range agents {
			if agent.AgentID != target.AgentID {
				continue
			}
			job, prepared := pkg.PreparedDeployJobs[agent.AgentID]
			var e error
			if !prepared {
				job, e = s.planDeploy(ctx, pkg, *revision, agent, deployRequest{Operation: operation, Parameters: pkg.DeployParameters})
			}
			if e != nil {
				actionID := idgen.New("act-")
				if err := s.store.StartAgentAction(ctx, store.AgentAction{ID: actionID, RunID: runID, AgentID: agent.AgentID, Kind: "software_" + operation, Summary: pkg.Name, RequestedBy: who}); err == nil {
					_ = s.store.FinishAgentAction(ctx, agent.AgentID, actionID, "failed", e.Error())
				}
				continue
			}
			job.RunID = runID
			if prepared {
				e = s.store.ReleaseDeployJob(ctx, job.ID)
			} else {
				e = s.persistDeployJob(ctx, job, pkg.Name, who)
			}
			if e != nil {
				s.logger.Error("persist software job", "error", e)
				continue
			}
			ids = append(ids, job.ID)
		}
	}
	// Staged rollouts rely on this call completing only after device outcomes.
	for _, id := range ids {
		for {
			record, e := s.store.GetDeployJob(ctx, id)
			if e != nil || record == nil || deploy.Terminal(record.Status) {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}
func (s *Server) publishedPlaybookPackage(ctx context.Context, runID string, pkg store.SoftwarePackage, operation string, params map[string]string, target store.AgentRecord, who string) (string, string) {
	revision, e := s.store.GetDeployRevision(ctx, pkg.DeployRevision)
	if e != nil || revision == nil || !revision.Published || revision.Retired || revision.PackageID != pkg.ID {
		return "failed", "published revision unavailable"
	}
	if _, e := deploy.SelectVariant(revision.Definition, target.OS, target.Arch, target.Platform, target.PlatformVersion); e != nil {
		return "skipped", e.Error()
	}
	job, e := s.planDeploy(ctx, pkg, *revision, target, deployRequest{Operation: operation, Parameters: params})
	if e != nil {
		return "failed", e.Error()
	}
	job.RunID = runID
	if e = s.persistDeployJob(ctx, job, pkg.Name, who); e != nil {
		return "failed", e.Error()
	}
	for {
		record, e := s.store.GetDeployJob(ctx, job.ID)
		if e != nil {
			return "failed", e.Error()
		}
		if record != nil && deploy.Terminal(record.Status) {
			return record.Status, record.Detail
		}
		select {
		case <-ctx.Done():
			return "timed_out", "Deployment continues independently; inspect " + job.ID
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Server) maintainDeployLogs(ctx context.Context) {
	settings, e := s.deploySettings(ctx)
	if e != nil {
		return
	}
	dir := filepath.Join(packageFileDir(), "deploy-logs")
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.IsDir() {
			if _, e := deploylog.Open(filepath.Join(dir, entry.Name()), settings.ServerLogs); e != nil {
				s.logger.Warn("retain deployment logs", "error", e)
			}
		}
	}
	if s.nc == nil {
		return
	}
	agents, e := s.store.ListAgents(ctx, s.staleAfter())
	if e != nil {
		return
	}
	raw, _ := json.Marshal(proto.AgentCommand{Cmd: "deploy_settings", DeploySettings: &settings})
	for _, a := range agents {
		if a.Online {
			_ = s.nc.Publish(bnats.Cmd(a.AgentID), raw)
		}
	}
}
