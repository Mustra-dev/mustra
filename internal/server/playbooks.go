package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Playbooks: doing several things in order, per endpoint, and deciding at
// each step whether the next one still makes sense.
//
// "Patch it, wait for the reboot, verify, tell the person" was four things
// mustra could already do and one it could not: sequence them. Everything
// here is orchestration over commands that already exist — no new agent
// command, nothing new on the endpoint. A playbook is the server being
// patient on your behalf.
//
// Two decisions shape the whole engine:
//
// Each endpoint walks the steps on its own. A run is not a fleet-wide
// state machine that halts because one machine failed; machine seven can be
// stuck waiting to come back from a reboot while machine three is already
// finished. Anything else would mean the slowest endpoint sets the pace and
// one bad endpoint stops the other thirty-eight.
//
// A step's outcome is written when it happens, not at the end. The
// interesting moment for a rolling reboot is while it is still rolling.

const (
	// playbookConcurrency is how many endpoints walk their steps at once.
	// Deliberately low: a playbook step can be "reboot", and rebooting the
	// fleet in parallel is not orchestration, it is an outage.
	playbookConcurrency = 5

	defaultPackageStepTimeout = 20 * time.Minute
	defaultPatchStepTimeout   = 90 * time.Minute
	defaultCheckStepTimeout   = 2 * time.Minute
	defaultEnforceStepTimeout = 15 * time.Minute
	defaultNotifyStepTimeout  = 30 * time.Second
	// maxWaitForOnline caps "wait until it comes back". A machine that has
	// not checked in within this is not slow to reboot, it is not coming
	// back, and the step should say so rather than hold a run open forever.
	maxWaitForOnline = 30 * time.Minute
)

// playbookStep is one thing to do. The kind decides which of the
// kind-specific fields matter; the control-flow fields apply to all of
// them.
type playbookStep struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// package | patch | notify | check | wait | enforce | approval
	Kind string `json:"kind" api:"required"`

	// kind: package
	PackageID    string            `json:"package_id,omitempty"`
	RevisionID   string            `json:"revision_id,omitempty"`
	FollowLatest bool              `json:"follow_latest,omitempty"`
	Operation    string            `json:"operation,omitempty"` // install | update | remove
	Params       map[string]string `json:"params,omitempty"`

	// kind: notify
	MessageID string `json:"message_id,omitempty"`

	// kind: enforce
	PolicyID string `json:"policy_id,omitempty"`

	// kind: check — the same rule dialect Comply and Enforce use
	Rules     []string `json:"rules,omitempty"`
	Condition string   `json:"condition,omitempty"`

	// kind: wait
	WaitSeconds   int  `json:"wait_seconds,omitempty"`
	WaitForOnline bool `json:"wait_for_online,omitempty"`

	// kind: approval — the run stops here until somebody with
	// playbooks.approve decides. ApprovalHours bounds how long it waits.
	ApprovalReason string `json:"approval_reason,omitempty"`
	ApprovalHours  int    `json:"approval_hours,omitempty"`

	// control flow
	RunIf          string `json:"run_if,omitempty"`     // always | previous_succeeded | previous_failed
	OnFailure      string `json:"on_failure,omitempty"` // stop | continue
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

func (st playbookStep) label(index int) string {
	if strings.TrimSpace(st.Name) != "" {
		return st.Name
	}
	return fmt.Sprintf("step %d (%s)", index+1, st.Kind)
}

func (st playbookStep) timeout(fallback time.Duration) time.Duration {
	if st.TimeoutSeconds > 0 {
		return time.Duration(st.TimeoutSeconds) * time.Second
	}
	return fallback
}

// --- targeting and launching -----------------------------------------

func (s *Server) playbookTargets(ctx context.Context, pb store.Playbook) ([]store.AgentRecord, error) {
	// See enforceTargets: a playbook whose group was deleted targets nothing
	// until somebody chooses again, rather than every endpoint.
	if pb.GroupDeleted {
		return nil, nil
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	var members map[string]bool
	if pb.GroupID != "" {
		members, err = s.groupMemberIDSet(ctx, pb.GroupID)
		if err != nil {
			return nil, fmt.Errorf("this playbook's computer group could not be resolved: %w", err)
		}
	}
	var out []store.AgentRecord
	for _, a := range agents {
		if !a.Online {
			continue
		}
		if pb.OS != "" && a.OS != pb.OS {
			continue
		}
		if members != nil && !members[a.AgentID] {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func playbookTargetDesc(pb store.Playbook) string {
	where := "every endpoint"
	switch {
	case pb.GroupDeleted:
		where = "nothing — its computer group was deleted"
	case pb.GroupName != "":
		where = "group: " + pb.GroupName
	case pb.GroupID != "":
		where = "a computer group"
	}
	if pb.OS != "" {
		where += " · " + pb.OS
	}
	return where
}

// launchPlaybook resolves targets, records the run, and walks it in the
// background. It returns as soon as the run exists, because a playbook that
// waits for a reboot is not something to hold an HTTP request open for.
func (s *Server) launchPlaybook(ctx context.Context, pb store.Playbook, who string) (string, int, error) {
	var steps []playbookStep
	if err := json.Unmarshal(pb.Steps, &steps); err != nil || len(steps) == 0 {
		return "", 0, fmt.Errorf("this playbook has no usable steps")
	}
	if err := s.freezePlaybookRevisions(ctx, steps, pb.OS); err != nil {
		return "", 0, err
	}
	pb.Steps, _ = json.Marshal(steps)
	targets, err := s.playbookTargets(ctx, pb)
	if err != nil {
		return "", 0, err
	}
	if len(targets) == 0 {
		return "", 0, fmt.Errorf("no online endpoint matches this playbook's targeting")
	}

	// Same reasoning as Enforce, with sharper consequences: a playbook step
	// can be "reboot" or "install this package", and two passes at once
	// means the same endpoint gets it twice, concurrently. The claim is held
	// until the walk finishes, which is why it is released by executePlaybook
	// rather than here — this function returns as soon as the run exists.
	if !s.runs.claim("playbook:" + pb.ID) {
		return "", 0, fmt.Errorf("%q is already running", pb.Name)
	}

	runID := idgen.New("pbr-")
	if err := s.store.StartPlaybookRun(ctx, store.PlaybookRun{
		ID: runID, PlaybookID: pb.ID, Name: pb.Name, Steps: pb.Steps,
		TargetDesc: playbookTargetDesc(pb), AgentCount: len(targets), TriggeredBy: who,
	}); err != nil {
		s.runs.release("playbook:" + pb.ID)
		return "", 0, err
	}
	// Also a deployment, sharing the run ID. Every per-endpoint action a
	// step takes is recorded against it, so a playbook shows up beside
	// patches and software rather than being the one thing that touches
	// machines without appearing where people look for what touched them.
	if err := s.store.RecordPatchJobRun(ctx, store.PatchJobRun{
		ID: runID, ScheduleName: "Playbook: " + pb.Name,
		TargetDesc: playbookTargetDesc(pb), AgentCount: len(targets), TriggeredBy: who,
	}); err != nil {
		s.logger.Warn("playbook: could not record the deployment row", "playbook", pb.Name, "error", err)
	}

	s.audit(ctx, auditEvent{
		Action: "playbook.run", Actor: who, Target: pb.Name, Severity: "notice",
		Detail: map[string]any{"run_id": runID, "steps": len(steps), "endpoints": len(targets)},
	})
	s.logger.Info("playbook run starting", "playbook", pb.Name, "run_id", runID,
		"steps", len(steps), "endpoints", len(targets), "by", who)

	go s.executePlaybook(context.WithoutCancel(ctx), runID, pb.ID, pb.Name, steps, targets, who)
	return runID, len(targets), nil
}

func (s *Server) executePlaybook(ctx context.Context, runID, playbookID, name string,
	steps []playbookStep, targets []store.AgentRecord, who string) {

	// Claimed in launchPlaybook, released here: the run is not finished
	// until every endpoint has walked its steps, which is minutes or hours
	// after the HTTP request returned.
	defer s.runs.release("playbook:" + playbookID)

	var (
		mu     sync.Mutex
		okCnt  int
		badCnt int
		parked int
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, playbookConcurrency)
	for _, target := range targets {
		wg.Add(1)
		go func(target store.AgentRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok, waiting := s.walkPlaybook(ctx, runID, steps, target, who, 0)
			mu.Lock()
			switch {
			case waiting:
				parked++
			case ok:
				okCnt++
			default:
				badCnt++
			}
			mu.Unlock()
		}(target)
	}
	wg.Wait()

	// A run with endpoints waiting at an approval gate is not finished, and
	// must not be recorded as though it were. It stays open, and the
	// decision — which may come tomorrow, after a restart — resumes it from
	// the database rather than from a goroutine still being alive.
	if parked > 0 {
		if err := s.store.SetPlaybookRunStatus(ctx, runID, "awaiting_approval"); err != nil {
			s.logger.Warn("playbook: could not park the run", "run_id", runID, "error", err)
		}
		s.logger.Info("playbook run parked for approval", "playbook", name, "run_id", runID,
			"waiting", parked, "done", okCnt+badCnt)
		s.notifyRequest(ctx, "notice", "Playbooks", name+" is waiting for approval",
			fmt.Sprintf("%d endpoint(s) have reached an approval step.", parked), "/playbooks#approvals", "playbook", runID, true)
		return
	}

	status := playbookRunStatus(okCnt, badCnt)
	if err := s.store.FinishPlaybookRun(ctx, runID, status); err != nil {
		s.logger.Warn("playbook: could not finish the run", "run_id", runID, "error", err)
	}
	s.logger.Info("playbook run finished", "playbook", name, "run_id", runID,
		"status", status, "succeeded", okCnt, "failed", badCnt)
	if badCnt > 0 {
		s.notify(ctx, "warning", "Playbooks",
			fmt.Sprintf("%s finished %s", name, status),
			fmt.Sprintf("%d of %d endpoints did not complete every step.", badCnt, okCnt+badCnt),
			"/playbooks#runs")
	}
}

// playbookRunStatus describes a whole run from its endpoints' outcomes.
// "partial" exists because it is the common case and the one worth acting
// on: thirty-six endpoints patched and three did not is neither a success
// nor a failure, and calling it either sends somebody to the wrong place.
func playbookRunStatus(succeeded, failed int) string {
	switch {
	case succeeded == 0:
		return "failed"
	case failed > 0:
		return "partial"
	default:
		return "succeeded"
	}
}

// walkPlaybook runs one endpoint's whole sequence. Returns whether it got
// to the end — a step that failed with "carry on anyway" is a red cell in
// the grid, not a failed endpoint.
func (s *Server) walkPlaybook(ctx context.Context, runID string, steps []playbookStep,
	target store.AgentRecord, who string, from int) (completed, waiting bool) {

	// The outcome of the last step that actually ran. A skipped step does
	// not become the new "previous": three conditional steps in a row
	// should all be judged against the last real result, not against each
	// other's absence.
	//
	// A resumed walk starts at "succeeded" because the step it resumes
	// after is an approval that was granted, and a granted approval is a
	// success.
	prev := "succeeded"

	for i, step := range steps {
		if i < from {
			continue
		}
		row := store.PlaybookStepResult{
			RunID: runID, AgentID: target.AgentID, Hostname: target.Hostname,
			StepIndex: i, StepName: step.label(i), Kind: step.Kind,
		}
		if reason, run := shouldRunStep(step.RunIf, prev); !run {
			_ = s.store.RecordSkippedPlaybookStep(ctx, row, reason)
			continue
		}
		if step.Kind == "approval" {
			// One gate for the run, not one per endpoint: asking forty
			// people to approve the same change forty times is not an
			// approval gate. Every endpoint that reaches it joins the same
			// pending decision and stops here.
			s.parkForApproval(ctx, runID, step, i, target, who, row)
			return false, true
		}
		if err := s.store.StartPlaybookStep(ctx, row); err != nil {
			s.logger.Warn("playbook: could not record a step start", "run_id", runID, "error", err)
		}

		status, detail := s.runPlaybookStep(ctx, runID, step, target, who)
		if err := s.store.FinishPlaybookStep(ctx, runID, target.AgentID, i, status, detail); err != nil {
			s.logger.Warn("playbook: could not record a step result", "run_id", runID, "error", err)
		}
		// Only a real outcome becomes the new "previous". A package with no
		// command for this platform reports "skipped" precisely so it does
		// not halt a mixed-platform playbook — but recording that as the
		// previous outcome made every later `previous_succeeded` step skip
		// too, cascading to the end of the run.
		if status != "skipped" {
			if status == "succeeded" {
				prev = status
			} else {
				prev = "failed"
			}
		}

		if status != "succeeded" && status != "skipped" {
			// Only a failure the author did *not* anticipate counts against
			// the endpoint. "Carry on anyway" is a declaration that this
			// step failing is survivable, and a run status that ignores it
			// makes the setting meaningless — worse, a gate-style check is
			// *supposed* to fail on most machines ("is a reboot pending?"),
			// so counting it would paint every run red forever. The step
			// itself is still recorded as failed, and shows red in the grid.
			if step.OnFailure != "continue" {
				// Everything after this is recorded as skipped rather than
				// left absent: "why did nobody get the reboot" is answered
				// by a row saying the step before it failed, and not at all
				// by a gap in the table.
				for j := i + 1; j < len(steps); j++ {
					_ = s.store.RecordSkippedPlaybookStep(ctx, store.PlaybookStepResult{
						RunID: runID, AgentID: target.AgentID, Hostname: target.Hostname,
						StepIndex: j, StepName: steps[j].label(j), Kind: steps[j].Kind,
					}, "an earlier step failed and this playbook stops there")
				}
				return false, false
			}
		}
	}
	return true, false
}

// shouldRunStep applies a step's condition to what the previous step did.
func shouldRunStep(runIf, prev string) (skipReason string, run bool) {
	switch runIf {
	case "previous_succeeded":
		if prev != "succeeded" {
			return "skipped: the previous step did not succeed", false
		}
	case "previous_failed":
		if prev != "failed" {
			return "skipped: this step only runs when the previous one fails", false
		}
	}
	return "", true
}

// --- the steps themselves --------------------------------------------

func (s *Server) runPlaybookStep(ctx context.Context, runID string, step playbookStep,
	target store.AgentRecord, who string) (status, detail string) {

	switch step.Kind {
	case "package":
		return s.stepPackage(ctx, runID, step, target, who)
	case "patch":
		return s.stepPatch(ctx, runID, step, target, who)
	case "notify":
		return s.stepNotify(ctx, runID, step, target, who)
	case "check":
		return s.stepCheck(ctx, step, target)
	case "enforce":
		return s.stepEnforce(ctx, step, target, who)
	case "wait":
		return s.stepWait(ctx, step, target)
	case "approval":
		// Handled in walkPlaybook: an approval stops the whole run rather
		// than this one endpoint, so it cannot be a step that returns an
		// outcome like the others.
		return "failed", "internal: an approval step reached the step runner"
	default:
		return "failed", "unknown step kind: " + step.Kind
	}
}

func (s *Server) stepPackage(ctx context.Context, runID string, step playbookStep,
	target store.AgentRecord, who string) (string, string) {

	pkg, err := s.store.GetSoftwarePackage(ctx, step.PackageID)
	if err != nil || pkg == nil {
		return "failed", "that package no longer exists"
	}
	operation := step.Operation
	if operation == "" {
		operation = "install"
	}
	if pkg.DeployRevision != "" {
		if step.RevisionID != "" {
			pkg.DeployRevision = step.RevisionID
		}
		return s.publishedPlaybookPackage(ctx, runID, *pkg, operation, step.Params, target, who)
	}
	command := legacyCommand(*pkg, pkg.Commands[target.OS], operation)
	if strings.TrimSpace(command) == "" {
		// Not a failure. A package with nothing to run on this platform is
		// a package that does not apply here, and failing the endpoint for
		// that would halt a mixed-platform playbook on its first step.
		return "skipped", fmt.Sprintf("%s has no %s command for %s", pkg.Name, operation, target.OS)
	}
	values, err := resolveParameters(pkg.Parameters, step.Params)
	if err != nil {
		return "failed", "parameters: " + err.Error()
	}
	command = substituteParameters(command, values)

	actionID := idgen.New("act-")
	if err := s.store.StartAgentAction(ctx, store.AgentAction{
		ID: actionID, RunID: runID, AgentID: target.AgentID, Kind: "software_" + operation,
		Summary: deploymentLabel(*pkg, operation), RequestedBy: who,
	}); err != nil {
		s.logger.Warn("playbook: could not record a package action", "error", err)
	}
	sctx, cancel := context.WithTimeout(ctx, step.timeout(defaultPackageStepTimeout))
	defer cancel()
	out, err := s.sendSoftwareCommand(sctx, target.AgentID, command,
		pkg.CommandTimeoutSeconds, s.packageFileRefs(ctx, pkg.ID))
	if err != nil {
		// The endpoint's action keeps timeout and no-response apart from a
		// failure; the step still halts the playbook as failed either way.
		status := softwareActionOutcome(err)
		detail := safeTruncate(softwareOutcomeDetail(status, err, out), 8000)
		_ = s.store.FinishAgentAction(ctx, target.AgentID, actionID, status, detail)
		return "failed", detail
	}
	_ = s.store.FinishAgentAction(ctx, target.AgentID, actionID, "succeeded", out)
	return "succeeded", out
}

// stepPatch applies pending patches and then waits for the real outcome.
//
// This is the step that justifies the engine. apply_patches acknowledges
// immediately and reports what actually happened minutes or hours later, so
// "patch then verify" done by hand means a person watching a page. Here the
// server does the waiting: it polls the action row until the agent's result
// lands, and only then decides whether the next step still applies.
func (s *Server) stepPatch(ctx context.Context, runID string, step playbookStep,
	target store.AgentRecord, who string) (string, string) {

	if why := patchUnsupportedReason(target); why != "" {
		return "skipped", why
	}
	actionID := idgen.New("act-")
	if err := s.store.StartAgentAction(ctx, store.AgentAction{
		ID: actionID, RunID: runID, AgentID: target.AgentID, Kind: "patch_apply",
		Summary: "Apply pending patches", RequestedBy: who,
	}); err != nil {
		s.logger.Warn("playbook: could not record a patch action", "error", err)
	}
	payload, err := json.Marshal(proto.AgentCommand{
		Cmd: "apply_patches", RunID: runID, ActionID: actionID,
	})
	if err != nil {
		return "failed", err.Error()
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(target.AgentID), payload)
	cancel()
	if err != nil {
		_ = s.store.FinishAgentAction(ctx, target.AgentID, actionID, "failed", "did not respond: "+err.Error())
		return "failed", "the endpoint did not accept the patch job: " + err.Error()
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &res); err != nil || !res.OK {
		reason := res.Error
		if reason == "" {
			reason = "malformed response"
		}
		_ = s.store.FinishAgentAction(ctx, target.AgentID, actionID, "failed", reason)
		return "failed", "the endpoint refused the patch job: " + reason
	}

	deadline := time.Now().Add(step.timeout(defaultPatchStepTimeout))
	for {
		select {
		case <-ctx.Done():
			return "failed", "the server stopped waiting"
		case <-time.After(20 * time.Second):
		}
		action, err := s.store.GetAgentAction(ctx, actionID)
		if err == nil && action.FinishedAt != nil {
			if action.Status == "succeeded" {
				return "succeeded", action.Detail
			}
			return "failed", action.Detail
		}
		if time.Now().After(deadline) {
			// The action is left open on purpose: the endpoint may still be
			// installing, and the agent will close it when it finishes. What
			// timed out is this step's patience, not the patch job.
			return "failed", "the patch job had not reported back after " +
				step.timeout(defaultPatchStepTimeout).String() + "; it may still be installing"
		}
	}
}

func (s *Server) stepNotify(ctx context.Context, runID string, step playbookStep,
	target store.AgentRecord, who string) (string, string) {

	msg, err := s.store.GetEUNMessage(ctx, step.MessageID)
	if err != nil || msg == nil {
		return "failed", "that message no longer exists"
	}
	actionID := idgen.New("act-")
	if err := s.store.StartAgentAction(ctx, store.AgentAction{
		ID: actionID, RunID: runID, AgentID: target.AgentID, Kind: "end_user_notification",
		Summary: msg.Title, RequestedBy: who,
	}); err != nil {
		s.logger.Warn("playbook: could not record a notification action", "error", err)
	}
	n := eunToProto(*msg)
	payload, err := json.Marshal(proto.AgentCommand{
		Cmd: "notify_user", Notify: &n, RunID: runID, ActionID: actionID,
	})
	if err != nil {
		return "failed", err.Error()
	}
	rctx, cancel := context.WithTimeout(ctx, step.timeout(defaultNotifyStepTimeout))
	defer cancel()
	reply, err := s.nc.RequestWithContext(rctx, bnats.Cmd(target.AgentID), payload)
	if err != nil {
		_ = s.store.FinishAgentAction(ctx, target.AgentID, actionID, "failed", "did not respond: "+err.Error())
		return "failed", "the endpoint did not take the message: " + err.Error()
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(reply.Data, &res); err != nil || !res.OK {
		reason := res.Error
		if reason == "" {
			reason = "malformed response"
		}
		_ = s.store.FinishAgentAction(ctx, target.AgentID, actionID, "failed", reason)
		return "failed", reason
	}
	// Delivered, which is not the same as answered — the action stays open
	// for the person's reply, exactly as a hand-sent notification does.
	return "succeeded", "the endpoint has the message"
}

// stepCheck is the gate. It evaluates rules on the endpoint and passes or
// fails, which is what makes "verify" a step rather than a hope.
func (s *Server) stepCheck(ctx context.Context, step playbookStep, target store.AgentRecord) (string, string) {
	if len(step.Rules) == 0 {
		return "failed", "this check defines no rules"
	}
	check := proto.ComplianceCheck{
		ID: "playbook-check", Title: step.Name,
		Condition: step.Condition, Rules: step.Rules,
	}
	payload, err := json.Marshal(proto.AgentCommand{
		Cmd: "run_compliance", Checks: []proto.ComplianceCheck{check},
	})
	if err != nil {
		return "failed", err.Error()
	}
	rctx, cancel := context.WithTimeout(ctx, step.timeout(defaultCheckStepTimeout))
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(target.AgentID), payload)
	if err != nil {
		return "failed", "the endpoint did not answer the check: " + err.Error()
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &res); err != nil || !res.OK {
		reason := res.Error
		if reason == "" {
			reason = "malformed response"
		}
		return "failed", reason
	}
	if len(res.Results) == 0 {
		return "failed", "the endpoint returned no result for this check"
	}
	r := res.Results[0]
	switch r.State {
	case "pass":
		return "succeeded", "passed"
	case "unknown":
		// Not a pass. The same reason "unknown" exists in Comply: a gate
		// that opens because nobody could evaluate it is worse than one
		// that stays shut.
		return "failed", "could not be evaluated on this endpoint: " + r.Detail
	default:
		return "failed", r.Detail
	}
}

func (s *Server) stepEnforce(ctx context.Context, step playbookStep,
	target store.AgentRecord, who string) (string, string) {

	policy, err := s.store.GetEnforcePolicy(ctx, step.PolicyID)
	if err != nil {
		return "failed", "could not read the enforce policy: " + err.Error()
	}
	if policy == nil {
		return "failed", "that enforce policy no longer exists"
	}
	sctx, cancel := context.WithTimeout(ctx, step.timeout(defaultEnforceStepTimeout))
	defer cancel()
	summary, err := s.runEnforceOn(sctx, *policy, []store.AgentRecord{target}, who)
	if err != nil {
		return "failed", err.Error()
	}
	detail := fmt.Sprintf("compliant %d, remediated %d, drifted %d, failed %d, unknown %d",
		summary.Compliant, summary.Remediated, summary.Drifted, summary.Failed, summary.Unknown)
	if summary.Failed > 0 || summary.Unreached > 0 {
		return "failed", detail
	}
	return "succeeded", detail
}

// stepWait is how a playbook survives a reboot.
//
// Waiting for a fixed number of seconds is a guess. Waiting until the
// endpoint has checked in *since this step started* is the real question,
// and it is why the heartbeat comparison is against the step's own start
// time rather than "is it online" — a machine that has not rebooted yet is
// still online, and a naive online check would sail straight past it.
func (s *Server) stepWait(ctx context.Context, step playbookStep, target store.AgentRecord) (string, string) {
	if step.WaitSeconds > 0 {
		select {
		case <-ctx.Done():
			return "failed", "the server stopped waiting"
		case <-time.After(time.Duration(step.WaitSeconds) * time.Second):
		}
	}
	// After the fixed wait, not before: a step configured with both would
	// otherwise accept a heartbeat sent during the sleep — from the machine
	// that has not gone down yet — and report it as having come back.
	since := time.Now().UTC()
	if !step.WaitForOnline {
		return "succeeded", fmt.Sprintf("waited %ds", step.WaitSeconds)
	}

	deadline := time.Now().Add(step.timeout(maxWaitForOnline))
	for {
		agents, err := s.store.ListAgents(ctx, s.staleAfter())
		if err == nil {
			for _, a := range agents {
				if a.AgentID != target.AgentID {
					continue
				}
				if a.Online && a.LastHeartbeat.After(since) {
					return "succeeded", "checked in again at " + a.LastHeartbeat.Format(time.RFC3339)
				}
			}
		}
		if time.Now().After(deadline) {
			return "failed", "the endpoint had not checked in again after " +
				step.timeout(maxWaitForOnline).String()
		}
		select {
		case <-ctx.Done():
			return "failed", "the server stopped waiting"
		case <-time.After(15 * time.Second):
		}
	}
}

// --- the schedule ----------------------------------------------------

func (s *Server) playbookSchedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDuePlaybooks(ctx)
		}
	}
}

func (s *Server) runDuePlaybooks(ctx context.Context) {
	due, err := s.store.DuePlaybooks(ctx, time.Now().UTC())
	if err != nil {
		s.logger.Warn("playbook: could not check for due runs", "error", err)
		return
	}
	for _, pb := range due {
		// The next run is computed and stored before launching. A playbook
		// whose steps take longer than its interval must not pile up on
		// itself, and a launch that fails must not leave it due forever.
		next, err := computeNextRun(pb.ScheduleKind, pb.TimeOfDay, pb.Weekday, time.Now().UTC())
		if err != nil {
			s.logger.Warn("playbook: bad schedule", "playbook", pb.Name, "error", err)
			next = nil
		}
		if err := s.store.MarkPlaybookRun(ctx, pb.ID, time.Now().UTC(), next); err != nil {
			s.logger.Warn("playbook: could not update the schedule", "playbook", pb.Name, "error", err)
		}
		if _, _, err := s.launchPlaybook(ctx, pb, "scheduler"); err != nil {
			// Still running from the previous firing: skipping is the point
			// of the guard. A playbook that waits for a reboot can easily
			// outlast a daily interval on a slow endpoint.
			if strings.Contains(err.Error(), "already running") {
				s.logger.Info("playbook: skipping a run that is still going", "playbook", pb.Name)
				continue
			}
			s.logger.Warn("playbook: scheduled run did not start", "playbook", pb.Name, "error", err)
		}
	}
}
