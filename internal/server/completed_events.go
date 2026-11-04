package server

// "Completed" events: an action has finished. Nothing receives them until an
// integration opts in, by ticking the event and, if it likes, choosing which
// actions (Config["completed_actions"]; blank is all of them). Success is info
// and failure is warning, so an integration's minimum severity chooses between
// every completion and only the ones that went wrong.
//
// Console notifications stay as they were: a tray filling up with things that
// went fine is a tray people stop opening. An email somebody asked for is not.

import (
	"context"
	"fmt"
	"strings"
)

var completedActions = map[string]string{
	"deployment":  "Deployments and patch runs",
	"playbook":    "Playbooks",
	"backup":      "Backups",
	"certificate": "Certificate renewals",
	"vuln_scan":   "Vulnerability scans",
	"report":      "Reports",
}

const configCompletedActions = "completed_actions"

// completedOutcome is an outcome from counts of what worked and what did not.
func completedOutcome(ok, bad int) (outcome, severity string) {
	switch {
	case bad == 0:
		return "succeeded", "info"
	case ok == 0:
		return "failed", "warning"
	}
	return "partial", "warning"
}

// emitCompleted announces that an action finished.
func (s *Server) emitCompleted(action, title, outcome, severity, body, target, link string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	s.emitEvent(integrationEvent{Type: "completed", Action: action, Title: title, Body: body, Target: target,
		Severity: severity, Outcome: outcome, Link: link, Detail: detail})
}

// completedWanted says whether an integration takes this action's completions.
func completedWanted(filter string, ev integrationEvent) bool {
	wanted := strings.FieldsFunc(filter, func(r rune) bool { return r == ',' || r == ' ' })
	if len(wanted) == 0 {
		return true
	}
	return containsString(wanted, ev.Action)
}

// parseCompletedFilter checks the actions an integration chose.
func parseCompletedFilter(v string) (string, error) {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })
	for _, f := range fields {
		if completedActions[f] == "" {
			return "", fmt.Errorf("no such action to be told about: %s", f)
		}
	}
	return strings.Join(fields, ","), nil
}

// announceRunCompleted announces a deployment or patch run once its last job
// or action has finished, whoever asked for what. Exactly once: the store
// claims it.
func (s *Server) announceRunCompleted(ctx context.Context, runID string) {
	if runID == "" {
		return
	}
	run, counts, err := s.store.ClaimRunCompletion(ctx, runID)
	if err != nil {
		s.logger.Warn("could not announce a finished run", "run", runID, "error", err)
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
	outcome, severity := completedOutcome(ok, total-ok)
	name := firstNonEmpty(run.ScheduleName, run.TargetDesc, runID)
	s.emitCompleted("deployment", "Deployment finished: "+name, outcome, severity, strings.Join(parts, " · "), name,
		"/patches#deployments", map[string]any{"succeeded": ok, "failed": total - ok, "total": total, "run_id": runID,
			"triggered_by": run.TriggeredBy})
}
