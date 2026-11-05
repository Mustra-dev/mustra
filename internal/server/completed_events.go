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
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

var completedActions = map[string]string{
	"deployment":  "Deployments and patch runs",
	"playbook":    "Playbooks",
	"backup":      "Backups",
	"compliance":  "Compliance scans",
	"enforce":     "Enforce runs",
	"certificate": "Certificate renewals",
	"vuln_scan":   "Vulnerability scans",
	"hunt":        "IOC hunts",
	"reveal":      "Sensitive-data scans",
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

// completionSweepWindow is how far back the sweep looks. Longer than the day a
// job held for a maintenance window waits, and short enough that a run which can
// never add up stops being looked at.
const completionSweepWindow = 7 * 24 * time.Hour

// completionSweepLoop catches runs that ended on any path. A result coming in
// announces at once, but jobs also end by timing out, by expiring while held for
// a window, and through an MDM. The claim makes announcing twice impossible.
func (s *Server) completionSweepLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepRunCompletions(ctx)
		}
	}
}

func (s *Server) sweepRunCompletions(ctx context.Context) {
	ids, err := s.store.UnannouncedRunIDs(ctx, time.Now().Add(-completionSweepWindow))
	if err != nil {
		s.logger.Warn("could not check for finished runs", "error", err)
		return
	}
	for _, id := range ids {
		s.announceRunCompleted(ctx, id)
	}
}

// complianceCompletion describes a finished compliance run. Failing checks do
// not make the run a failure: finding them is the job, and drift has its own
// alert. An endpoint that never answered does, because its state is unknown.
func complianceCompletion(policy string, total, reported, failing int) (title, outcome, severity, body string) {
	outcome, severity = completedOutcome(reported, total-reported)
	body = fmt.Sprintf("%d of %d endpoints reported. %d check%s failing.", reported, total, failing, plural(failing))
	return "Compliance scan finished: " + policy, outcome, severity, body
}

// enforceCompletion describes a finished Enforce pass. Drift in report mode is
// the policy doing its job; a failed remediation or an unreached endpoint is not.
func enforceCompletion(sum enforceRunSummary) (title, outcome, severity, body string) {
	bad := sum.Failed + sum.Unreached
	good := sum.Compliant + sum.Drifted + sum.Remediated + sum.Unknown
	outcome, severity = completedOutcome(good, bad)
	body = fmt.Sprintf("%d endpoint%s, %d unreached. Settings: %d compliant, %d drifted, %d remediated, %d failed, %d unknown.",
		sum.Endpoints, plural(sum.Endpoints), sum.Unreached, sum.Compliant, sum.Drifted, sum.Remediated, sum.Failed, sum.Unknown)
	return "Enforce run finished: " + sum.Policy, outcome, severity, body
}

// huntCompletion describes a finished IOC hunt. A match is what a hunt is for,
// and it has its own alert, so finding something does not make the hunt a failure.
func huntCompletion(found int) (title, outcome, severity, body string) {
	return "IOC hunt finished", "succeeded", "info", fmt.Sprintf("%d new finding%s.", found, plural(found))
}

// revealCompletion describes a finished sensitive-data scan from the rows of the
// endpoints it was sent to. Matching files are what it looks for; an endpoint
// that failed or never finished is what makes the scan incomplete. The terms of a
// quick search stay out of it: they can be the very thing being looked for.
func revealCompletion(rule store.RevealRule, rows []store.RevealScan, total int) (title, outcome, severity, body string, detail map[string]any) {
	done, matched := 0, 0
	for _, r := range rows {
		if r.FinishedAt != nil && r.Error == "" {
			done++
			matched += r.FilesMatched
		}
	}
	name := rule.Name
	title = "Sensitive-data scan finished: " + name
	if rule.Kind == "quick" {
		name = "Quick search"
		title = "Sensitive-data search finished"
	}
	outcome, severity = completedOutcome(done, total-done)
	body = fmt.Sprintf("%d of %d endpoints finished. %d file%s matched.", done, total, matched, plural(matched))
	return title, outcome, severity, body, map[string]any{"succeeded": done, "failed": total - done, "total": total,
		"files_matched": matched, "name": name}
}

// revealCompletionTimeout outlasts the 15 minutes a scan may run on an endpoint.
const revealCompletionTimeout = 20 * time.Minute

// announceRevealScan waits for the endpoints a scan went to, then announces it.
// Scans report per endpoint with no run to close, so this watches for them. A
// server restart loses the watch and that one announcement.
func (s *Server) announceRevealScan(ctx context.Context, rule store.RevealRule, sent, skipped int) {
	total := sent + skipped
	if total == 0 {
		return
	}
	if _, busy := s.revealWatches.LoadOrStore(rule.ID, true); busy {
		return
	}
	since := time.Now().Add(-5 * time.Second)
	go func() {
		defer s.revealWatches.Delete(rule.ID)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revealCompletionTimeout)
		defer cancel()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		var rows []store.RevealScan
		for {
			if all, err := s.store.ListRevealScans(ctx, rule.ID); err == nil {
				rows = rows[:0]
				finished := 0
				for _, r := range all {
					if r.DispatchedAt.After(since) {
						rows = append(rows, r)
						if r.FinishedAt != nil {
							finished++
						}
					}
				}
				if finished >= total {
					break
				}
			}
			select {
			case <-ctx.Done():
			case <-ticker.C:
				continue
			}
			break
		}
		title, outcome, severity, body, detail := revealCompletion(rule, rows, total)
		s.emitCompleted("reveal", title, outcome, severity, body, detail["name"].(string), "/reveal", detail)
	}()
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
