package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// Enforce: holding a setting in place, rather than reporting that it moved.
//
// Comply already answers "is the firewall on". The difference here is that
// this turns it back on, on a timer, without anybody asking — which makes
// it the most dangerous thing mustra does, and the design is mostly about
// that. Three rules:
//
//  1. A policy starts in report mode and stays there until somebody
//     deliberately switches it. You can watch what it *would* do first.
//  2. The endpoint re-checks after remediating. An exit code is not
//     evidence the setting took.
//  3. A remediation that has failed MaxRemediationAttempts times in a row
//     on one endpoint stops being sent there. Without that, a broken
//     command runs every half hour on every affected machine forever, and
//     the engine generates load in exact proportion to how wrong it is.

const (
	// enforceInterval is how often every enabled policy is evaluated.
	// Half-hourly rather than by the minute: this is desired state, not
	// intrusion prevention, and each pass may run commands on every
	// targeted endpoint.
	enforceInterval = 30 * time.Minute
	// enforceDispatchTimeout caps one endpoint's whole pass. Generous
	// because every setting may shell out twice — check, fix, check again.
	enforceDispatchTimeout = 15 * time.Minute
	enforceConcurrency     = 8
)

func (s *Server) enforceLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	s.runAllEnforcePolicies(ctx)

	ticker := time.NewTicker(enforceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runAllEnforcePolicies(ctx)
		}
	}
}

func (s *Server) runAllEnforcePolicies(ctx context.Context) {
	policies, err := s.store.ListEnforcePolicies(ctx)
	if err != nil {
		s.logger.Warn("enforce: could not load policies", "error", err)
		return
	}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		if _, err := s.runEnforcePolicy(ctx, p, "scheduler"); err != nil {
			// A policy still running from the last tick is the guard doing
			// its job, not a failure: a pass may legitimately outlast the
			// interval on a slow fleet.
			if strings.Contains(err.Error(), "already running") {
				s.logger.Info("enforce: skipping a policy that is still running",
					"policy", p.Name)
				continue
			}
			s.logger.Warn("enforce: policy run failed", "policy", p.Name, "error", err)
		}
	}
}

type enforceRunSummary struct {
	Policy     string `json:"policy"`
	Mode       string `json:"mode"`
	Endpoints  int    `json:"endpoints"`
	Compliant  int    `json:"compliant"`
	Drifted    int    `json:"drifted"`
	Remediated int    `json:"remediated"`
	Failed     int    `json:"failed"`
	Unknown    int    `json:"unknown"`
	Unreached  int    `json:"unreached"`
}

// enforceTargets resolves who a policy applies to right now.
//
// A policy whose group has been deleted targets nothing rather than
// everything. Silently widening from "the twelve servers" to "all
// thirty-nine endpoints" because a group was tidied up is the kind of
// surprise an enforcement engine must never spring.
func (s *Server) enforceTargets(ctx context.Context, p store.EnforcePolicy) ([]store.AgentRecord, error) {
	// Targeting that lost its group is targeting nothing. A blank group id
	// otherwise reads as "the whole fleet", which would turn a policy scoped
	// to twelve servers into one that remediates thirty-nine.
	if p.GroupDeleted {
		return nil, nil
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	var members map[string]bool
	if p.GroupID != "" {
		members, err = s.groupMemberIDSet(ctx, p.GroupID)
		if err != nil {
			return nil, fmt.Errorf("this policy's computer group could not be resolved: %w", err)
		}
	}
	var out []store.AgentRecord
	for _, a := range agents {
		if !a.Online {
			continue
		}
		if p.OS != "" && a.OS != p.OS {
			continue
		}
		if members != nil && !members[a.AgentID] {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// runEnforcePolicy evaluates a policy across everything it targets.
//
// The one-at-a-time guard lives here rather than in runEnforceOn, and the
// distinction matters: this is the fleet-wide pass, which a schedule and a
// person can both start, and running the same remediation twice at once on
// the same machine is a race. runEnforceOn is also called per endpoint by a
// playbook's enforce step — five endpoints at a time — and a guard there
// refused four of every five and stopped those playbooks dead.
func (s *Server) runEnforcePolicy(ctx context.Context, p store.EnforcePolicy, who string) (enforceRunSummary, error) {
	if !s.runs.claim("enforce:" + p.ID) {
		return enforceRunSummary{Policy: p.Name, Mode: p.Mode},
			fmt.Errorf("%q is already running", p.Name)
	}
	defer s.runs.release("enforce:" + p.ID)

	targets, err := s.enforceTargets(ctx, p)
	if err != nil {
		return enforceRunSummary{Policy: p.Name, Mode: p.Mode}, err
	}
	return s.runEnforceOn(ctx, p, targets, who)
}

// runEnforceOn evaluates a policy against an explicit target list. Split
// out from runEnforcePolicy so a playbook step can enforce a policy on the
// one endpoint it is currently walking, without a second copy of the
// suppression, recording and notification logic drifting away from this
// one.
// dryRunMode is what handleRunEnforcePolicy passes instead of rewriting the
// policy's mode. Blanking Mode also emptied the suppression map, so a single
// dry run overwrote every "failing" row — the record of what mustra had
// given up on — with plain "drifted", losing the give-up signal until the
// next scheduled pass re-derived it.
const dryRunMode = "report (dry run)"

func (s *Server) runEnforceOn(ctx context.Context, p store.EnforcePolicy,
	targets []store.AgentRecord, who string) (enforceRunSummary, error) {

	summary := enforceRunSummary{Policy: p.Name, Mode: p.Mode}
	var settings []proto.EnforceSetting
	if err := json.Unmarshal(p.Settings, &settings); err != nil || len(settings) == 0 {
		return summary, fmt.Errorf("this policy has no usable settings")
	}
	summary.Endpoints = len(targets)
	if len(targets) == 0 {
		_ = s.store.MarkEnforcePolicyRun(ctx, p.ID)
		return summary, nil
	}

	// Read the failure history once for the whole pass. It decides, per
	// endpoint and per setting, whether this run is allowed to touch
	// anything — which is a decision only the server can make, because only
	// the server remembers the last three runs.
	failures, err := s.store.EnforceFailureCounts(ctx, p.ID)
	if err != nil {
		s.logger.Warn("enforce: could not read failure history; running in report mode",
			"policy", p.Name, "error", err)
		failures = map[string]map[string]int{}
	}

	var (
		mu        sync.Mutex
		firstFail = map[string][]string{} // setting name -> hostnames
		gaveUp    = map[string][]string{}
		wg        sync.WaitGroup
	)
	sem := make(chan struct{}, enforceConcurrency)

	for _, target := range targets {
		wg.Add(1)
		go func(target store.AgentRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			spec := proto.EnforcePolicySpec{ID: p.ID, Name: p.Name}
			suppressed := map[string]bool{}
			for _, setting := range settings {
				out := setting
				count := failures[target.AgentID][setting.ID]
				// Nothing is remediated on a dry run, but a setting mustra
				// has given up on is still given up on — so suppression is
				// decided by whether the policy *would* enforce, not by
				// whether this particular pass is going to.
				wouldEnforce := p.Mode == "enforce" || p.Mode == dryRunMode
				out.Enforce = p.Mode == "enforce" && count < store.MaxRemediationAttempts
				if wouldEnforce && count >= store.MaxRemediationAttempts {
					suppressed[setting.ID] = true
				}
				spec.Settings = append(spec.Settings, out)
			}

			results, err := s.dispatchEnforce(ctx, target, spec)
			if err != nil {
				mu.Lock()
				summary.Unreached++
				mu.Unlock()
				s.logger.Warn("enforce: endpoint did not complete the policy",
					"policy", p.Name, "hostname", target.Hostname, "error", err)
				return
			}

			byID := map[string]proto.EnforceSetting{}
			for _, setting := range settings {
				byID[setting.ID] = setting
			}
			for _, res := range results {
				state, detail := res.State, res.Detail
				// A suppressed setting comes back "drifted" because nothing
				// was attempted. Storing that would be a lie by omission —
				// it isn't merely drifted, mustra has stopped trying.
				if state == "drifted" && suppressed[res.SettingID] {
					state = "failing"
					detail = fmt.Sprintf("still wrong, and not retried: the fix failed %d times in a row here. %s",
						store.MaxRemediationAttempts, detail)
				}
				row, err := s.store.RecordEnforceResult(ctx, store.EnforceResult{
					AgentID: target.AgentID, PolicyID: p.ID, SettingID: res.SettingID,
					Name: nameFor(byID[res.SettingID], res), Severity: byID[res.SettingID].Severity,
					State: state, Detail: detail, Output: trimOutput(res.Output),
				})
				if err != nil {
					s.logger.Warn("enforce: could not record result", "policy", p.Name, "error", err)
					continue
				}

				mu.Lock()
				switch state {
				case "compliant":
					summary.Compliant++
				case "remediated":
					summary.Remediated++
				case "failed", "failing":
					summary.Failed++
				case "unknown":
					summary.Unknown++
				default:
					summary.Drifted++
				}
				// Announce the edges only: the first time a fix fails here,
				// and the moment mustra gives up. Everything in between is
				// the same news repeated every half hour.
				if state == "failed" && row.ConsecutiveFailures == 1 {
					firstFail[row.Name] = append(firstFail[row.Name], target.Hostname)
				}
				if state == "failed" && row.ConsecutiveFailures == store.MaxRemediationAttempts {
					gaveUp[row.Name] = append(gaveUp[row.Name], target.Hostname)
				}
				mu.Unlock()

				if state == "remediated" || state == "failed" {
					s.auditRemediation(ctx, p, target, row, who)
				}
			}
		}(target)
	}
	wg.Wait()
	_ = s.store.MarkEnforcePolicyRun(ctx, p.ID)

	for name, hosts := range firstFail {
		s.notify(ctx, "warning", "Enforce",
			fmt.Sprintf("%s: %q could not be fixed", p.Name, name),
			summariseHosts(hosts)+". Retrying next pass.", "/enforce#"+p.ID)
	}
	for name, hosts := range gaveUp {
		s.notify(ctx, "critical", "Enforce",
			fmt.Sprintf("%s: gave up on %q", p.Name, name),
			fmt.Sprintf("%s after %d failed attempts. mustra will not try again until the policy or the endpoint changes.",
				summariseHosts(hosts), store.MaxRemediationAttempts), "/enforce#"+p.ID)
	}

	s.logger.Info("enforce policy run finished", "policy", p.Name, "mode", p.Mode,
		"endpoints", summary.Endpoints, "compliant", summary.Compliant,
		"remediated", summary.Remediated, "drifted", summary.Drifted,
		"failed", summary.Failed, "unreached", summary.Unreached)
	return summary, nil
}

func (s *Server) dispatchEnforce(ctx context.Context, target store.AgentRecord,
	spec proto.EnforcePolicySpec) ([]proto.EnforceResult, error) {

	payload, err := json.Marshal(proto.AgentCommand{Cmd: "run_enforce", Enforce: &spec})
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, enforceDispatchTimeout)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(target.AgentID), payload)
	if err != nil {
		return nil, err
	}
	var result proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("unreadable reply: %w", err)
	}
	if !result.OK {
		// An agent too old to know run_enforce answers "unknown command".
		// Swallowing that would produce a run that completes instantly
		// having stored nothing, which is indistinguishable from a fleet
		// that is entirely compliant.
		return nil, fmt.Errorf("the endpoint refused the policy: %s", result.Error)
	}
	return result.Enforced, nil
}

// auditRemediation records a change mustra made to a machine nobody asked
// about. This is the answer to "what touched my server at 3am", and it is
// the reason enforcement is tolerable at all.
func (s *Server) auditRemediation(ctx context.Context, p store.EnforcePolicy,
	target store.AgentRecord, row store.EnforceResult, who string) {

	outcome, severity := "ok", "notice"
	if row.State != "remediated" {
		outcome, severity = "failed", "warning"
	}
	s.audit(ctx, auditEvent{
		Action: "enforce.remediate", Actor: who, Target: target.Hostname,
		AgentID: target.AgentID, Outcome: outcome, Severity: severity,
		Detail: map[string]any{
			"policy": p.Name, "setting": row.Name, "state": row.State,
			"detail": row.Detail, "consecutive_failures": row.ConsecutiveFailures,
		},
	})
}

func nameFor(setting proto.EnforceSetting, res proto.EnforceResult) string {
	if setting.Name != "" {
		return setting.Name
	}
	if res.Name != "" {
		return res.Name
	}
	return res.SettingID
}

// trimOutput keeps a remediation's output useful without letting one
// verbose installer fill the table.
func trimOutput(out string) string {
	out = strings.TrimSpace(out)
	const max = 4000
	if len(out) <= max {
		return out
	}
	// Cut on a rune boundary. A byte slice through a multi-byte character
	// yields invalid UTF-8, which Postgres refuses in a text column — so the
	// result was not stored at all, and the only sign was a logged warning.
	cut := out[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "\n… (truncated)"
}

// enforceOverview is the per-policy roll-up the console lists.
type enforceOverview struct {
	store.EnforcePolicy
	Endpoints  int `json:"endpoints"`
	Compliant  int `json:"compliant"`
	Drifted    int `json:"drifted"`
	Remediated int `json:"remediated"`
	Failed     int `json:"failed"`
	Failing    int `json:"failing"`
	Unknown    int `json:"unknown"`
}

func summariseEnforce(policies []store.EnforcePolicy, results []store.EnforceResult) []enforceOverview {
	byPolicy := map[string]*enforceOverview{}
	out := make([]enforceOverview, 0, len(policies))
	for _, p := range policies {
		out = append(out, enforceOverview{EnforcePolicy: p})
	}
	for i := range out {
		byPolicy[out[i].ID] = &out[i]
	}
	seen := map[string]map[string]bool{}
	for _, r := range results {
		o := byPolicy[r.PolicyID]
		if o == nil {
			continue
		}
		if seen[r.PolicyID] == nil {
			seen[r.PolicyID] = map[string]bool{}
		}
		if !seen[r.PolicyID][r.AgentID] {
			seen[r.PolicyID][r.AgentID] = true
			o.Endpoints++
		}
		switch r.State {
		case "compliant":
			o.Compliant++
		case "remediated":
			o.Remediated++
		case "failed":
			o.Failed++
		case "failing":
			o.Failing++
		case "unknown":
			o.Unknown++
		default:
			o.Drifted++
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}
