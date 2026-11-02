package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Automatic remediation of threat briefings: an opt-in rule that patches
// the endpoints a briefing confirms as vulnerable, and alerts for those
// still vulnerable past CISA's due date.
//
// It deliberately does as little as a person pressing the briefing's
// "Patch only the affected packages" button would: only endpoints whose
// version the vulnerability scan confirmed (never "product present"), only
// the pending updates for the vulnerable packages, within maintenance
// windows and the patch lists, and never more than autoPatchMaxAttempts
// times for the same exposure. A setting turns it on, so an administrator
// decides once rather than per run, as with a patch schedule.

const (
	settingThreatAutoRemediation = "threats.auto_remediation"
	autoPatchMaxAttempts         = 3
	autoPatchRetryAfter          = 24 * time.Hour
)

// threatAutoRemediation is the rule: GET/PUT /api/threat-settings.
type threatAutoRemediation struct {
	// Enabled turns automatic patching on. Off by default.
	Enabled bool `json:"enabled"`
	// AfterDays waits this many days after an endpoint is first found
	// vulnerable before patching it, for testing a fix first; 0 patches at
	// the next hourly check. 0–30.
	AfterDays int `json:"after_days"`
	// RestartMode is "" (never restart) or "if_required" (restart when the
	// updates need it, after RestartWarnMinutes of the system's warning).
	RestartMode        string `json:"restart_mode"`
	RestartWarnMinutes int    `json:"restart_warn_minutes"`
	// OverdueAlerts notifies once per endpoint and briefing that is still
	// vulnerable after CISA's due date. On by default.
	OverdueAlerts bool `json:"overdue_alerts"`
}

func defaultThreatAutoRemediation() threatAutoRemediation {
	return threatAutoRemediation{OverdueAlerts: true, RestartWarnMinutes: 15}
}

func (s *Server) threatAutoRemediationSettings(ctx context.Context) threatAutoRemediation {
	cfg := defaultThreatAutoRemediation()
	if raw, err := s.store.GetSetting(ctx, settingThreatAutoRemediation); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

func (c threatAutoRemediation) validate() error {
	if c.AfterDays < 0 || c.AfterDays > 30 {
		return fmt.Errorf("after_days must be 0–30")
	}
	switch c.RestartMode {
	case "", "if_required":
	default:
		return fmt.Errorf(`restart_mode must be "" or "if_required"`)
	}
	if c.RestartMode != "" && (c.RestartWarnMinutes < 1 || c.RestartWarnMinutes > 240) {
		return fmt.Errorf("restart_warn_minutes must be 1–240")
	}
	return nil
}

// threatSettingsResponse is what GET and PUT /api/threat-settings answer.
type threatSettingsResponse struct {
	AutoRemediation threatAutoRemediation `json:"auto_remediation"`
	// Editable is set when the caller may change it (patches.manage).
	Editable bool `json:"editable"`
}

// GET /api/threat-settings
func (s *Server) handleGetThreatSettings(w http.ResponseWriter, r *http.Request) {
	can, _ := s.auth.HasPermission(r.Context(), auth.CurrentUser(r.Context()), auth.PermPatchesManage)
	writeJSONResponse(w, threatSettingsResponse{AutoRemediation: s.threatAutoRemediationSettings(r.Context()), Editable: can})
}

// PUT /api/threat-settings
func (s *Server) handlePutThreatSettings(w http.ResponseWriter, r *http.Request) {
	var cfg threatAutoRemediation
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&cfg); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if cfg.RestartMode == "" {
		cfg.RestartWarnMinutes = 0
	}
	if err := cfg.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(cfg)
	u := auth.CurrentUser(r.Context())
	if err := s.store.SetSetting(r.Context(), settingThreatAutoRemediation, string(raw), u.Username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "threats.auto_remediation", Actor: u.Username, Target: "threat briefings", Severity: "notice",
		Detail: map[string]any{"enabled": cfg.Enabled, "after_days": cfg.AfterDays, "restart_mode": cfg.RestartMode, "overdue_alerts": cfg.OverdueAlerts}})
	writeJSONResponse(w, threatSettingsResponse{AutoRemediation: cfg, Editable: true})
}

// remediateThreats is threatLoop's hourly pass over the briefings it just
// evaluated (the whole fleet).
func (s *Server) remediateThreats(ctx context.Context, set *threatSet) {
	cfg := s.threatAutoRemediationSettings(ctx)
	current := map[string][]string{}
	vulnerable := map[string]map[string]threatEndpoint{} // brief → agent → endpoint
	for _, b := range set.briefs {
		for _, e := range set.endpoints[b.ID] {
			if e.Status != "vulnerable" {
				continue
			}
			current[b.ID] = append(current[b.ID], e.AgentID)
			if vulnerable[b.ID] == nil {
				vulnerable[b.ID] = map[string]threatEndpoint{}
			}
			vulnerable[b.ID][e.AgentID] = e
		}
	}
	exposures, err := s.store.SyncThreatExposures(ctx, current)
	if err != nil {
		s.logger.Warn("threat briefings: tracking exposures failed", "error", err)
		return
	}
	now := time.Now()
	if cfg.OverdueAlerts {
		s.alertOverdueThreats(ctx, set, vulnerable, exposures, now)
	}
	if cfg.Enabled {
		s.autoPatchThreats(ctx, cfg, set, vulnerable, exposures, now)
	}
}

// alertOverdueThreats notifies, once per exposure, for endpoints still
// vulnerable after the briefing's CISA due date.
func (s *Server) alertOverdueThreats(ctx context.Context, set *threatSet, vulnerable map[string]map[string]threatEndpoint,
	exposures map[string]map[string]store.ThreatExposure, now time.Time) {
	for _, b := range set.briefs {
		if b.DueDate == nil || !now.After(b.DueDate.Add(24*time.Hour)) {
			continue
		}
		var keys, agents, hosts []string
		for id, e := range vulnerable[b.ID] {
			if exposures[b.ID][id].OverdueNotified {
				continue
			}
			keys, agents, hosts = append(keys, b.ID), append(agents, id), append(hosts, e.Hostname)
		}
		if len(agents) == 0 {
			continue
		}
		sort.Strings(hosts)
		shown := hosts
		if len(shown) > 5 {
			shown = append(shown[:5:5], fmt.Sprintf("%d more", len(hosts)-5))
		}
		s.notify(ctx, "warning", "Threat briefings", "Past CISA's due date: "+b.Title,
			fmt.Sprintf("%s still vulnerable after the %s due date: %s", countOf(len(hosts), "endpoint"), b.DueDate.Format("2 Jan 2006"), strings.Join(shown, ", ")),
			"/threats#"+url.PathEscape(b.ID))
		s.audit(ctx, auditEvent{Action: "threats.overdue", Actor: "system", Target: b.Title, Severity: "warning",
			Detail: map[string]any{"id": b.ID, "due_date": b.DueDate.Format("2006-01-02"), "endpoints": len(hosts)}})
		if err := s.store.MarkThreatOverdueNotified(ctx, keys, agents); err != nil {
			s.logger.Warn("threat briefings: recording overdue alert failed", "error", err)
		}
	}
}

// autoPatchThreats starts one patch run for every exposure that is due,
// each endpoint updating only its vulnerable packages.
func (s *Server) autoPatchThreats(ctx context.Context, cfg threatAutoRemediation, set *threatSet,
	vulnerable map[string]map[string]threatEndpoint, exposures map[string]map[string]store.ThreatExposure, now time.Time) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return
	}
	byID := map[string]store.AgentRecord{}
	for _, a := range agents {
		byID[a.AgentID] = a
	}
	only := map[string][]string{}
	var keys, ids []string
	titles := map[string]string{}
	var gaveUp []string
	for _, b := range set.briefs {
		for id, e := range vulnerable[b.ID] {
			x := exposures[b.ID][id]
			a, ok := byID[id]
			switch {
			case !ok || !a.Online || patchUnsupportedReason(a) != "" || len(e.Packages) == 0:
				continue
			case x.GaveUp:
				continue
			case now.Sub(x.FirstSeen) < time.Duration(cfg.AfterDays)*24*time.Hour:
				continue
			case x.LastAttempt != nil && now.Sub(*x.LastAttempt) < autoPatchRetryAfter:
				continue
			}
			for _, p := range e.Packages {
				if !containsString(only[id], p) {
					only[id] = append(only[id], p)
				}
			}
			keys, ids = append(keys, b.ID), append(ids, id)
			titles[b.ID] = b.Title
			if x.Attempts+1 >= autoPatchMaxAttempts {
				gaveUp = append(gaveUp, e.Hostname+" ("+b.Title+")")
			}
		}
	}
	if len(only) == 0 {
		return
	}
	targets := make([]store.AgentRecord, 0, len(only))
	for id := range only {
		targets = append(targets, byID[id])
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Hostname < targets[j].Hostname })
	runID := idgen.New("run-")
	desc := fmt.Sprintf("automatic remediation: %s, %s", countOf(len(targets), "endpoint"), countOf(len(titles), "briefing"))
	if err := s.store.RecordPatchJobRun(ctx, store.PatchJobRun{ID: runID, TargetDesc: desc, AgentCount: len(targets), TriggeredBy: "auto-remediation"}); err != nil {
		s.logger.Warn("record automatic remediation run failed", "error", err)
	}
	// Counted before dispatch: a run that crashes part-way must not be
	// retried every hour.
	if err := s.store.RecordThreatPatchAttempt(ctx, keys, ids, runID, autoPatchMaxAttempts); err != nil {
		s.logger.Warn("record automatic remediation attempt failed", "error", err)
		return
	}
	names := make([]string, 0, len(titles))
	for _, t := range titles {
		names = append(names, t)
	}
	sort.Strings(names)
	s.audit(ctx, auditEvent{Action: "patches.deploy", Actor: "auto-remediation", Target: desc, Severity: "notice",
		Detail: map[string]any{"run_id": runID, "endpoints": len(targets), "briefings": names, "only_packages": only}})
	restart := patchRestart{Mode: cfg.RestartMode, WarnMinutes: cfg.RestartWarnMinutes}
	started, failed := s.deployPatchesToAgents(ctx, targets, "auto-remediation", runID, false, restart, only)
	s.logger.Info("automatic remediation started", "run_id", runID, "endpoints", len(targets), "started", len(started), "failed", len(failed))
	if len(gaveUp) > 0 {
		sort.Strings(gaveUp)
		s.notify(ctx, "warning", "Threat briefings", "Automatic remediation's last attempt",
			fmt.Sprintf("This was attempt %d of %d for %s; if it does not fix them, patch them by hand: %s",
				autoPatchMaxAttempts, autoPatchMaxAttempts, countOf(len(gaveUp), "endpoint"), strings.Join(gaveUp, ", ")),
			"/patches?run="+url.QueryEscape(runID)+"#deployments")
	}
}

// countOf is "1 endpoint", "3 endpoints".
func countOf(n int, noun string) string {
	return fmt.Sprintf("%d %s%s", n, noun, plural(n))
}
