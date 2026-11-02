package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/reveal"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

// Guide: the notification tray.
//
// Findings used to live on the page that produced them -- a stalled job on
// Deploy, a certificate on Certificate Manager, a missing grant on one
// endpoint's Privileges tab -- and nobody watches five pages. Every couple
// of minutes the evaluators below look at the whole picture and write one
// item per condition, keyed so a condition that persists is one item that
// refreshes rather than a new one each pass. Two kinds:
// guidance links to the fix; an observation is something to look at.
//
// An evaluator reports everything it can see, and whatever it did not
// report is resolved: the tray empties itself when the world improves,
// which is what makes it trustworthy enough to look at.

const guideEvery = 2 * time.Minute

type guideItem struct {
	key, kind, severity, title, detail, link string
	count                                    int
}

func (s *Server) guideLoop(ctx context.Context) {
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.evaluateGuide(ctx)
		timer.Reset(guideEvery)
	}
}

// evaluateGuide runs every evaluator, each responsible for one source.
// One failing evaluator must not silence the others, so each is its own
// call with its own error handling.
func (s *Server) evaluateGuide(ctx context.Context) {
	evaluators := map[string]func(context.Context) ([]guideItem, error){
		"deploy":          s.guideStalledJobs,
		"certificates":    s.guideCertificates,
		"agents":          s.guideAgents,
		"endpoint":        s.guideEndpoints,
		"reveal":          s.guideReveal,
		"impact":          s.guideImpact,
		"directory":       s.guideDirectory,
		"vulnerabilities": s.guideVulnerabilities,
		"os_lifecycle":    s.guideOSLifecycle,
		"exploited":       s.guideExploited,
		"alerts":          s.guideAlerts,
	}
	for source, eval := range evaluators {
		items, err := eval(ctx)
		if err != nil {
			s.logger.Warn("guide: evaluator failed", "source", source, "error", err)
			continue
		}
		keep := make([]string, 0, len(items))
		for _, it := range items {
			key := source + ":" + it.key
			keep = append(keep, key)
			n := store.GuideNotification{ID: idgen.New("gd-"), SubjectKey: key, Source: source, Kind: it.kind, Severity: it.severity,
				Title: it.title, Detail: it.detail, Link: it.link, Count: it.count}
			if n.Count == 0 {
				n.Count = 1
			}
			if err := s.store.UpsertGuide(ctx, n); err != nil {
				s.logger.Warn("guide: could not record", "source", source, "key", it.key, "error", err)
			}
		}
		if err := s.store.ResolveGuideExcept(ctx, source, keep); err != nil {
			s.logger.Warn("guide: could not resolve", "source", source, "error", err)
		}
	}
}

// ---- evaluators ----

// A job still outstanding on an endpoint that stopped answering; what an
// agent update that killed the agent looks like.
func (s *Server) guideStalledJobs(ctx context.Context) ([]guideItem, error) {
	records, err := s.store.ListDeployJobs(ctx, true, "")
	if err != nil {
		return nil, err
	}
	stale := s.staleAfter()
	agents, _ := s.store.ListAgents(ctx, stale)
	hosts := map[string]string{}
	for _, a := range agents {
		hosts[a.AgentID] = a.Hostname
	}
	var out []guideItem
	for _, rec := range records {
		silent, stalled := deployJobStalled(rec, stale)
		if !stalled {
			continue
		}
		host := rec.Job.AgentID
		if h := hosts[rec.Job.AgentID]; h != "" {
			host = h
		}
		out = append(out, guideItem{key: "job:" + rec.Job.ID, kind: "guidance", severity: "high",
			title:  fmt.Sprintf("%s went quiet with a %s job outstanding", host, rec.Job.Operation),
			detail: fmt.Sprintf("Silent for %s while the job is still %s. If it was an agent update, it may have taken the agent with it; reinstalling on the endpoint is the way back.", silent.Round(time.Minute), rec.Status),
			link:   "/deploy?job=" + rec.Job.ID + "#jobs"})
	}
	return out, nil
}

func (s *Server) guideCertificates(ctx context.Context) ([]guideItem, error) {
	rows, err := s.certificateRows(ctx)
	if err != nil {
		return nil, err
	}
	expired, critical := 0, 0
	var soonest *certificateRow
	for i := range rows {
		r := &rows[i]
		if r.TrustStore {
			continue // an OS trust store's expiring root is the vendor's to rotate
		}
		switch r.Status {
		case "expired":
			expired++
		case "critical":
			critical++
			if soonest == nil || r.DaysLeft < soonest.DaysLeft {
				soonest = r
			}
		}
	}
	var out []guideItem
	if expired > 0 {
		out = append(out, guideItem{key: "expired", kind: "guidance", severity: "high", count: expired,
			title:  fmt.Sprintf("%d service certificate(s) have expired", expired),
			detail: "Something is presenting a certificate that is already past its date. Certificate Manager lists them with where each one lives.", link: "/certificates"})
	}
	if critical > 0 {
		detail := "Renew before they lapse."
		if soonest != nil {
			detail = fmt.Sprintf("Soonest: %s in %d day(s). %s", soonest.Subject, soonest.DaysLeft, detail)
		}
		out = append(out, guideItem{key: "critical", kind: "guidance", severity: "medium", count: critical,
			title: fmt.Sprintf("%d service certificate(s) expire within a week", critical), detail: detail, link: "/certificates"})
	}
	return out, nil
}

// Agents behind the version the control plane serves.
func (s *Server) guideAgents(ctx context.Context) ([]guideItem, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	serving := version.Agent()
	if !versionParses(serving) {
		return nil, nil
	}
	behind := 0
	var names []string
	for _, a := range agents {
		if a.AgentVersion != "" && versionIsNewer(serving, a.AgentVersion) {
			behind++
			if len(names) < 6 {
				names = append(names, a.Hostname)
			}
		}
	}
	if behind == 0 {
		return nil, nil
	}
	more := ""
	if behind > len(names) {
		more = fmt.Sprintf(" and %d more", behind-len(names))
	}
	return []guideItem{{key: "behind:" + serving, kind: "observation", severity: "low", count: behind,
		title:  fmt.Sprintf("%d endpoint(s) run an agent older than %s", behind, serving),
		detail: strings.Join(names, ", ") + more + ". Client Management shows every version; the \"Update mustra agent\" package targets exactly these.",
		link:   "/agents#overview"}}, nil
}

// Per-endpoint conditions: a Mac without Full Disk Access, an endpoint
// offline for more than a day.
func (s *Server) guideEndpoints(ctx context.Context) ([]guideItem, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	var out []guideItem
	byID := map[string]store.AgentRecord{}
	for _, a := range agents {
		byID[a.AgentID] = a
		if !a.Online && a.LastHeartbeat != nil && time.Since(*a.LastHeartbeat) > 24*time.Hour {
			out = append(out, guideItem{key: "offline:" + a.AgentID, kind: "observation", severity: "low",
				title:  a.Hostname + " has been offline for " + fmt.Sprintf("%d day(s)", int(time.Since(*a.LastHeartbeat).Hours()/24)),
				detail: "Last heard from " + a.LastHeartbeat.UTC().Format("2006-01-02 15:04") + " UTC. If it was decommissioned, remove it from inventory from its page.",
				link:   "/endpoint/" + a.AgentID})
		}
	}
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorPrivileges))
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		a, ok := byID[row.AgentID]
		if !ok || a.OS != "darwin" {
			continue
		}
		var infos []proto.PrivilegeInfo
		if json.Unmarshal(row.Data, &infos) != nil || len(infos) == 0 {
			var one proto.PrivilegeInfo
			if json.Unmarshal(row.Data, &one) != nil {
				continue
			}
			infos = []proto.PrivilegeInfo{one}
		}
		if !infos[0].FullDiskAccess {
			out = append(out, guideItem{key: "fda:" + a.AgentID, kind: "guidance", severity: "medium",
				title:  a.Hostname + " is missing Full Disk Access",
				detail: "macOS keeps Desktop, Documents, Downloads, Mail and Photos behind TCC even for root. Grant it under System Settings → Privacy & Security → Full Disk Access, or install the profile from Client Management.",
				link:   "/endpoint/" + a.AgentID + "#privileges"})
		}
	}
	return out, nil
}

func (s *Server) guideReveal(ctx context.Context) ([]guideItem, error) {
	sum, err := s.store.RevealSummary(ctx)
	if err != nil {
		return nil, err
	}
	if sum.ConfirmedFiles == 0 {
		return nil, nil
	}
	var parts []string
	names := map[string]string{}
	for _, p := range reveal.Builtin() {
		names[p.ID] = p.Name
	}
	keys := make([]string, 0, len(sum.ByPattern))
	for k := range sum.ByPattern {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return sum.ByPattern[keys[i]] > sum.ByPattern[keys[j]] })
	for i, k := range keys {
		if i == 4 {
			break
		}
		n := names[k]
		if n == "" {
			n = k
		}
		parts = append(parts, fmt.Sprintf("%s ×%d", n, sum.ByPattern[k]))
	}
	sev := "medium"
	if sum.ByPattern["credit_card"] > 0 || sum.ByPattern["ssn_us"] > 0 || sum.ByPattern["private_key"] > 0 || sum.ByPattern["aws_access_key"] > 0 {
		sev = "high"
	}
	return []guideItem{{key: "confirmed", kind: "observation", severity: sev, count: sum.ConfirmedFiles,
		title:  fmt.Sprintf("%d file(s) with confirmed sensitive data on %d endpoint(s)", sum.ConfirmedFiles, sum.EndpointsWithConfirmed),
		detail: strings.Join(parts, ", ") + ". Snippets are masked; the files are where the Results page says.", link: "/reveal#results"}}, nil
}

func (s *Server) guideImpact(ctx context.Context) ([]guideItem, error) {
	a, err := s.impactAnalysis(ctx, false)
	if err != nil {
		return nil, err
	}
	var out []guideItem
	for _, f := range a.Findings {
		if f.Severity != "critical" && f.Severity != "high" {
			continue
		}
		out = append(out, guideItem{key: f.SubjectKind + ":" + f.SubjectID + ":" + f.Category, kind: "guidance", severity: f.Severity, count: f.Count,
			title: f.SubjectName + ": " + strings.ToLower(f.Category[:1]) + f.Category[1:], detail: f.Detail, link: "/impact#findings"})
	}
	return out, nil
}

func (s *Server) guideDirectory(ctx context.Context) ([]guideItem, error) {
	_, view, err := s.directoryConfig(ctx)
	if err != nil {
		return nil, err
	}
	if view.LastError == "" {
		return nil, nil
	}
	return []guideItem{{key: "sync-failed", kind: "guidance", severity: "medium",
		title: "The directory sync is failing", detail: view.LastError + " Impact is using the directory as last synced.", link: "/settings#directory"}}, nil
}

func (s *Server) guideVulnerabilities(ctx context.Context) ([]guideItem, error) {
	rows, err := s.store.ListAllAgentVulnerabilities(ctx)
	if err != nil {
		return nil, err
	}
	hosts := map[string]int{}
	for _, r := range rows {
		if r.Suppressed || strings.ToLower(r.Severity) != "critical" {
			continue
		}
		hosts[r.Hostname]++
	}
	if len(hosts) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(hosts))
	for h := range hosts {
		names = append(names, h)
	}
	sort.Strings(names)
	shown := names
	if len(shown) > 6 {
		shown = shown[:6]
	}
	more := ""
	if len(names) > len(shown) {
		more = fmt.Sprintf(" and %d more", len(names)-len(shown))
	}
	return []guideItem{{key: "critical", kind: "guidance", severity: "high", count: len(hosts),
		title:  fmt.Sprintf("%d endpoint(s) have critical vulnerabilities the distribution has not waived", len(hosts)),
		detail: strings.Join(shown, ", ") + more + ". Patch lists what is pending; Risk & Compliance has the CVEs.", link: "/risk#vulns"}}, nil
}

// guideOSLifecycle: endpoints on an OS release past its end of life
// (guidance: upgrade it), and those whose support ends within 90 days.
func (s *Server) guideOSLifecycle(ctx context.Context) ([]guideItem, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ended, soon := map[string][]string{}, map[string][]string{}
	for _, a := range agents {
		sup, ok := s.osSupportFor(a.Platform, a.PlatformVersion, now)
		if !ok {
			continue
		}
		switch d := sup.daysLeft(now); {
		case sup.Ended:
			ended[sup.Release] = append(ended[sup.Release], a.Hostname)
		case d >= 0 && d <= 90:
			k := sup.Release + " (support ends " + sup.EOL.Format("2006-01-02") + ")"
			soon[k] = append(soon[k], a.Hostname)
		}
	}
	describe := func(m map[string][]string) (int, string) {
		var parts []string
		n := 0
		for _, rel := range sortedMapKeys(m) {
			hosts := m[rel]
			sort.Strings(hosts)
			n += len(hosts)
			parts = append(parts, rel+": "+strings.Join(hosts, ", "))
		}
		return n, strings.Join(parts, "; ")
	}
	var items []guideItem
	if n, detail := describe(ended); n > 0 {
		items = append(items, guideItem{key: "ended", kind: "guidance", severity: "high", count: n,
			title:  fmt.Sprintf("%d endpoint(s) run an OS release past its end of life", n),
			detail: detail + ". Their vulnerabilities will not be fixed for that release; upgrade it (the Upgrade OS release package).", link: "/risk#levels"})
	}
	if n, detail := describe(soon); n > 0 {
		items = append(items, guideItem{key: "ending", kind: "observation", severity: "medium", count: n,
			title:  fmt.Sprintf("%d endpoint(s) run an OS release whose support ends within 90 days", n),
			detail: detail + ".", link: "/risk#levels"})
	}
	return items, nil
}

func sortedMapKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---- API ----

// guideResponse is what GET /api/guide answers.
type guideResponse struct {
	Counts store.GuideCounts         `json:"counts"`
	Items  []store.GuideNotification `json:"items"`
}

func (s *Server) handleGuide(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1"
	items, err := s.store.ListGuide(r.Context(), all)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	counts, _ := s.store.GuideCounts(r.Context())
	writeJSONResponse(w, guideResponse{Items: items, Counts: counts})
}

func (s *Server) handleGuideDismiss(w http.ResponseWriter, r *http.Request) {
	who := auth.CurrentUser(r.Context()).Username
	undo := strings.HasSuffix(r.URL.Path, "/undismiss")
	ok, err := s.store.DismissGuide(r.Context(), r.PathValue("id"), who, !undo)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(204)
}

// handleGuideRefresh re-evaluates now, for the page's refresh button.
func (s *Server) handleGuideRefresh(w http.ResponseWriter, r *http.Request) {
	s.evaluateGuide(r.Context())
	s.handleGuide(w, r)
}
