package server

// Integrations: Mustra's events, as they happen, to the systems around it.
//
// Every audit event and every alert (a console notification) goes onto an
// in-memory queue; a worker delivers each to the enabled integrations that
// subscribe to its type at or above their minimum severity. Delivery never
// blocks the action that raised the event: a full queue drops and counts.
//
// Kinds: webhook (JSON, optionally HMAC-signed), slack, teams, discord,
// splunk_hec (HTTP Event Collector), loki (push API), servicenow (an
// incident per event) and prometheus, which receives nothing: it holds the
// token that /metrics accepts. Scheduled exports of answers stay in Connect,
// and the audit log's syslog forwarding in Logging.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

type integrationEvent struct {
	Type     string         `json:"type"` // audit, alert
	Time     time.Time      `json:"time"`
	Title    string         `json:"title"`
	Action   string         `json:"action,omitempty"`
	Actor    string         `json:"actor,omitempty"`
	Target   string         `json:"target,omitempty"`
	AgentID  string         `json:"agent_id,omitempty"`
	Severity string         `json:"severity"`
	Outcome  string         `json:"outcome,omitempty"`
	Body     string         `json:"body,omitempty"`
	Link     string         `json:"link,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
	// Actions are buttons for a request somebody has to decide (approve,
	// deny); their links open Mustra's /approve page, where the decision is
	// made signed in and under the usual permissions.
	Actions []eventAction `json:"actions,omitempty"`
}

var integrationKinds = map[string]string{
	"webhook":    "Webhook (JSON)",
	"slack":      "Slack",
	"teams":      "Microsoft Teams",
	"discord":    "Discord",
	"splunk_hec": "Splunk (HTTP Event Collector)",
	"loki":       "Grafana Loki",
	"servicenow": "ServiceNow (incidents)",
	"prometheus": "Prometheus (scrape token)",
}

var severityRank = map[string]int{"info": 0, "notice": 1, "warning": 2, "error": 3, "critical": 3}

type integrationBus struct {
	once    sync.Once
	queue   chan integrationEvent
	dropped atomic.Int64
	mu      sync.Mutex
	cache   []store.Integration
	cached  time.Time
}

func (s *Server) integrations() *integrationBus {
	s.integ.once.Do(func() { s.integ.queue = make(chan integrationEvent, 1000) })
	return &s.integ
}

// emitEvent queues an event for delivery and returns at once.
func (s *Server) emitEvent(ev integrationEvent) {
	b := s.integrations()
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	select {
	case b.queue <- ev:
	default:
		b.dropped.Add(1)
	}
}

type eventAction struct {
	Label string `json:"label"`
	Link  string `json:"link"`            // console path; made absolute when delivered
	Style string `json:"style,omitempty"` // primary, danger
}

func (s *Server) integrationLoop(ctx context.Context) {
	b := s.integrations()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-b.queue:
			for _, in := range s.cachedIntegrations(ctx) {
				// A request waiting on somebody's decision reaches every
				// channel taking alerts, whatever its severity threshold.
				if !in.Enabled || in.Kind == "prometheus" || !containsString(in.Events, ev.Type) {
					continue
				}
				// Expiry events are already chosen by their thresholds, so
				// they ignore the severity floor; an integration can narrow
				// them further to some thresholds (expiryWanted).
				if ev.Type == "expiry" {
					if !expiryWanted(in.Config["expiry_days"], ev) {
						continue
					}
				} else if len(ev.Actions) == 0 && severityRank[ev.Severity] < severityRank[in.MinSeverity] {
					continue
				}
				err := s.deliverEvent(ctx, in, ev)
				_ = s.store.RecordIntegrationResult(ctx, in.ID, err)
				if err != nil {
					s.logger.Warn("integration delivery failed", "integration", in.Name, "kind", in.Kind, "error", err)
				}
			}
		}
	}
}

func (s *Server) cachedIntegrations(ctx context.Context) []store.Integration {
	b := s.integrations()
	b.mu.Lock()
	defer b.mu.Unlock()
	if time.Since(b.cached) > 30*time.Second {
		if list, err := s.store.ListIntegrations(ctx); err == nil {
			b.cache, b.cached = list, time.Now()
		}
	}
	return b.cache
}

func (s *Server) forgetIntegrationCache() {
	b := s.integrations()
	b.mu.Lock()
	b.cached = time.Time{}
	b.mu.Unlock()
}

func (s *Server) integrationSecret(in store.Integration) (string, error) {
	if in.Secret == "" {
		return "", nil
	}
	return s.openSetting("integration/"+in.ID, in.Secret)
}

// eventText is the one-line human form chat and incidents use.
func eventText(ev integrationEvent) (title, body string) {
	title = ev.Title
	if ev.Type == "audit" {
		title = fmt.Sprintf("%s by %s", ev.Action, firstNonEmpty(ev.Actor, "mustra"))
		if ev.Target != "" {
			title += " on " + ev.Target
		}
		if ev.Outcome != "" && ev.Outcome != "ok" {
			title += " (" + ev.Outcome + ")"
		}
	}
	body = ev.Body
	if body == "" && len(ev.Detail) > 0 {
		b, _ := json.Marshal(ev.Detail)
		body = string(b)
	}
	return title, safeTruncate(body, 1500)
}

func (s *Server) eventLink(ctx context.Context, ev integrationEvent) string {
	if ev.Link == "" {
		return ""
	}
	if base, _ := s.agentPublicURLOrEmpty(ctx); base != "" {
		return strings.TrimRight(base, "/") + ev.Link
	}
	return ev.Link
}

func (s *Server) deliverEvent(ctx context.Context, in store.Integration, ev integrationEvent) error {
	secret, err := s.integrationSecret(in)
	if err != nil {
		return err
	}
	target := in.Config["url"]
	title, body := eventText(ev)
	link := s.eventLink(ctx, ev)
	sev := strings.ToUpper(ev.Severity)
	actions := make([]eventAction, 0, len(ev.Actions))
	for _, a := range ev.Actions {
		a.Link = s.eventLink(ctx, integrationEvent{Link: a.Link})
		actions = append(actions, a)
	}
	ev.Actions = actions
	switch in.Kind {
	case "webhook":
		if ev.Link != "" {
			ev.Link = link
		}
		raw, _ := json.Marshal(ev)
		h := map[string]string{"Content-Type": "application/json"}
		if secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(raw)
			h["X-Mustra-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		}
		return integrationPost(ctx, target, raw, h)
	case "slack":
		text := fmt.Sprintf("*[%s] %s*\n%s", sev, title, body)
		if len(actions) > 0 {
			// Link buttons work through an incoming webhook; no Slack app
			// or interactivity endpoint is needed.
			var buttons []map[string]any
			for i, a := range actions {
				btn := map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": a.Label}, "url": a.Link, "action_id": fmt.Sprintf("mustra_%d", i)}
				if a.Style == "primary" || a.Style == "danger" {
					btn["style"] = a.Style
				}
				buttons = append(buttons, btn)
			}
			return integrationPostJSON(ctx, target, map[string]any{"text": text, "blocks": []map[string]any{
				{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": safeTruncate(text, 2900)}},
				{"type": "actions", "elements": buttons},
			}}, nil)
		}
		if link != "" {
			text += "\n<" + link + "|Open in Mustra>"
		}
		return integrationPostJSON(ctx, target, map[string]any{"text": text}, nil)
	case "discord":
		text := fmt.Sprintf("**[%s] %s**\n%s", sev, title, body)
		if len(actions) > 0 {
			// A plain Discord webhook cannot carry buttons; links can.
			var parts []string
			for _, a := range actions {
				parts = append(parts, "["+a.Label+"]("+a.Link+")")
			}
			text += "\n" + strings.Join(parts, " · ")
		} else if link != "" {
			text += "\n" + link
		}
		return integrationPostJSON(ctx, target, map[string]any{"content": safeTruncate(text, 1900)}, nil)
	case "teams":
		blocks := []map[string]any{
			{"type": "TextBlock", "text": "[" + sev + "] " + title, "weight": "Bolder", "wrap": true},
			{"type": "TextBlock", "text": body, "wrap": true},
		}
		card := map[string]any{"type": "AdaptiveCard", "version": "1.4", "body": blocks}
		if len(actions) > 0 {
			var acts []map[string]any
			for _, a := range actions {
				act := map[string]any{"type": "Action.OpenUrl", "title": a.Label, "url": a.Link}
				if a.Style == "primary" {
					act["style"] = "positive"
				} else if a.Style == "danger" {
					act["style"] = "destructive"
				}
				acts = append(acts, act)
			}
			card["actions"] = acts
		} else if link != "" {
			card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open in Mustra", "url": link}}
		}
		return integrationPostJSON(ctx, target, map[string]any{"type": "message",
			"attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}}, nil)
	case "splunk_hec":
		u := strings.TrimRight(target, "/")
		if !strings.Contains(u, "/services/collector") {
			u += "/services/collector/event"
		}
		payload := map[string]any{"time": float64(ev.Time.UnixMilli()) / 1000, "source": "mustra",
			"sourcetype": "mustra:" + ev.Type, "event": ev}
		if idx := in.Config["index"]; idx != "" {
			payload["index"] = idx
		}
		return integrationPostJSON(ctx, u, payload, map[string]string{"Authorization": "Splunk " + secret})
	case "loki":
		u := strings.TrimRight(target, "/")
		if !strings.HasSuffix(u, "/loki/api/v1/push") {
			u += "/loki/api/v1/push"
		}
		line, _ := json.Marshal(ev)
		payload := map[string]any{"streams": []map[string]any{{
			"stream": map[string]string{"job": "mustra", "type": ev.Type, "severity": ev.Severity},
			"values": [][2]string{{fmt.Sprint(ev.Time.UnixNano()), string(line)}},
		}}}
		h := map[string]string{}
		if secret != "" {
			if user, pass, ok := strings.Cut(secret, ":"); ok {
				h["Authorization"] = "Basic " + basicAuth(user, pass)
			} else {
				h["Authorization"] = "Bearer " + secret
			}
		}
		return integrationPostJSON(ctx, u, payload, h)
	case "servicenow":
		user, pass, _ := strings.Cut(secret, ":")
		urgency := map[string]string{"critical": "1", "error": "1", "warning": "2"}[ev.Severity]
		if urgency == "" {
			urgency = "3"
		}
		inc := map[string]any{"short_description": safeTruncate("Mustra: "+title, 160), "urgency": urgency, "impact": urgency,
			"description": strings.TrimSpace(body + "\n\n" + link), "category": firstNonEmpty(in.Config["category"], "software")}
		if g := in.Config["assignment_group"]; g != "" {
			inc["assignment_group"] = g
		}
		// An expiry carries a stable id per item and expiry date, so a
		// ServiceNow rule can tell a repeat from a new one.
		if ev.Type == "expiry" {
			if k, _ := ev.Detail["key"].(string); k != "" {
				exp, _ := ev.Detail["expires_at"].(string)
				inc["correlation_id"] = safeTruncate("mustra:"+k+":"+exp, 100)
				inc["correlation_display"] = "Mustra"
			}
		}
		u := strings.TrimRight(target, "/") + "/api/now/table/incident"
		return integrationPostJSON(ctx, u, inc, map[string]string{"Authorization": "Basic " + basicAuth(user, pass), "Accept": "application/json"})
	}
	return fmt.Errorf("unknown integration kind %q", in.Kind)
}

// parseExpiryFilter normalises an integration's expiry thresholds: days
// from 1 to 365, and 0 or "expired" for expired.
func parseExpiryFilter(v string) (string, error) {
	seen := map[int]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		n := 0
		if !strings.EqualFold(f, "expired") {
			var err error
			if n, err = strconv.Atoi(f); err != nil || n < 0 || n > 365 {
				return "", fmt.Errorf("expiry thresholds are days from 1 to 365, or 0/expired: %q", f)
			}
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, strconv.Itoa(n))
		}
	}
	return strings.Join(out, ","), nil
}

// expiryWanted applies an integration's threshold filter ("60" or
// "60,7"; empty takes every threshold) to an expiry event: it is sent when
// it newly crossed any of them.
func expiryWanted(filter string, ev integrationEvent) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	want := map[int]bool{}
	for _, f := range strings.Split(filter, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			want[n] = true
		}
	}
	crossed, _ := ev.Detail["thresholds"].([]int)
	for _, t := range crossed {
		if want[t] {
			return true
		}
	}
	return false
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func integrationPostJSON(ctx context.Context, target string, payload any, headers map[string]string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"
	return integrationPost(ctx, target, raw, headers)
}

var integrationClient = &http.Client{Timeout: 15 * time.Second}

func integrationPost(ctx context.Context, target string, raw []byte, headers map[string]string) error {
	if u, err := url.Parse(target); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the integration has no valid URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mustra/"+version.Version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := integrationClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("%d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// --- API --------------------------------------------------------------------

// listIntegrationsResponse is what GET /api/admin/integrations answers.
type listIntegrationsResponse struct {
	Dropped      int64               `json:"dropped"`
	Integrations []store.Integration `json:"integrations"`
	Kinds        map[string]string   `json:"kinds"`
	Overview     map[string]any      `json:"overview"`
}

func (s *Server) handleListIntegrations(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListIntegrations(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listIntegrationsResponse{Integrations: list, Kinds: integrationKinds,
		Dropped: s.integrations().dropped.Load(), Overview: s.integrationOverview(r.Context())})
}

// integrationOverview reports the integrations configured elsewhere, so the
// Integrations page shows the whole picture in one place.
func (s *Server) integrationOverview(ctx context.Context) map[string]any {
	settings, _ := s.store.GetAllSettings(ctx)
	remote, _ := s.remoteConfig(ctx)
	exports, _ := s.store.ListExportConfigs(ctx)
	return map[string]any{
		"oidc":           len(s.auth.Providers()) > 0,
		"scim":           settings[settingSCIMToken] != "",
		"fleet_mdm":      settings[settingFleetURL] != "" && settings[settingFleetToken] != "",
		"entra":          settings[settingEntraSecret] != "",
		"remote":         map[string]any{"enabled": remoteReady(remote), "provider": remote.Provider},
		"private_ca":     settings[settingCACert] != "",
		"cloudflare":     settings[settingCFToken] != "",
		"connect":        len(exports),
		"syslog":         s.syslogEnabled(),
		"update_repo":    settings[settingUpdateRepo],
		"mdm_enroll_url": settings[settingMacMDMEnrollURL] != "",
	}
}

// saveIntegrationRequest is the body of POST /api/admin/integrations and
// PUT /api/admin/integrations/{id}.
type saveIntegrationRequest struct {
	store.Integration
	Secret *string `json:"secret" api:"writeonly"`
}

func (s *Server) handleSaveIntegration(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change integrations") {
		return
	}
	var body saveIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	in := body.Integration
	if id := r.PathValue("id"); id != "" {
		in.ID = id
	}
	if integrationKinds[in.Kind] == "" {
		http.Error(w, "unknown integration kind", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = integrationKinds[in.Kind]
	}
	if in.Config == nil {
		in.Config = map[string]string{}
	}
	if in.Kind != "prometheus" {
		if u, err := url.Parse(in.Config["url"]); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			http.Error(w, "a http(s) URL is required", http.StatusBadRequest)
			return
		}
	}
	for _, e := range in.Events {
		if e != "audit" && e != "alert" && e != "expiry" {
			http.Error(w, "events are audit, alert and/or expiry", http.StatusBadRequest)
			return
		}
	}
	if v := strings.TrimSpace(in.Config["expiry_days"]); v != "" {
		days, err := parseExpiryFilter(v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		in.Config["expiry_days"] = days
	}
	if len(in.Events) == 0 {
		in.Events = []string{"alert"}
	}
	if _, ok := severityRank[in.MinSeverity]; !ok {
		in.MinSeverity = "warning"
	}
	if in.ID == "" {
		in.ID = idgen.New("int-")
		in.CreatedBy = auth.CurrentUser(r.Context()).Username
	}
	var sealed *string
	if body.Secret != nil {
		v := ""
		if strings.TrimSpace(*body.Secret) != "" {
			var err error
			if v, err = s.sealSetting("integration/"+in.ID, strings.TrimSpace(*body.Secret)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		sealed = &v
	}
	if err := s.store.SaveIntegration(r.Context(), in, sealed); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.forgetIntegrationCache()
	s.audit(r.Context(), auditEvent{Action: "settings.integration", Actor: auth.CurrentUser(r.Context()).Username,
		Target: in.Name, Severity: "notice", Detail: map[string]any{"kind": in.Kind, "enabled": in.Enabled, "secret_changed": body.Secret != nil}})
	s.handleListIntegrations(w, r)
}

func (s *Server) handleDeleteIntegration(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change integrations") {
		return
	}
	if err := s.store.DeleteIntegration(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.forgetIntegrationCache()
	w.WriteHeader(http.StatusNoContent)
}

// testIntegrationResponse is what POST /api/admin/integrations/{id}/test
// answers.
type testIntegrationResponse struct {
	Result string `json:"result"`
}

// POST /api/admin/integrations/{id}/test sends one test event now.
func (s *Server) handleTestIntegration(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListIntegrations(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, in := range list {
		if in.ID != r.PathValue("id") {
			continue
		}
		if in.Kind == "prometheus" {
			writeJSONResponse(w, testIntegrationResponse{Result: "Prometheus scrapes /metrics with this token; nothing is sent."})
			return
		}
		err := s.deliverEvent(r.Context(), in, integrationEvent{Type: "alert", Time: time.Now().UTC(), Severity: "notice",
			Title: "Test from Mustra", Body: "If you can read this, " + integrationKinds[in.Kind] + " is connected.", Link: "/admin#integrations"})
		_ = s.store.RecordIntegrationResult(r.Context(), in.ID, err)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		writeJSONResponse(w, testIntegrationResponse{Result: "sent"})
		return
	}
	http.NotFound(w, r)
}

// --- Prometheus -------------------------------------------------------------

// handleMetrics serves fleet metrics in the Prometheus text format to a
// scraper holding a Prometheus integration's token (Authorization: Bearer).
// prometheusTokenOK reports whether the request carries the token of an
// enabled Prometheus integration: what /metrics and /metrics/endpoints ask.
func (s *Server) prometheusTokenOK(r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	for _, in := range s.cachedIntegrations(r.Context()) {
		if in.Kind != "prometheus" || !in.Enabled {
			continue
		}
		if want, err := s.integrationSecret(in); err == nil && want != "" && hmac.Equal([]byte(want), []byte(token)) {
			return true
		}
	}
	return false
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.prometheusTokenOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	var b strings.Builder
	gauge := func(name, help string) { fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name) }
	label := func(v string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ").Replace(v) }

	gauge("mustra_build_info", "The running server build.")
	fmt.Fprintf(&b, "mustra_build_info{version=\"%s\"} 1\n", label(version.Version))

	agents, _ := s.store.ListAgents(ctx, s.staleAfter())
	byOS := map[[2]string]int{}
	versions := map[string]int{}
	for _, a := range agents {
		os := a.OS
		if a.Platform == "haos" {
			os = "haos"
		}
		byOS[[2]string{os, fmt.Sprint(a.Online)}]++
		versions[a.AgentVersion]++
	}
	gauge("mustra_agents", "Endpoints by operating system and whether they are online.")
	for _, k := range sortedPairs(byOS) {
		fmt.Fprintf(&b, "mustra_agents{os=\"%s\",online=\"%s\"} %d\n", label(k[0]), k[1], byOS[k])
	}
	gauge("mustra_agent_versions", "Endpoints by agent version.")
	for _, v := range sortedKeys(versions) {
		fmt.Fprintf(&b, "mustra_agent_versions{version=\"%s\"} %d\n", label(v), versions[v])
	}

	if rows, err := s.store.ListSensorDataForSensor(ctx, "patches"); err == nil {
		total, withPending := 0, 0
		for _, row := range rows {
			var list []json.RawMessage
			_ = json.Unmarshal(row.Data, &list)
			total += len(list)
			if len(list) > 0 {
				withPending++
			}
		}
		gauge("mustra_patches_pending", "Pending patches summed over endpoints.")
		fmt.Fprintf(&b, "mustra_patches_pending %d\n", total)
		gauge("mustra_endpoints_with_pending_patches", "Endpoints with at least one pending patch.")
		fmt.Fprintf(&b, "mustra_endpoints_with_pending_patches %d\n", withPending)
	}
	if open, err := s.store.OpenPatchJobs(ctx); err == nil {
		gauge("mustra_patch_jobs_open", "Endpoints with a patch job still running.")
		fmt.Fprintf(&b, "mustra_patch_jobs_open %d\n", len(open))
	}
	if cov, err := s.store.SensorCoverage(ctx); err == nil {
		gauge("mustra_sensor_reporting", "Endpoints reporting each sensor.")
		for _, c := range cov {
			fmt.Fprintf(&b, "mustra_sensor_reporting{sensor=\"%s\"} %d\n", label(c.Sensor), c.Agents)
		}
		gauge("mustra_sensor_stale", "Endpoints whose last collection of a sensor is over an hour old.")
		for _, c := range cov {
			fmt.Fprintf(&b, "mustra_sensor_stale{sensor=\"%s\"} %d\n", label(c.Sensor), c.Stale)
		}
	}
	if mcs, err := s.store.ListManagedCerts(ctx); err == nil {
		gauge("mustra_managed_certificate_expiry_timestamp_seconds", "When each managed certificate expires.")
		for _, m := range mcs {
			if m.ExpiresAt != nil {
				fmt.Fprintf(&b, "mustra_managed_certificate_expiry_timestamp_seconds{name=\"%s\",host=\"%s\",state=\"%s\"} %d\n",
					label(m.Name), label(m.Hostname), label(m.State), m.ExpiresAt.Unix())
			}
		}
	}
	if guests, err := s.backupStatuses(ctx); err == nil {
		gauge("mustra_backup_age_hours", "Hours since each Proxmox guest's newest backup (absent when it has none).")
		states := map[string]int{"ok": 0, "overdue": 0, "never": 0, "not_covered": 0}
		for _, g := range guests {
			states[g.State]++
			if g.AgeHours != nil {
				fmt.Fprintf(&b, "mustra_backup_age_hours{guest=\"%s\",vmid=\"%d\",node=\"%s\",endpoint=\"%s\"} %.2f\n",
					label(g.Name), g.VMID, label(g.Node), label(g.Hostname), *g.AgeHours)
			}
		}
		gauge("mustra_backup_guests", "Proxmox guests by backup state.")
		for _, k := range sortedKeys(states) {
			fmt.Fprintf(&b, "mustra_backup_guests{state=\"%s\"} %d\n", k, states[k])
		}
	}
	if devices, err := s.store.ListNetworkDevices(ctx); err == nil {
		managed := map[string]bool{}
		if hosts, _, _, err := s.discoverHosts(ctx); err == nil {
			for _, h := range hosts {
				managed[h.MAC] = h.Managed
			}
		}
		unmanaged, fresh := 0, 0
		for _, d := range devices {
			if d.Ignored {
				continue
			}
			if !managed[d.MAC] && time.Since(d.LastSeen) < 24*time.Hour {
				unmanaged++
			}
			if !d.Baseline && time.Since(d.FirstSeen) < 24*time.Hour {
				fresh++
			}
		}
		gauge("mustra_network_devices", "Devices seen in endpoints' neighbour tables.")
		fmt.Fprintf(&b, "mustra_network_devices %d\n", len(devices))
		gauge("mustra_network_devices_unmanaged", "Devices seen in the last day that Mustra does not manage (ignored ones excluded).")
		fmt.Fprintf(&b, "mustra_network_devices_unmanaged %d\n", unmanaged)
		gauge("mustra_network_devices_new", "Devices first seen in the last day.")
		fmt.Fprintf(&b, "mustra_network_devices_new %d\n", fresh)
	}
	if roots, err := s.trustRoots(ctx); err == nil {
		gauge("mustra_trusted_root_endpoints", "Endpoints by state for each pushed root certificate.")
		for _, root := range roots {
			states, err := s.store.ListRootTrust(ctx, root.Fingerprint)
			if err != nil {
				continue
			}
			count := map[string]int{}
			for _, st := range states {
				count[firstNonEmpty(st.State, "pending")]++
			}
			for _, k := range sortedKeys(count) {
				fmt.Fprintf(&b, "mustra_trusted_root_endpoints{root=\"%s\",state=\"%s\"} %d\n", label(root.Name), k, count[k])
			}
		}
	}
	gauge("mustra_integration_events_dropped", "Events dropped because the delivery queue was full.")
	fmt.Fprintf(&b, "mustra_integration_events_dropped %d\n", s.integrations().dropped.Load())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = io.WriteString(w, b.String())
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPairs(m map[[2]string]int) [][2]string {
	out := make([][2]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0]+out[i][1] < out[j][0]+out[j][1] })
	return out
}

func (s *Server) syslogEnabled() bool {
	s.syslog.mu.RLock()
	defer s.syslog.mu.RUnlock()
	return s.syslog.enabled
}
