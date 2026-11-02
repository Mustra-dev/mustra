package server

// Expiry alerts (Cert Manager → Alerts). Hourly, every certificate and
// credential with an expiry is checked against the alert thresholds (60,
// 30, 14, 7 and 1 days by default, and "expired"). Each threshold an item
// crosses is announced once: a console notification, and an "expiry" event
// for the integrations that take it — Teams, Discord, Slack, a webhook for
// automations, a ServiceNow incident. An item first seen inside several
// thresholds is announced once, naming all of them. A renewal gives the
// item a new expiry, and its thresholds start over.
//
// The event's detail is meant for automations: a stable key, what kind of
// item it is, where it lives, the expiry, the days left and the thresholds
// crossed. An integration can also take only some thresholds (a ServiceNow
// integration that opens one incident at 60 days, say).

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingExpiryThresholds = "certs.expiry_thresholds"
	settingExpirySources    = "certs.expiry_sources"
	defaultExpiryThresholds = "60,30,14,7,1"
	defaultExpirySources    = "managed,fleet,apps"
)

// expiringItem is one thing that expires.
type expiringItem struct {
	Key       string    `json:"key"`
	Type      string    `json:"item_type"` // managed_certificate, certificate, app_credential, app_credential_rotation
	Name      string    `json:"name"`
	Where     string    `json:"where"`
	ExpiresAt time.Time `json:"expires_at"`
	Link      string    `json:"link"`
	// Extra is what this kind of item adds: issuer and fingerprint for a
	// fleet certificate, authority for a managed one, provider and mode
	// for an app credential. Sent as "Extra" before #86.
	Extra map[string]any `json:"extra"`
}

// parseThresholds reads "60,30,14" into sorted, distinct days, largest
// first; 0 ("expired") is always included.
func parseThresholds(v string) []int {
	seen := map[int]bool{0: true}
	out := []int{0}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 365 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

// daysLeft rounds up: a certificate expiring in 29 days and an hour has 30
// days left, the way people count.
func daysLeft(exp, now time.Time) int {
	return int(math.Ceil(exp.Sub(now).Hours() / 24))
}

// crossedThresholds are the thresholds an item with this many days left
// is inside (0 only once it has expired).
func crossedThresholds(thresholds []int, left int) []int {
	var out []int
	for _, th := range thresholds {
		if (th == 0 && left <= 0) || (th > 0 && left <= th) {
			out = append(out, th)
		}
	}
	return out
}

func expirySeverity(left int) string {
	switch {
	case left <= 7:
		return "critical"
	case left <= 30:
		return "warning"
	}
	return "notice"
}

// expiringItems gathers everything with an expiry from the chosen sources.
func (s *Server) expiringItems(ctx context.Context, sources map[string]bool) []expiringItem {
	var items []expiringItem
	managedPaths := map[string]bool{}
	if mcs, err := s.store.ListManagedCerts(ctx); err == nil {
		for _, m := range mcs {
			managedPaths[m.AgentID+"|"+m.CertPath] = true
			if !sources["managed"] || m.ExpiresAt == nil {
				continue
			}
			items = append(items, expiringItem{Key: "mc:" + m.ID, Type: "managed_certificate", Name: m.Name,
				Where: firstNonEmpty(m.Hostname, m.AgentID) + " " + m.CertPath, ExpiresAt: *m.ExpiresAt, Link: "/certificates#renewal",
				Extra: map[string]any{"authority": certCAs[m.CA], "renews_automatically": m.Enabled, "agent_id": m.AgentID}})
		}
	}
	if sources["fleet"] {
		if rows, err := s.certificateRows(ctx); err == nil {
			for _, c := range rows {
				if c.TrustStore || c.IsCA {
					continue
				}
				exp, err := time.Parse(time.RFC3339, c.NotAfter)
				if err != nil {
					continue
				}
				var hosts []string
				managed := false
				for _, l := range c.Locations {
					hosts = append(hosts, l.Hostname)
					managed = managed || managedPaths[l.AgentID+"|"+l.Path]
				}
				// A managed certificate is announced as such, once.
				if managed && sources["managed"] {
					continue
				}
				items = append(items, expiringItem{Key: "fp:" + c.Fingerprint, Type: "certificate", Name: firstNonEmpty(c.Subject, "(no common name)"),
					Where: strings.Join(uniqueStrings(hosts), ", "), ExpiresAt: exp, Link: "/certificates#overview",
					Extra: map[string]any{"issuer": c.Issuer, "self_signed": c.SelfSigned, "dns_names": c.DNSNames, "fingerprint": c.Fingerprint}})
			}
		}
	}
	if sources["apps"] {
		if creds, err := s.store.ListAppCredentials(ctx); err == nil {
			for _, c := range creds {
				typ, exp := "app_credential", c.ExpiresAt
				if exp == nil {
					// A secret that never expires is announced as its rotation falls due.
					if due := dueAt(c); due != nil && c.RotateDays > 0 {
						d := due.Add(time.Duration(c.RenewDays) * 24 * time.Hour)
						exp, typ = &d, "app_credential_rotation"
					}
				}
				if exp == nil {
					continue
				}
				items = append(items, expiringItem{Key: "ac:" + c.ID + ":" + c.ExternalID, Type: typ,
					Name: c.AppName + " · " + appCredTypes[c.CredType], Where: appCredKinds[c.Kind], ExpiresAt: *exp, Link: "/certificates#apps",
					Extra: map[string]any{"provider": appCredKinds[c.Kind], "credential_type": c.CredType, "mode": c.Mode}})
			}
		}
	}
	return items
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) expirySettings(ctx context.Context) ([]int, map[string]bool) {
	settings, _ := s.store.GetAllSettings(ctx)
	th := settings[settingExpiryThresholds]
	if th == "" {
		th = defaultExpiryThresholds
	}
	src := settings[settingExpirySources]
	if src == "" {
		src = defaultExpirySources
	}
	sources := map[string]bool{}
	for _, v := range strings.Split(src, ",") {
		sources[strings.TrimSpace(v)] = true
	}
	return parseThresholds(th), sources
}

// expiryAlertLoop runs the check hourly.
func (s *Server) expiryAlertLoop(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		s.checkExpiryAlerts(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) checkExpiryAlerts(ctx context.Context) {
	thresholds, sources := s.expirySettings(ctx)
	if sources["off"] {
		return
	}
	sent, err := s.store.SentExpiryThresholds(ctx)
	if err != nil {
		return
	}
	now := time.Now()
	for _, it := range s.expiringItems(ctx, sources) {
		left := daysLeft(it.ExpiresAt, now)
		// Long expired is old news, not an alert.
		if left < -30 {
			continue
		}
		done := sent[it.Key+"|"+it.ExpiresAt.UTC().Format(time.RFC3339)]
		var fresh []int
		for _, th := range crossedThresholds(thresholds, left) {
			if !done[th] {
				fresh = append(fresh, th)
			}
		}
		if len(fresh) == 0 {
			continue
		}
		s.announceExpiry(ctx, it, left, fresh)
		_ = s.store.RecordExpiryAlerts(ctx, it.Key, it.ExpiresAt, fresh, it.Name, left)
	}
}

// expiryTitle says it the way a person would.
func expiryTitle(it expiringItem, left int) string {
	what := map[string]string{"managed_certificate": "Certificate", "certificate": "Certificate",
		"app_credential": "App credential", "app_credential_rotation": "App credential rotation"}[it.Type]
	switch {
	case left < 0:
		return fmt.Sprintf("%s expired %d day(s) ago: %s", what, -left, it.Name)
	case left == 0:
		// Days round up, so none left means it has just gone.
		return fmt.Sprintf("%s expired today: %s", what, it.Name)
	case it.Type == "app_credential_rotation":
		return fmt.Sprintf("%s due in %d day(s): %s", what, left, it.Name)
	}
	return fmt.Sprintf("%s expires in %d day(s): %s", what, left, it.Name)
}

// announceExpiry raises the console notification and the expiry event.
func (s *Server) announceExpiry(ctx context.Context, it expiringItem, left int, thresholds []int) {
	title := expiryTitle(it, left)
	body := fmt.Sprintf("%s · expires %s", it.Where, it.ExpiresAt.UTC().Format("2006-01-02"))
	sev := expirySeverity(left)
	detail := map[string]any{"key": it.Key, "item_type": it.Type, "name": it.Name, "where": it.Where,
		"expires_at": it.ExpiresAt.UTC().Format(time.RFC3339), "days_left": left, "thresholds": thresholds,
		"threshold": thresholds[len(thresholds)-1], "source": "Certificates"}
	for k, v := range it.Extra {
		detail[k] = v
	}
	// The console's own copy; integrations get the expiry event below, not
	// a second "alert" one.
	n := store.Notification{ID: idgen.New("ntf-"), Severity: sev, Title: title, Body: body, Source: "Certificates", Link: it.Link}
	if err := s.store.CreateNotification(ctx, n); err != nil {
		s.logger.Warn("could not raise expiry notification", "title", title, "error", err)
	} else {
		go s.fireEventTriggers(context.WithoutCancel(ctx), n) // playbooks can start on it too
	}
	s.emitEvent(integrationEvent{Type: "expiry", Title: title, Body: body, Severity: sev, Link: it.Link, Detail: detail})
}

// --- API --------------------------------------------------------------------

// expiryAlertIntegration is an entry of what GET /api/certificates/alerts
// answers.
type expiryAlertIntegration struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Only    string `json:"only_days,omitempty"`
}

// upcomingExpiry is an entry of what GET /api/certificates/alerts answers.
type upcomingExpiry struct {
	expiringItem
	DaysLeft int `json:"days_left"`
}

// getExpiryAlertsResponse is what GET /api/certificates/alerts answers.
type getExpiryAlertsResponse struct {
	Effective    []int                    `json:"effective"`
	Integrations []expiryAlertIntegration `json:"integrations"`
	Recent       []store.ExpiryAlert      `json:"recent"`
	Sources      []string                 `json:"sources"`
	Thresholds   string                   `json:"thresholds"`
	Upcoming     []upcomingExpiry         `json:"upcoming"`
}

// GET /api/certificates/alerts
func (s *Server) handleGetExpiryAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	settings, _ := s.store.GetAllSettings(ctx)
	recent, _ := s.store.RecentExpiryAlerts(ctx, 25)
	ints, _ := s.store.ListIntegrations(ctx)
	subs := []expiryAlertIntegration{}
	for _, in := range ints {
		if containsString(in.Events, "expiry") {
			subs = append(subs, expiryAlertIntegration{in.Name, integrationKinds[in.Kind], in.Enabled, in.Config["expiry_days"]})
		}
	}
	th := firstNonEmpty(settings[settingExpiryThresholds], defaultExpiryThresholds)
	src := firstNonEmpty(settings[settingExpirySources], defaultExpirySources)
	// What is coming up, for the page: the next 20 by expiry.
	thresholds, sources := s.expirySettings(ctx)
	items := s.expiringItems(ctx, sources)
	sort.Slice(items, func(i, j int) bool { return items[i].ExpiresAt.Before(items[j].ExpiresAt) })
	var next []upcomingExpiry
	now := time.Now()
	for _, it := range items {
		if l := daysLeft(it.ExpiresAt, now); l >= -30 && len(next) < 20 {
			next = append(next, upcomingExpiry{it, l})
		}
	}
	writeJSONResponse(w, getExpiryAlertsResponse{Thresholds: th, Effective: thresholds, Sources: strings.Split(src, ","),
		Integrations: subs, Recent: recent, Upcoming: next})
}

// saveExpiryAlertsRequest is the body of POST /api/certificates/alerts.
type saveExpiryAlertsRequest struct {
	Thresholds string   `json:"thresholds" api:"required"`
	Sources    []string `json:"sources"`
}

// saveExpiryAlertsResponse is what POST /api/certificates/alerts answers.
type saveExpiryAlertsResponse struct {
	Sources    []string `json:"sources"`
	Thresholds string   `json:"thresholds"`
}

// POST /api/certificates/alerts {thresholds, sources}
func (s *Server) handleSaveExpiryAlerts(w http.ResponseWriter, r *http.Request) {
	var body saveExpiryAlertsRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	th := parseThresholds(body.Thresholds)
	if len(th) < 2 {
		http.Error(w, "give at least one threshold, in days between 1 and 365", http.StatusBadRequest)
		return
	}
	var parts []string
	for _, t := range th {
		if t > 0 {
			parts = append(parts, strconv.Itoa(t))
		}
	}
	var src []string
	for _, v := range body.Sources {
		if v == "managed" || v == "fleet" || v == "apps" {
			src = append(src, v)
		}
	}
	if len(src) == 0 {
		src = []string{"off"}
	}
	who := auth.CurrentUser(r.Context()).Username
	if err := s.store.SetSetting(r.Context(), settingExpiryThresholds, strings.Join(parts, ","), who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.SetSetting(r.Context(), settingExpirySources, strings.Join(src, ","), who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "certs.expiry_alerts", Actor: who, Target: "expiry alerts", Severity: "notice",
		Detail: map[string]any{"thresholds": parts, "sources": src}})
	go s.checkExpiryAlerts(context.WithoutCancel(r.Context()))
	writeJSONResponse(w, saveExpiryAlertsResponse{Thresholds: strings.Join(parts, ","), Sources: src})
}

// testExpiryAlertResponse is what POST /api/certificates/alerts/test
// answers.
type testExpiryAlertResponse struct {
	OK bool `json:"ok"`
}

// POST /api/certificates/alerts/test: one sample expiry event to every
// integration that takes them, so a channel or an automation can be
// checked without waiting for a real expiry.
func (s *Server) handleTestExpiryAlert(w http.ResponseWriter, r *http.Request) {
	exp := time.Now().Add(60 * 24 * time.Hour)
	s.emitEvent(integrationEvent{Type: "expiry", Title: "Test: Certificate expires in 60 day(s): test.example.com", Severity: "notice",
		Body: "web01 /etc/nginx/ssl/test.crt · expires " + exp.UTC().Format("2006-01-02") + " (a test from Cert Manager → Alerts)",
		Link: "/certificates#alerts", Detail: map[string]any{"key": "test:expiry", "item_type": "certificate", "name": "test.example.com",
			"where": "web01 /etc/nginx/ssl/test.crt", "expires_at": exp.UTC().Format(time.RFC3339), "days_left": 60,
			"thresholds": []int{60}, "threshold": 60, "source": "Certificates", "test": true}})
	writeJSONResponse(w, testExpiryAlertResponse{OK: true})
}
