package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/impact"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/directory"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
)

// Impact: who can reach what, if an account or endpoint is compromised.
//
// Two inputs, one graph. The directory (Administration → Directory) gives
// users, groups and nested membership; every endpoint's local_admins and
// users sensors give who can administer it and who is signed in. The
// engine in internal/impact walks the result; this file feeds it and
// serves what it finds.

// Directory settings. The bind password is stored as the SCIM and update
// tokens are -- in the settings table -- and never returned to the
// console; the view says only whether one is set.
const (
	settingDirectoryURL                = "directory.url"
	settingDirectoryBindDN             = "directory.bind_dn"
	settingDirectoryBindPassword       = "directory.bind_password"
	settingDirectoryBaseDN             = "directory.base_dn"
	settingDirectoryStartTLS           = "directory.starttls"
	settingDirectoryInsecureSkipVerify = "directory.insecure_skip_verify"
	settingDirectoryAllowInsecure      = "directory.allow_insecure"
	settingDirectoryCAPEM              = "directory.ca_pem"
	settingDirectoryEnabled            = "directory.enabled"
	settingDirectoryIntervalMinutes    = "directory.interval_minutes"
	settingDirectoryLastSync           = "directory.last_sync"
	settingDirectoryLastError          = "directory.last_error"
	settingDirectoryLastSummary        = "directory.last_summary"
	// The synced domain's names, kept so remote sessions can pre-fill the
	// short (NetBIOS) form people type at a Windows sign-in.
	settingDirectoryDNSName     = "directory.dns_name"
	settingDirectoryNetBIOSName = "directory.netbios_name"
)

type directoryView struct {
	URL                string                `json:"url"`
	BindDN             string                `json:"bind_dn"`
	PasswordSet        bool                  `json:"password_set"`
	BaseDN             string                `json:"base_dn"`
	StartTLS           bool                  `json:"starttls"`
	InsecureSkipVerify bool                  `json:"insecure_skip_verify"`
	AllowInsecure      bool                  `json:"allow_insecure"`
	CAPEM              string                `json:"ca_pem"`
	Enabled            bool                  `json:"enabled"`
	IntervalMinutes    int                   `json:"interval_minutes"`
	LastSync           string                `json:"last_sync,omitempty"`
	LastError          string                `json:"last_error,omitempty"`
	LastSummary        string                `json:"last_summary,omitempty"`
	Counts             store.DirectoryCounts `json:"counts"`
}

func (s *Server) directoryConfig(ctx context.Context) (directory.Config, directoryView, error) {
	m, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return directory.Config{}, directoryView{}, err
	}
	interval, _ := strconv.Atoi(m[settingDirectoryIntervalMinutes])
	if interval <= 0 {
		interval = 60
	}
	bindPassword, err := openWith(s.vault, vault.SettingAAD(settingDirectoryBindPassword), m[settingDirectoryBindPassword])
	if err != nil {
		return directory.Config{}, directoryView{}, fmt.Errorf("directory bind password: %w", err)
	}
	cfg := directory.Config{
		URL: m[settingDirectoryURL], BindDN: m[settingDirectoryBindDN], BindPassword: bindPassword,
		BaseDN: m[settingDirectoryBaseDN], StartTLS: m[settingDirectoryStartTLS] == "true",
		InsecureSkipVerify: m[settingDirectoryInsecureSkipVerify] == "true", AllowInsecure: m[settingDirectoryAllowInsecure] == "true",
		CAPEM: m[settingDirectoryCAPEM],
	}
	allowed := s.webhookAllowedHosts(ctx)
	cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return guardedDial(ctx, network, addr, allowed, 30*time.Second)
	}
	view := directoryView{
		URL: cfg.URL, BindDN: cfg.BindDN, PasswordSet: cfg.BindPassword != "", BaseDN: cfg.BaseDN,
		StartTLS: cfg.StartTLS, InsecureSkipVerify: cfg.InsecureSkipVerify, AllowInsecure: cfg.AllowInsecure, CAPEM: cfg.CAPEM,
		Enabled: m[settingDirectoryEnabled] == "true", IntervalMinutes: interval,
		LastSync: m[settingDirectoryLastSync], LastError: m[settingDirectoryLastError], LastSummary: m[settingDirectoryLastSummary],
	}
	view.Counts, _ = s.store.DirectoryCounts(ctx)
	return cfg, view, nil
}

func (s *Server) handleDirectorySettings(w http.ResponseWriter, r *http.Request) {
	_, view, err := s.directoryConfig(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSONResponse(w, view)
}

type directoryUpdate struct {
	URL                *string `json:"url"`
	BindDN             *string `json:"bind_dn"`
	BindPassword       *string `json:"bind_password" api:"writeonly"` // empty keeps the stored one
	BaseDN             *string `json:"base_dn"`
	StartTLS           *bool   `json:"starttls"`
	InsecureSkipVerify *bool   `json:"insecure_skip_verify"`
	AllowInsecure      *bool   `json:"allow_insecure"`
	CAPEM              *string `json:"ca_pem"`
	Enabled            *bool   `json:"enabled"`
	IntervalMinutes    *int    `json:"interval_minutes"`
}

// directoryPasswordMoves reports what in req would send the stored bind
// password somewhere, or some way, it has not been sent before: another
// server, or weaker transport security. Such a change has to come with
// the password typed again. Kept, the stored one let anyone allowed to
// edit the directory settings point them at a host of their own (with
// plain LDAP allowed) and read the service account's password off the
// wire at the next test or sync.
func directoryPasswordMoves(stored directory.Config, req directoryUpdate) string {
	if req.BindPassword != nil && *req.BindPassword != "" {
		return ""
	}
	if req.URL != nil && !sameLDAPEndpoint(stored.URL, strings.TrimSpace(*req.URL)) {
		return "the server"
	}
	if req.AllowInsecure != nil && *req.AllowInsecure && !stored.AllowInsecure {
		return "allowing plain LDAP"
	}
	if req.InsecureSkipVerify != nil && *req.InsecureSkipVerify && !stored.InsecureSkipVerify {
		return "skipping certificate verification"
	}
	if req.StartTLS != nil && !*req.StartTLS && stored.StartTLS {
		return "turning StartTLS off"
	}
	if req.CAPEM != nil && strings.TrimSpace(*req.CAPEM) != strings.TrimSpace(stored.CAPEM) {
		return "the trusted certificate authority"
	}
	return ""
}

// sameLDAPEndpoint compares two directory URLs by scheme, host and port.
func sameLDAPEndpoint(a, b string) bool {
	norm := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"ldap": "389", "ldaps": "636"}[u.Scheme]
		}
		return u.Scheme + "://" + strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")) + ":" + port
	}
	return norm(a) == norm(b)
}

func (s *Server) handleUpdateDirectorySettings(w http.ResponseWriter, r *http.Request) {
	var req directoryUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), 400)
		return
	}
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	stored, _, err := s.directoryConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if stored.BindPassword != "" {
		if what := directoryPasswordMoves(stored, req); what != "" {
			http.Error(w, "changing "+what+" needs the bind password entered again", 400)
			return
		}
	}
	set := func(key string, v *string) error {
		if v == nil {
			return nil
		}
		return s.store.SetSetting(ctx, key, strings.TrimSpace(*v), who)
	}
	setBool := func(key string, v *bool) error {
		if v == nil {
			return nil
		}
		return s.store.SetSetting(ctx, key, strconv.FormatBool(*v), who)
	}
	if req.URL != nil && *req.URL != "" && !strings.HasPrefix(*req.URL, "ldap://") && !strings.HasPrefix(*req.URL, "ldaps://") {
		http.Error(w, "the directory URL must start with ldap:// or ldaps://", 400)
		return
	}
	if req.IntervalMinutes != nil && (*req.IntervalMinutes < 5 || *req.IntervalMinutes > 1440) {
		http.Error(w, "interval_minutes must be between 5 and 1440", 400)
		return
	}
	for _, e := range []error{
		set(settingDirectoryURL, req.URL), set(settingDirectoryBindDN, req.BindDN), set(settingDirectoryBaseDN, req.BaseDN), set(settingDirectoryCAPEM, req.CAPEM),
		setBool(settingDirectoryStartTLS, req.StartTLS), setBool(settingDirectoryInsecureSkipVerify, req.InsecureSkipVerify),
		setBool(settingDirectoryAllowInsecure, req.AllowInsecure), setBool(settingDirectoryEnabled, req.Enabled),
	} {
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
	}
	if req.BindPassword != nil && *req.BindPassword != "" {
		sealed, err := sealWith(s.vault, vault.SettingAAD(settingDirectoryBindPassword), *req.BindPassword)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := s.store.SetSetting(ctx, settingDirectoryBindPassword, sealed, who); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	if req.IntervalMinutes != nil {
		if err := s.store.SetSetting(ctx, settingDirectoryIntervalMinutes, strconv.Itoa(*req.IntervalMinutes), who); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	s.audit(ctx, auditEvent{Action: "directory.settings", Actor: who, Severity: "notice", Target: "directory"})
	_, view, err := s.directoryConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSONResponse(w, view)
}

// directoryTestResponse is what POST /api/directory/test answers when the
// bind works.
type directoryTestResponse struct {
	Info string `json:"info"`
	OK   bool   `json:"ok"`
}

// directoryTestFailure is what POST /api/directory/test answers when the
// bind fails: still a 200, since the test itself ran.
type directoryTestFailure struct {
	Error string `json:"error"`
	OK    bool   `json:"ok"`
}

// handleDirectoryTest binds with what is on the form, falling back to the
// stored password so "test" works without retyping it.
func (s *Server) handleDirectoryTest(w http.ResponseWriter, r *http.Request) {
	var req directoryUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), 400)
		return
	}
	cfg, _, err := s.directoryConfig(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// The stored password is only tried against the server, and with the
	// transport security, it was saved for.
	if cfg.BindPassword != "" {
		if what := directoryPasswordMoves(cfg, req); what != "" {
			http.Error(w, "testing with a change to "+what+" needs the bind password entered", 400)
			return
		}
	}
	if req.URL != nil {
		cfg.URL = strings.TrimSpace(*req.URL)
	}
	if req.BindDN != nil {
		cfg.BindDN = strings.TrimSpace(*req.BindDN)
	}
	if req.BaseDN != nil {
		cfg.BaseDN = strings.TrimSpace(*req.BaseDN)
	}
	if req.BindPassword != nil && *req.BindPassword != "" {
		cfg.BindPassword = *req.BindPassword
	}
	if req.StartTLS != nil {
		cfg.StartTLS = *req.StartTLS
	}
	if req.InsecureSkipVerify != nil {
		cfg.InsecureSkipVerify = *req.InsecureSkipVerify
	}
	if req.AllowInsecure != nil {
		cfg.AllowInsecure = *req.AllowInsecure
	}
	if req.CAPEM != nil {
		cfg.CAPEM = *req.CAPEM
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	info, err := directory.Test(ctx, cfg)
	if err != nil {
		writeJSONResponse(w, directoryTestFailure{OK: false, Error: err.Error()})
		return
	}
	writeJSONResponse(w, directoryTestResponse{OK: true, Info: info})
}

func (s *Server) handleDirectorySync(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	summary, err := s.runDirectorySync(ctx, auth.CurrentUser(r.Context()).Username)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	_, view, verr := s.directoryConfig(r.Context())
	if verr != nil {
		http.Error(w, verr.Error(), 500)
		return
	}
	view.LastSummary = summary
	writeJSONResponse(w, view)
}

// runDirectorySync reads the domain and swaps the cache. The outcome is
// recorded either way, so the settings page can say when it last worked
// and why it last did not.
func (s *Server) runDirectorySync(ctx context.Context, who string) (string, error) {
	cfg, _, err := s.directoryConfig(ctx)
	if err != nil {
		return "", err
	}
	res, err := directory.Sync(ctx, cfg)
	if err != nil {
		_ = s.store.SetSetting(ctx, settingDirectoryLastError, err.Error(), who)
		s.logger.Warn("directory sync failed", "error", err)
		return "", err
	}
	if err := s.store.ReplaceDirectory(ctx, res.Objects, res.Members); err != nil {
		_ = s.store.SetSetting(ctx, settingDirectoryLastError, err.Error(), who)
		return "", err
	}
	users, groups, computers := 0, 0, 0
	for _, o := range res.Objects {
		switch o.Kind {
		case "user":
			users++
		case "group":
			groups++
		case "computer":
			computers++
		}
	}
	summary := fmt.Sprintf("%s (%s): %d users, %d groups, %d computers, %d memberships in %s", res.Domain, res.NetBIOS,
		users, groups, computers, len(res.Members), res.Elapsed.Round(time.Millisecond))
	if res.Unresolved > 0 {
		summary += fmt.Sprintf("; %d member references pointed outside the base DN", res.Unresolved)
	}
	_ = s.store.SetSetting(ctx, settingDirectoryLastSync, time.Now().UTC().Format(time.RFC3339), who)
	_ = s.store.SetSetting(ctx, settingDirectoryLastError, "", who)
	_ = s.store.SetSetting(ctx, settingDirectoryLastSummary, summary, who)
	if res.NetBIOS != "" {
		_ = s.store.SetSetting(ctx, settingDirectoryDNSName, res.Domain, who)
		_ = s.store.SetSetting(ctx, settingDirectoryNetBIOSName, res.NetBIOS, who)
	}
	s.logger.Info("directory synced", "summary", summary, "by", who)
	s.audit(ctx, auditEvent{Action: "directory.sync", Actor: who, Severity: "info", Target: res.Domain,
		Detail: map[string]any{"users": users, "groups": groups, "computers": computers, "memberships": len(res.Members)}})
	s.impact.invalidate()
	return summary, nil
}

// directorySyncLoop keeps the cache fresh on the configured interval while
// the directory is enabled. Disabled means untouched: the last sync stays
// readable, nothing new is fetched.
func (s *Server) directorySyncLoop(ctx context.Context) {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		_, view, err := s.directoryConfig(ctx)
		interval := time.Hour
		if err == nil {
			interval = time.Duration(view.IntervalMinutes) * time.Minute
			if view.Enabled {
				sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				_, _ = s.runDirectorySync(sctx, "scheduler")
				cancel()
			}
		}
		timer.Reset(interval)
	}
}

// ---- the analysis, cached ----

// impactCache holds the last analysis. The graph is cheap for this fleet
// but not free per request, and a page's four tabs would otherwise build
// it four times; two minutes is shorter than any sensor interval.
type impactCache struct {
	mu         sync.Mutex
	a          *impact.Analysis
	unresolved int
	at         time.Time
}

func (c *impactCache) invalidate() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

func (s *Server) impactAnalysis(ctx context.Context, force bool) (*impact.Analysis, error) {
	s.impact.mu.Lock()
	defer s.impact.mu.Unlock()
	if !force && s.impact.a != nil && time.Since(s.impact.at) < 2*time.Minute {
		return s.impact.a, nil
	}
	in, unresolved, err := s.buildImpactInput(ctx)
	if err != nil {
		return nil, err
	}
	a := impact.Analyze(in)
	a.Coverage.Unresolved = unresolved
	s.impact.a, s.impact.unresolved, s.impact.at = a, unresolved, time.Now()
	return a, nil
}

// buildImpactInput joins the directory to the fleet's sensors. Every
// principal an endpoint names is resolved to a directory object when it
// can be -- by SID first, by DOMAIN\name second -- and becomes a local
// principal scoped to that endpoint when it cannot.
func (s *Server) buildImpactInput(ctx context.Context) (impact.Input, int, error) {
	in := impact.Input{
		Principals: map[string]impact.Principal{}, Members: map[string][]string{},
		Admins: map[string][]impact.Grant{}, Sessions: map[string][]string{}, Endpoints: map[string]impact.Endpoint{},
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return in, 0, err
	}
	criticality, _ := s.store.ListCriticality(ctx)
	objects, err := s.store.ListDirectoryObjects(ctx)
	if err != nil {
		return in, 0, err
	}
	members, err := s.store.ListDirectoryMembers(ctx)
	if err != nil {
		return in, 0, err
	}

	bySID := map[string]store.DirectoryObject{}
	userByName := map[string]string{}
	groupByName := map[string]string{}
	computerByName := map[string]store.DirectoryObject{}
	netbios := ""
	domainSID := ""
	for _, o := range objects {
		bySID[o.SID] = o
		if netbios == "" {
			netbios = strings.ToLower(o.Domain)
		}
		if domainSID == "" && (o.Kind == "user" || o.Kind == "group") {
			if i := strings.LastIndex(o.SID, "-"); i > 0 {
				domainSID = o.SID[:i]
			}
		}
		switch o.Kind {
		case "user":
			userByName[strings.ToLower(o.Name)] = o.SID
			in.Principals[o.SID] = impact.Principal{ID: o.SID, Kind: "user", Name: o.Name, Domain: o.Domain, Display: o.DisplayName, Enabled: o.Enabled, AdminCount: o.AdminCount}
		case "group":
			groupByName[strings.ToLower(o.Name)] = o.SID
			in.Principals[o.SID] = impact.Principal{ID: o.SID, Kind: "group", Name: o.Name, Domain: o.Domain, Display: o.DisplayName, Enabled: true, AdminCount: o.AdminCount}
		case "computer":
			computerByName[strings.ToLower(o.Name)] = o
		}
	}
	for _, m := range members {
		in.Members[m.GroupSID] = append(in.Members[m.GroupSID], m.MemberSID)
	}

	shortName := func(h string) string {
		h = strings.ToLower(h)
		if i := strings.Index(h, "."); i > 0 {
			h = h[:i]
		}
		return h
	}
	for _, a := range agents {
		e := impact.Endpoint{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Online: a.Online, Criticality: criticality[a.AgentID]}
		if c, ok := computerByName[shortName(a.Hostname)]; ok && c.DomainController {
			e.DomainController = true
		}
		in.Endpoints[a.AgentID] = e
	}

	// A local principal is scoped to its endpoint: "alex" on two machines
	// is two accounts until a finding says the name repeats.
	local := func(agentID, name, kind string) string {
		pkind := "local"
		if kind == "group" {
			pkind = "local_group"
		}
		id := pkind + ":" + agentID + ":" + strings.ToLower(name)
		if _, ok := in.Principals[id]; !ok {
			in.Principals[id] = impact.Principal{ID: id, Kind: pkind, Name: name, Domain: shortName(in.Endpoints[agentID].Hostname), Enabled: true}
		}
		return id
	}
	unresolved := 0
	// resolve turns what an endpoint reported into a principal ID.
	resolve := func(agentID string, row proto.LocalAdmin) string {
		hostname := shortName(in.Endpoints[agentID].Hostname)
		domain := strings.ToLower(row.Domain)
		if row.SID != "" {
			if _, ok := bySID[row.SID]; ok {
				return row.SID
			}
			if strings.HasPrefix(row.SID, "S-1-5-32-") || domain == hostname || row.Source == "local" {
				return local(agentID, row.Name, row.Kind)
			}
			if domainSID != "" && strings.HasPrefix(row.SID, domainSID+"-") {
				// A domain object the sync did not see (outside the base
				// DN, or newer than the last sync): keep it as itself.
				kind := row.Kind
				if kind != "group" {
					kind = "user"
				}
				if _, ok := in.Principals[row.SID]; !ok {
					in.Principals[row.SID] = impact.Principal{ID: row.SID, Kind: kind, Name: row.Name, Domain: row.Domain, Enabled: true}
				}
				unresolved++
				return row.SID
			}
			// Another domain or a well-known SID: local to this endpoint.
			return local(agentID, row.Name, row.Kind)
		}
		if row.Source == "local" || (domain != "" && domain == hostname) || (domain == "" && netbios == "") {
			return local(agentID, row.Name, row.Kind)
		}
		name := strings.ToLower(row.Name)
		if sid, ok := groupByName[name]; ok && row.Kind != "user" {
			return sid
		}
		if sid, ok := userByName[name]; ok {
			return sid
		}
		if sid, ok := groupByName[name]; ok {
			return sid
		}
		if domain != "" && domain != netbios && domain != hostname {
			unresolved++
		}
		return local(agentID, row.Name, row.Kind)
	}

	adminRows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorLocalAdmins))
	if err != nil {
		return in, 0, err
	}
	for _, row := range adminRows {
		if _, ok := in.Endpoints[row.AgentID]; !ok {
			continue
		}
		var admins []proto.LocalAdmin
		if json.Unmarshal(row.Data, &admins) != nil {
			continue
		}
		grants := []impact.Grant{}
		for _, a := range admins {
			if a.Name == "" {
				continue
			}
			grants = append(grants, impact.Grant{PrincipalID: resolve(row.AgentID, a), Via: a.Via})
		}
		in.Admins[row.AgentID] = grants
	}

	// Sessions: the users sensor. On a Windows endpoint a bare name that
	// matches a directory user is taken to be that user, because that is
	// what a domain-joined machine shows; elsewhere a name is local.
	sessionRows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorUsers))
	if err != nil {
		return in, 0, err
	}
	for _, row := range sessionRows {
		e, ok := in.Endpoints[row.AgentID]
		if !ok {
			continue
		}
		var users []proto.LoggedInUser
		if json.Unmarshal(row.Data, &users) != nil {
			continue
		}
		seen := map[string]bool{}
		for _, u := range users {
			name := u.User
			domain := ""
			if i := strings.Index(name, `\`); i >= 0 {
				domain, name = strings.ToLower(name[:i]), name[i+1:]
			} else if i := strings.Index(name, "@"); i > 0 {
				domain, name = strings.ToLower(name[i+1:]), name[:i]
			}
			if name == "" {
				continue
			}
			id := ""
			if e.OS == "windows" && domain != shortName(e.Hostname) {
				if sid, ok := userByName[strings.ToLower(name)]; ok {
					id = sid
				}
			}
			if id == "" {
				id = local(row.AgentID, name, "user")
			}
			if !seen[id] {
				seen[id] = true
				in.Sessions[row.AgentID] = append(in.Sessions[row.AgentID], id)
			}
		}
	}
	return in, unresolved, nil
}

// ---- handlers ----

// impactOverviewResponse is what GET /api/impact/overview answers.
type impactOverviewResponse struct {
	ComputedAt   time.Time               `json:"computed_at"`
	Coverage     impact.Coverage         `json:"coverage"`
	Directory    impactOverviewDirectory `json:"directory"`
	Findings     []impact.Finding        `json:"findings"`
	Levels       impactOverviewLevels    `json:"levels"`
	TopEndpoints []impact.Rating         `json:"top_endpoints"`
	TopGroups    []impact.Rating         `json:"top_groups"`
	TopUsers     []impact.Rating         `json:"top_users"`
}

// impactOverviewDirectory is the directory connection the analysis
// reads, and how its last sync went.
type impactOverviewDirectory struct {
	Counts    store.DirectoryCounts `json:"counts"`
	Enabled   bool                  `json:"enabled"`
	LastError string                `json:"last_error"`
	LastSync  string                `json:"last_sync"`
}

// impactOverviewLevels counts users, groups and endpoints by impact
// level (critical, high, medium, low, none).
type impactOverviewLevels struct {
	Endpoints map[string]int `json:"endpoints"`
	Groups    map[string]int `json:"groups"`
	Users     map[string]int `json:"users"`
}

func (s *Server) handleImpactOverview(w http.ResponseWriter, r *http.Request) {
	a, err := s.impactAnalysis(r.Context(), r.URL.Query().Get("refresh") == "1")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_, dir, _ := s.directoryConfig(r.Context())
	top := func(rs []impact.Rating, n int) []impact.Rating {
		if len(rs) > n {
			rs = rs[:n]
		}
		return rs
	}
	levels := func(rs []impact.Rating) map[string]int {
		m := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
		for _, r := range rs {
			m[r.Level]++
		}
		return m
	}
	writeJSONResponse(w, impactOverviewResponse{
		ComputedAt: a.ComputedAt,
		Coverage:   a.Coverage,
		Directory: impactOverviewDirectory{
			Enabled: dir.Enabled, LastSync: dir.LastSync, LastError: dir.LastError, Counts: dir.Counts,
		},
		Levels:       impactOverviewLevels{Users: levels(a.Users), Groups: levels(a.Groups), Endpoints: levels(a.Endpoints)},
		TopUsers:     top(a.Users, 8),
		TopGroups:    top(a.Groups, 8),
		TopEndpoints: top(a.Endpoints, 8),
		Findings:     a.Findings,
	})
}

// impactRatingsResponse is what GET /api/impact/{kind} answers for users,
// groups and endpoints.
type impactRatingsResponse struct {
	ComputedAt time.Time       `json:"computed_at"`
	Rows       []impact.Rating `json:"rows"`
}

// impactFindingsResponse is what GET /api/impact/findings answers.
type impactFindingsResponse struct {
	ComputedAt time.Time        `json:"computed_at"`
	Rows       []impact.Finding `json:"rows"`
}

func (s *Server) handleImpactList(w http.ResponseWriter, r *http.Request) {
	a, err := s.impactAnalysis(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	switch r.PathValue("kind") {
	case "users":
		writeJSONResponse(w, impactRatingsResponse{Rows: a.Users, ComputedAt: a.ComputedAt})
	case "groups":
		writeJSONResponse(w, impactRatingsResponse{Rows: a.Groups, ComputedAt: a.ComputedAt})
	case "endpoints":
		writeJSONResponse(w, impactRatingsResponse{Rows: a.Endpoints, ComputedAt: a.ComputedAt})
	case "findings":
		writeJSONResponse(w, impactFindingsResponse{Rows: a.Findings, ComputedAt: a.ComputedAt})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleImpactObject(w http.ResponseWriter, r *http.Request) {
	a, err := s.impactAnalysis(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	d, ok := a.Detail(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSONResponse(w, d)
}

// impactPathResponse is what GET /api/impact/path answers.
type impactPathResponse struct {
	From      string            `json:"from"`
	Path      []impact.PathStep `json:"path"`
	Reachable bool              `json:"reachable"`
	To        string            `json:"to"`
}

func (s *Server) handleImpactPath(w http.ResponseWriter, r *http.Request) {
	a, err := s.impactAnalysis(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if from == "" || to == "" {
		http.Error(w, "from and to are required", 400)
		return
	}
	path := a.ShortestPath(from, to)
	if path == nil {
		path = []impact.PathStep{}
	}
	writeJSONResponse(w, impactPathResponse{From: from, To: to, Path: path, Reachable: len(path) > 0})
}

// impactSearchHit is an entry of what GET /api/impact/search answers.
type impactSearchHit struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// impactSearchResponse is what GET /api/impact/search answers.
type impactSearchResponse struct {
	Hits []impactSearchHit `json:"hits"`
}

// handleImpactSearch lists every object the graph knows by name, for the
// path finder's pickers.
func (s *Server) handleImpactSearch(w http.ResponseWriter, r *http.Request) {
	a, err := s.impactAnalysis(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	q := strings.ToLower(r.URL.Query().Get("q"))
	hits := []impactSearchHit{}
	for _, list := range [][]impact.Rating{a.Endpoints, a.Users, a.Groups} {
		for _, x := range list {
			if q == "" || strings.Contains(strings.ToLower(x.Name), q) {
				hits = append(hits, impactSearchHit{x.ID, x.Kind, x.Name})
			}
		}
	}
	// The ID breaks a tie of names, so the same 200 come back each time.
	sort.Slice(hits, func(i, j int) bool {
		if a, b := strings.ToLower(hits[i].Name), strings.ToLower(hits[j].Name); a != b {
			return a < b
		}
		return hits[i].ID < hits[j].ID
	})
	if len(hits) > 200 {
		hits = hits[:200]
	}
	writeJSONResponse(w, impactSearchResponse{Hits: hits})
}

func (s *Server) handleImpactRecompute(w http.ResponseWriter, r *http.Request) {
	if _, err := s.impactAnalysis(r.Context(), true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}
