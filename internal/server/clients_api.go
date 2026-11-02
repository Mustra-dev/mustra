package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

// Client Management's status, health and configuration profiles: the
// fleet's own agents as a managed thing rather than a script somebody
// runs. Status is every client's registration and connectivity, exportable;
// Health is versions, named check failures and settings drift by group;
// Profiles are settings pushed to groups, with an upgrade ring per profile
// and a deferral ring that a fleet roll leaves alone.

// --- profiles and effective settings -----------------------------------

// effectiveProfiles resolves which profile governs each endpoint: the
// highest-priority enabled profile whose groups cover it. Endpoints no
// profile covers have no profile and no expected settings.
func (s *Server) effectiveProfiles(ctx context.Context, agents []store.AgentRecord) (map[string]*store.ClientProfile, error) {
	profiles, err := s.store.ListClientProfiles(ctx)
	if err != nil {
		return nil, err
	}
	type entry struct {
		p       store.ClientProfile
		members map[string]bool
	}
	var entries []entry
	for _, p := range profiles {
		if !p.Enabled {
			continue
		}
		members, err := s.agentsInGroups(ctx, p.GroupIDs)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{p: p, members: members})
	}
	out := map[string]*store.ClientProfile{}
	for _, a := range agents {
		for i := range entries { // already ordered by priority desc
			if entries[i].members == nil || entries[i].members[a.AgentID] {
				p := entries[i].p
				out[a.AgentID] = &p
				break
			}
		}
	}
	return out, nil
}

// settingsDrift lists which of a profile's settings an agent is not
// running with, judged from what the agent last reported.
func settingsDrift(a store.AgentRecord, p *store.ClientProfile) []string {
	if p == nil {
		return nil
	}
	var reported proto.AgentSettings
	if len(a.Settings) > 0 {
		_ = json.Unmarshal(a.Settings, &reported)
	}
	var drift []string
	want := p.Settings
	if want.SensorIntervalSeconds > 0 && reported.SensorIntervalSeconds != want.SensorIntervalSeconds {
		drift = append(drift, fmt.Sprintf("sensor interval %ds (profile %ds)", reported.SensorIntervalSeconds, want.SensorIntervalSeconds))
	}
	if want.LogLevel != "" && !strings.EqualFold(reported.LogLevel, want.LogLevel) {
		drift = append(drift, fmt.Sprintf("log level %s (profile %s)", orDash(reported.LogLevel), want.LogLevel))
	}
	if want.RandomDelaySeconds > 0 && reported.RandomDelaySeconds != want.RandomDelaySeconds {
		drift = append(drift, fmt.Sprintf("random delay %ds (profile %ds)", reported.RandomDelaySeconds, want.RandomDelaySeconds))
	}
	return drift
}

func orDash(s string) string {
	if s == "" {
		return "unset"
	}
	return s
}

// pushProfile sends an agent its profile's settings. It is the only path
// settings reach an endpoint; the apply loop and the save handler both
// call it.
func (s *Server) pushProfile(ctx context.Context, a store.AgentRecord, p *store.ClientProfile) error {
	settings := p.Settings
	settings.Profile = p.Name
	payload, err := json.Marshal(proto.AgentCommand{Cmd: "configure", Settings: &settings})
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(a.AgentID), payload)
	if err != nil {
		return fmt.Errorf("did not respond: %w", err)
	}
	var result proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return fmt.Errorf("unreadable reply: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("%s", result.Error)
	}
	return nil
}

// applyProfiles pushes settings to every online endpoint whose reported
// settings drift from its profile. Returns how many were pushed and how
// many refused (an agent older than 0.47.0 does not know "configure").
func (s *Server) applyProfiles(ctx context.Context, only string) (pushed int, failed map[string]string) {
	failed = map[string]string{}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return 0, failed
	}
	profiles, err := s.effectiveProfiles(ctx, agents)
	if err != nil {
		s.logger.Warn("resolve client profiles", "error", err)
		return 0, failed
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, a := range agents {
		p := profiles[a.AgentID]
		if p == nil || !a.Online || (only != "" && p.ID != only) {
			continue
		}
		if len(settingsDrift(a, p)) == 0 {
			continue
		}
		wg.Add(1)
		go func(a store.AgentRecord, p *store.ClientProfile) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			err := s.pushProfile(ctx, a, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed[a.Hostname] = err.Error()
				return
			}
			pushed++
		}(a, p)
	}
	wg.Wait()
	return pushed, failed
}

// clientProfileLoop re-applies profiles every five minutes, which is what
// makes a profile a standing state rather than a one-off push: an agent
// that restarts with old flags, or that joined a group since, converges.
func (s *Server) clientProfileLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(90 * time.Second):
	}
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		pushed, failed := s.applyProfiles(ctx, "")
		if pushed > 0 || len(failed) > 0 {
			s.logger.Info("client profiles applied", "pushed", pushed, "failed", len(failed))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// --- status --------------------------------------------------------------

type clientStatusRow struct {
	AgentID       string               `json:"agent_id"`
	Hostname      string               `json:"hostname"`
	OS            string               `json:"os"`
	Platform      string               `json:"platform"`
	PlatformVer   string               `json:"platform_version"`
	Arch          string               `json:"arch"`
	Site          string               `json:"site"`
	IPs           []string             `json:"ips"`
	Version       string               `json:"version"`
	Current       bool                 `json:"current"`
	Online        bool                 `json:"online"`
	FirstSeen     time.Time            `json:"first_seen"`
	LastHeartbeat *time.Time           `json:"last_heartbeat"`
	LastFacts     *time.Time           `json:"last_facts"`
	Transport     string               `json:"transport"`
	Settings      *proto.AgentSettings `json:"settings,omitempty"`
	Profile       string               `json:"profile,omitempty"`
	ProfileID     string               `json:"profile_id,omitempty"`
	UpgradeRing   int                  `json:"upgrade_ring"`
	Drift         []string             `json:"drift"`
}

func (s *Server) clientStatusRows(ctx context.Context) ([]clientStatusRow, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	profiles, err := s.effectiveProfiles(ctx, agents)
	if err != nil {
		return nil, err
	}
	serving := version.Agent()
	out := make([]clientStatusRow, 0, len(agents))
	for _, a := range agents {
		row := clientStatusRow{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Platform: a.Platform, PlatformVer: a.PlatformVersion, Arch: a.Arch, Site: a.Site,
			IPs: nonNil(a.IPs), Version: a.AgentVersion, Current: !versionIsNewer(serving, a.AgentVersion), Online: a.Online,
			FirstSeen: a.FirstSeen, LastHeartbeat: a.LastHeartbeat, LastFacts: a.LastFacts, Transport: "NATS over TLS", Drift: []string{}, UpgradeRing: 1}
		if len(a.Settings) > 0 {
			var st proto.AgentSettings
			if json.Unmarshal(a.Settings, &st) == nil {
				row.Settings = &st
			}
		}
		if p := profiles[a.AgentID]; p != nil {
			row.Profile, row.ProfileID, row.UpgradeRing = p.Name, p.ID, p.UpgradeRing
			row.Drift = nonNil(settingsDrift(a, p))
		}
		out = append(out, row)
	}
	return out, nil
}

// clientStatusResponse is what GET /api/clients/status answers.
type clientStatusResponse struct {
	Clients        []clientStatusRow `json:"clients"`
	ServingVersion string            `json:"serving_version"`
}

func (s *Server) handleClientStatus(w http.ResponseWriter, r *http.Request) {
	rows, err := s.clientStatusRows(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="mustra-clients.csv"`)
		cw := newSafeCSVWriter(w)
		_ = cw.Write([]string{"hostname", "agent_id", "os", "platform", "platform_version", "arch", "site", "ips", "agent_version", "current", "online", "first_seen", "last_heartbeat", "last_facts", "transport", "profile", "upgrade_ring", "sensor_interval_seconds", "log_level", "random_delay_seconds", "drift"})
		for _, x := range rows {
			ts := func(t *time.Time) string {
				if t == nil {
					return ""
				}
				return t.UTC().Format(time.RFC3339)
			}
			st := proto.AgentSettings{}
			if x.Settings != nil {
				st = *x.Settings
			}
			_ = cw.Write([]string{x.Hostname, x.AgentID, x.OS, x.Platform, x.PlatformVer, x.Arch, x.Site, strings.Join(x.IPs, " "), x.Version, strconv.FormatBool(x.Current), strconv.FormatBool(x.Online),
				x.FirstSeen.UTC().Format(time.RFC3339), ts(x.LastHeartbeat), ts(x.LastFacts), x.Transport, x.Profile, strconv.Itoa(x.UpgradeRing),
				strconv.Itoa(st.SensorIntervalSeconds), st.LogLevel, strconv.Itoa(st.RandomDelaySeconds), strings.Join(x.Drift, "; ")})
		}
		cw.Flush()
		return
	}
	writeJSONResponse(w, clientStatusResponse{Clients: rows, ServingVersion: version.Agent()})
}

// --- health --------------------------------------------------------------

type clientCheck struct {
	Check    string `json:"check"`
	Severity string `json:"severity"` // high | medium | low
	Detail   string `json:"detail"`
}

type clientHealthRow struct {
	AgentID  string        `json:"agent_id"`
	Hostname string        `json:"hostname"`
	OS       string        `json:"os"`
	Version  string        `json:"version"`
	Online   bool          `json:"online"`
	Profile  string        `json:"profile,omitempty"`
	Ring     int           `json:"upgrade_ring"`
	Checks   []clientCheck `json:"checks"`
	Drift    []string      `json:"drift"`
}

// clientChecks are the named health checks. Each is a fact about the
// agent's own operation, not about the endpoint's security: is it here,
// is it current, is it reporting, are its reports fresh.
func (s *Server) clientChecks(a store.AgentRecord, sensors map[string]time.Time, now time.Time) []clientCheck {
	var out []clientCheck
	serving := version.Agent()
	if !a.Online {
		age := "never seen"
		if a.LastHeartbeat != nil {
			age = "last heartbeat " + now.Sub(*a.LastHeartbeat).Round(time.Minute).String() + " ago"
		}
		sev := "medium"
		if a.LastHeartbeat == nil || now.Sub(*a.LastHeartbeat) > 24*time.Hour {
			sev = "high"
		}
		out = append(out, clientCheck{"offline", sev, age})
	}
	if versionIsNewer(serving, a.AgentVersion) {
		out = append(out, clientCheck{"agent behind", "medium", fmt.Sprintf("running %s, server serves %s", a.AgentVersion, serving)})
	}
	if a.Online {
		if a.LastFacts == nil || now.Sub(*a.LastFacts) > 10*time.Minute {
			out = append(out, clientCheck{"facts stale", "medium", "no facts in the last 10 minutes while online"})
		}
		interval := 15 * time.Minute
		var st proto.AgentSettings
		if len(a.Settings) > 0 && json.Unmarshal(a.Settings, &st) == nil && st.SensorIntervalSeconds > 0 {
			interval = time.Duration(st.SensorIntervalSeconds) * time.Second
		}
		for _, kind := range []string{string(proto.SensorProcesses), string(proto.SensorServices), string(proto.SensorInstalledApps), string(proto.SensorHardware)} {
			at, ok := sensors[kind]
			if !ok {
				out = append(out, clientCheck{"sensor missing", "medium", kind + " has never been reported"})
				continue
			}
			if now.Sub(at) > 3*interval {
				out = append(out, clientCheck{"sensor stale", "medium", fmt.Sprintf("%s last reported %s ago (interval %s)", kind, now.Sub(at).Round(time.Minute), interval)})
			}
		}
		if at, ok := sensors[string(proto.SensorPatches)]; ok && now.Sub(at) > 6*time.Hour {
			out = append(out, clientCheck{"patch scan stale", "low", fmt.Sprintf("patches last reported %s ago", now.Sub(at).Round(time.Hour))})
		}
	}
	return out
}

// clientHealthResponse is what GET /api/clients/health answers.
type clientHealthResponse struct {
	Behind         int                    `json:"behind"`
	Checks         map[string]int         `json:"checks"`
	Clients        []clientHealthRow      `json:"clients"`
	Drifted        int                    `json:"drifted"`
	Rings          map[int]map[string]int `json:"rings"`
	ServingVersion string                 `json:"serving_version"`
	Total          int                    `json:"total"`
	Versions       map[string]int         `json:"versions"`
}

func (s *Server) handleClientHealth(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	profiles, err := s.effectiveProfiles(r.Context(), agents)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	times, err := s.store.ListSensorTimes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// A group filter, because "what is wrong with the DCs" is the question
	// and "what is wrong with everything" is the noise around it.
	var members map[string]bool
	if g := r.URL.Query().Get("group"); g != "" {
		members, _ = s.agentsInGroups(r.Context(), []string{g})
	}
	now := time.Now()
	versions := map[string]int{}
	checkCounts := map[string]int{}
	rings := map[int]map[string]int{} // ring -> {total, behind}
	rows := []clientHealthRow{}
	behind, drifted := 0, 0
	serving := version.Agent()
	for _, a := range agents {
		if members != nil && !members[a.AgentID] {
			continue
		}
		versions[a.AgentVersion]++
		p := profiles[a.AgentID]
		row := clientHealthRow{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Version: a.AgentVersion, Online: a.Online, Ring: 1, Drift: []string{}}
		if p != nil {
			row.Profile, row.Ring = p.Name, p.UpgradeRing
			row.Drift = nonNil(settingsDrift(a, p))
		}
		row.Checks = s.clientChecks(a, times[a.AgentID], now)
		if row.Checks == nil {
			row.Checks = []clientCheck{}
		}
		for _, c := range row.Checks {
			checkCounts[c.Check]++
		}
		if rings[row.Ring] == nil {
			rings[row.Ring] = map[string]int{}
		}
		rings[row.Ring]["total"]++
		if versionIsNewer(serving, a.AgentVersion) {
			behind++
			rings[row.Ring]["behind"]++
		}
		if len(row.Drift) > 0 {
			drifted++
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if len(rows[i].Checks) != len(rows[j].Checks) {
			return len(rows[i].Checks) > len(rows[j].Checks)
		}
		return rows[i].Hostname < rows[j].Hostname
	})
	writeJSONResponse(w, clientHealthResponse{
		Clients: rows, Versions: versions, Checks: checkCounts, Rings: rings,
		ServingVersion: serving, Behind: behind, Drifted: drifted, Total: len(rows),
	})
}

// --- profiles API ----------------------------------------------------------

// clientProfileView is an entry of what GET /api/clients/profiles answers.
type clientProfileView struct {
	store.ClientProfile
	Members int `json:"members"`
}

// listClientProfilesResponse is what GET /api/clients/profiles answers.
type listClientProfilesResponse struct {
	Profiles []clientProfileView `json:"profiles"`
}

func (s *Server) handleListClientProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.store.ListClientProfiles(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := make([]clientProfileView, 0, len(profiles))
	for _, p := range profiles {
		v := clientProfileView{ClientProfile: p, Members: -1}
		if set, err := s.agentsInGroups(r.Context(), p.GroupIDs); err == nil && set != nil {
			v.Members = len(set)
		}
		out = append(out, v)
	}
	writeJSONResponse(w, listClientProfilesResponse{Profiles: out})
}

// saveClientProfileResponse is what POST /api/clients/profiles and PUT
// /api/clients/profiles/{id} answer.
type saveClientProfileResponse struct {
	Failed map[string]string `json:"failed"`
	ID     string            `json:"id"`
	Pushed int               `json:"pushed"`
}

func (s *Server) handleSaveClientProfile(w http.ResponseWriter, r *http.Request) {
	var in store.ClientProfile
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "invalid profile", 400)
		return
	}
	// A POST creates under an ID minted here, whatever the body says; a
	// PUT updates the profile it names, which must exist.
	if r.PathValue("id") == "" {
		in.ID = idgen.New("cpf-")
		in.Enabled = true
	} else {
		old, err := s.store.GetClientProfile(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if old == nil {
			http.Error(w, "no such profile", 404)
			return
		}
		in.ID = old.ID
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "a profile needs a name", 400)
		return
	}
	if in.Settings.SensorIntervalSeconds != 0 && (in.Settings.SensorIntervalSeconds < 5 || in.Settings.SensorIntervalSeconds > 86400) {
		http.Error(w, "sensor interval must be 5–86400 seconds, or 0 to leave it alone", 400)
		return
	}
	if in.Settings.LogLevel != "" && !strings.Contains(" debug info warn error ", " "+strings.ToLower(in.Settings.LogLevel)+" ") {
		http.Error(w, "log level must be debug, info, warn or error", 400)
		return
	}
	if in.Settings.RandomDelaySeconds < 0 || in.Settings.RandomDelaySeconds > 3600 {
		http.Error(w, "random delay must be 0–3600 seconds", 400)
		return
	}
	if in.UpgradeRing < 0 || in.UpgradeRing > 9 {
		http.Error(w, "upgrade ring must be 0 (deferral) to 9", 400)
		return
	}
	in.Settings.Profile = ""
	if in.GroupIDs == nil {
		in.GroupIDs = []string{}
	}
	if !s.requireKnownGroups(w, r, in.GroupIDs) {
		return
	}
	in.CreatedBy = auth.CurrentUser(r.Context()).Username
	if err := s.store.UpsertClientProfile(r.Context(), in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "client_profile.save", Actor: in.CreatedBy, Target: in.Name, Severity: "notice",
		Detail: map[string]any{"id": in.ID, "settings": in.Settings, "ring": in.UpgradeRing, "groups": len(in.GroupIDs), "enabled": in.Enabled}})
	// Push straight away so the operator sees the effect, then the loop
	// keeps it true.
	pushed, failed := s.applyProfiles(context.WithoutCancel(r.Context()), in.ID)
	writeJSONResponse(w, saveClientProfileResponse{ID: in.ID, Pushed: pushed, Failed: failed})
}

func (s *Server) handleDeleteClientProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteClientProfile(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}

// applyClientProfilesResponse is what POST /api/clients/profiles/apply
// answers.
type applyClientProfilesResponse struct {
	Failed map[string]string `json:"failed"`
	Pushed int               `json:"pushed"`
}

func (s *Server) handleApplyClientProfiles(w http.ResponseWriter, r *http.Request) {
	pushed, failed := s.applyProfiles(context.WithoutCancel(r.Context()), r.URL.Query().Get("profile"))
	writeJSONResponse(w, applyClientProfilesResponse{Pushed: pushed, Failed: failed})
}

// --- upgrade rings ---------------------------------------------------------

// upgradeRingRequest is the body of POST /api/clients/upgrade.
type upgradeRingRequest struct {
	Ring            *int `json:"ring"`
	IncludeDeferred bool `json:"include_deferred"`
}

// upgradeRingResponse is what POST /api/clients/upgrade answers.
type upgradeRingResponse struct {
	Results        []agentUpdateOutcome `json:"results"`
	ServingVersion string               `json:"serving_version"`
	Started        int                  `json:"started"`
	Targets        int                  `json:"targets"`
}

// handleUpgradeRing asks every online endpoint in one ring that is behind
// the served version to update itself, the same mechanism as Update
// agents but bounded to a ring. Ring 0 is the deferral ring and is refused
// unless the request says include_deferred, so a fleet roll cannot reach
// it by accident.
func (s *Server) handleUpgradeRing(w http.ResponseWriter, r *http.Request) {
	var req upgradeRingRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	profiles, err := s.effectiveProfiles(r.Context(), agents)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	serving := version.Agent()
	var targets []store.AgentRecord
	for _, a := range agents {
		ring := 1
		if p := profiles[a.AgentID]; p != nil {
			ring = p.UpgradeRing
		}
		if ring == 0 && !req.IncludeDeferred {
			continue
		}
		if req.Ring != nil && ring != *req.Ring {
			continue
		}
		if a.Online && versionIsNewer(serving, a.AgentVersion) {
			targets = append(targets, a)
		}
	}
	results := make([]agentUpdateOutcome, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t store.AgentRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = s.updateAgent(r.Context(), t)
		}(i, t)
	}
	wg.Wait()
	started := 0
	for _, x := range results {
		if x.Started {
			started++
		}
	}
	who := auth.CurrentUser(r.Context()).Username
	s.audit(r.Context(), auditEvent{Action: "agents.upgrade_ring", Actor: who, Target: fmt.Sprintf("ring %v", ringLabel(req.Ring)), Severity: "notice",
		Detail: map[string]any{"targets": len(targets), "started": started, "include_deferred": req.IncludeDeferred, "to": serving}})
	writeJSONResponse(w, upgradeRingResponse{Targets: len(targets), Started: started, Results: results, ServingVersion: serving})
}

func ringLabel(r *int) string {
	if r == nil {
		return "all"
	}
	return strconv.Itoa(*r)
}
