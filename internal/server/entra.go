package server

// Microsoft Entra ID and Intune, through Microsoft Graph with an app
// registration (client credentials). Every hour the server reads Entra's
// devices and Intune's managed devices, merges them by Entra device ID and
// matches each to a Mustra endpoint (the directory sensor's Entra device
// ID, then the hostname). Endpoints show join type, compliance and
// Intune's last check-in; Intune's Sync and Restart are offered as actions.
//
// Application permissions needed (admin consent): Device.Read.All,
// DeviceManagementManagedDevices.Read.All, and for the actions
// DeviceManagementManagedDevices.PrivilegedOperations.All.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingEntraTenant   = "entra.tenant_id"
	settingEntraClient   = "entra.client_id"
	settingEntraSecret   = "entra.client_secret"
	settingEntraLastSync = "entra.last_sync"
	settingEntraLastErr  = "entra.last_error"

	entraSyncEvery = time.Hour
)

var entraGUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// graphClient talks to Microsoft Graph. loginBase and graphBase are
// fields so a test can point them at a fake.
type graphClient struct {
	tenant, clientID, secret string
	loginBase, graphBase     string
	http                     *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newGraphClient(tenant, clientID, secret string) *graphClient {
	return &graphClient{tenant: tenant, clientID: clientID, secret: secret,
		loginBase: "https://login.microsoftonline.com", graphBase: "https://graph.microsoft.com",
		http: &http.Client{Timeout: 30 * time.Second}}
}

func (g *graphClient) accessToken(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && time.Until(g.expires) > time.Minute {
		return g.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {g.clientID}, "client_secret": {g.secret},
		"scope": {"https://graph.microsoft.com/.default"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.loginBase+"/"+url.PathEscape(g.tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("Entra sign-in: %w", err)
	}
	defer resp.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t)
	if resp.StatusCode != http.StatusOK || t.AccessToken == "" {
		desc, _, _ := strings.Cut(t.Description, "\r\n")
		return "", fmt.Errorf("Entra refused the app's credentials (%d %s): %s", resp.StatusCode, t.Error, desc)
	}
	g.token, g.expires = t.AccessToken, time.Now().Add(time.Duration(t.ExpiresIn)*time.Second)
	return g.token, nil
}

func (g *graphClient) do(ctx context.Context, method, pathOrURL string, out any) error {
	tok, err := g.accessToken(ctx)
	if err != nil {
		return err
	}
	u := pathOrURL
	if strings.HasPrefix(u, "/") {
		u = g.graphBase + u
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := g.http.Do(req)
	if err != nil {
		return fmt.Errorf("Microsoft Graph: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		hint := ""
		if resp.StatusCode == http.StatusForbidden {
			hint = " (grant the app registration the Graph application permission and admin consent)"
		}
		return fmt.Errorf("Microsoft Graph %s %s: %d %s %s%s", method, strings.SplitN(strings.TrimPrefix(u, g.graphBase), "?", 2)[0], resp.StatusCode, e.Error.Code, e.Error.Message, hint)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// all follows @odata.nextLink through every page.
func (g *graphClient) all(ctx context.Context, path string, each func(json.RawMessage) error) error {
	next := path
	for pages := 0; next != "" && pages < 500; pages++ {
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := g.do(ctx, http.MethodGet, next, &page); err != nil {
			return err
		}
		for _, v := range page.Value {
			if err := each(v); err != nil {
				return err
			}
		}
		next = page.NextLink
	}
	return nil
}

func (s *Server) entraClient(ctx context.Context) (*graphClient, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}
	tenant, client, stored := settings[settingEntraTenant], settings[settingEntraClient], settings[settingEntraSecret]
	if tenant == "" || client == "" || stored == "" {
		return nil, nil
	}
	secret, err := s.openSetting(settingEntraSecret, stored)
	if err != nil {
		return nil, err
	}
	if s.entraOverride != nil {
		return s.entraOverride(tenant, client, secret), nil
	}
	return newGraphClient(tenant, client, secret), nil
}

func (s *Server) entraLoop(ctx context.Context) {
	ticker := time.NewTicker(entraSyncEvery)
	defer ticker.Stop()
	for {
		if _, err := s.syncEntra(ctx); err != nil && !errors.Is(err, errEntraNotSet) {
			s.logger.Warn("Entra ID / Intune sync failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

var errEntraNotSet = errors.New("Entra ID is not set up")

// entraSyncCounts is what a sync found, and what POST /api/admin/entra/sync
// answers. matched and intune are left out while zero, as they always were.
type entraSyncCounts struct {
	Devices int `json:"devices"`
	Intune  int `json:"intune,omitempty"`
	Matched int `json:"matched,omitempty"`
}

// syncEntra reads both device lists, merges and matches them, and stores
// the result. It returns how many devices were found and matched.
func (s *Server) syncEntra(ctx context.Context) (entraSyncCounts, error) {
	g, err := s.entraClient(ctx)
	if err != nil {
		return entraSyncCounts{}, err
	}
	if g == nil {
		return entraSyncCounts{}, errEntraNotSet
	}
	devices, intuneErr, err := fetchEntraDevices(ctx, g)
	if err == nil {
		s.matchEntraDevices(ctx, devices)
		err = s.store.ReplaceEntraDevices(ctx, devices)
	}
	who := "system (Entra sync)"
	errText := ""
	if err != nil {
		errText = err.Error()
	} else if intuneErr != nil {
		errText = "Intune: " + intuneErr.Error()
	}
	_ = s.store.SetSetting(ctx, settingEntraLastErr, errText, who)
	if err != nil {
		return entraSyncCounts{}, err
	}
	_ = s.store.SetSetting(ctx, settingEntraLastSync, time.Now().UTC().Format(time.RFC3339), who)
	counts := entraSyncCounts{Devices: len(devices)}
	for _, d := range devices {
		if d.AgentID != "" {
			counts.Matched++
		}
		if d.IntuneID != "" {
			counts.Intune++
		}
	}
	return counts, nil
}

// fetchEntraDevices: Entra's device directory, then Intune's managed
// devices merged in by Entra device ID. Without an Intune licence or
// permission the Entra half still stands (intuneErr says why).
func fetchEntraDevices(ctx context.Context, g *graphClient) ([]store.EntraDevice, error, error) {
	byDevice := map[string]*store.EntraDevice{}
	var order []string
	err := g.all(ctx, "/v1.0/devices?$select=deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,accountEnabled,isCompliant,approximateLastSignInDateTime&$top=999",
		func(raw json.RawMessage) error {
			var d struct {
				DeviceID       string     `json:"deviceId"`
				Name           string     `json:"displayName"`
				OS             string     `json:"operatingSystem"`
				OSVersion      string     `json:"operatingSystemVersion"`
				TrustType      string     `json:"trustType"`
				AccountEnabled *bool      `json:"accountEnabled"`
				IsCompliant    *bool      `json:"isCompliant"`
				LastSignIn     *time.Time `json:"approximateLastSignInDateTime"`
			}
			if json.Unmarshal(raw, &d) != nil || d.DeviceID == "" {
				return nil
			}
			key := strings.ToLower(d.DeviceID)
			byDevice[key] = &store.EntraDevice{Key: key, EntraDeviceID: key, Name: d.Name, OS: d.OS, OSVersion: d.OSVersion, TrustType: d.TrustType,
				AccountEnabled: d.AccountEnabled, EntraCompliant: d.IsCompliant, LastSignIn: d.LastSignIn}
			order = append(order, key)
			return nil
		})
	if err != nil {
		return nil, nil, err
	}
	intuneErr := g.all(ctx, "/v1.0/deviceManagement/managedDevices?$select=id,azureADDeviceId,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,userPrincipalName,serialNumber&$top=999",
		func(raw json.RawMessage) error {
			var m struct {
				ID         string     `json:"id"`
				EntraID    string     `json:"azureADDeviceId"`
				Name       string     `json:"deviceName"`
				OS         string     `json:"operatingSystem"`
				OSVersion  string     `json:"osVersion"`
				Compliance string     `json:"complianceState"`
				LastSync   *time.Time `json:"lastSyncDateTime"`
				UPN        string     `json:"userPrincipalName"`
				Serial     string     `json:"serialNumber"`
			}
			if json.Unmarshal(raw, &m) != nil || m.ID == "" {
				return nil
			}
			key := strings.ToLower(m.EntraID)
			d, ok := byDevice[key]
			if !ok || key == "" || key == "00000000-0000-0000-0000-000000000000" {
				key = "intune:" + m.ID
				d = &store.EntraDevice{Key: key, Name: m.Name, OS: m.OS, OSVersion: m.OSVersion}
				byDevice[key] = d
				order = append(order, key)
			}
			d.IntuneID, d.ComplianceState, d.LastSync, d.UserUPN, d.Serial = m.ID, m.Compliance, m.LastSync, m.UPN, m.Serial
			return nil
		})
	out := make([]store.EntraDevice, 0, len(order))
	for _, k := range order {
		out = append(out, *byDevice[k])
	}
	return out, intuneErr, nil
}

// matchEntraDevices joins devices to endpoints: the Entra device ID the
// endpoint itself reports (dsregcmd), else a unique hostname match.
func (s *Server) matchEntraDevices(ctx context.Context, devices []store.EntraDevice) {
	byEntraID := map[string]string{}
	if rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorDirectory)); err == nil {
		for _, row := range rows {
			var infos []proto.DirectoryInfo
			if json.Unmarshal(row.Data, &infos) == nil && len(infos) > 0 && infos[0].EntraDeviceID != "" {
				byEntraID[strings.ToLower(infos[0].EntraDeviceID)] = row.AgentID
			}
		}
	}
	byName := map[string][]string{}
	if agents, err := s.store.ListAgents(ctx, s.staleAfter()); err == nil {
		for _, a := range agents {
			short, _, _ := strings.Cut(strings.ToLower(a.Hostname), ".")
			byName[short] = append(byName[short], a.AgentID)
		}
	}
	matchDevices(devices, byEntraID, byName)
}

func matchDevices(devices []store.EntraDevice, byEntraID map[string]string, byName map[string][]string) {
	for i := range devices {
		if id, ok := byEntraID[devices[i].EntraDeviceID]; ok && devices[i].EntraDeviceID != "" {
			devices[i].AgentID = id
			continue
		}
		short, _, _ := strings.Cut(strings.ToLower(devices[i].Name), ".")
		if ids := byName[short]; len(ids) == 1 {
			devices[i].AgentID = ids[0]
		}
	}
}

// entraDevicesResponse is what GET /api/entra/devices answers.
type entraDevicesResponse struct {
	Configured bool                `json:"configured"`
	Devices    []store.EntraDevice `json:"devices"`
	LastError  string              `json:"last_error"`
	LastSync   string              `json:"last_sync"`
}

// GET /api/entra/devices[?agent_id=]
func (s *Server) handleEntraDevices(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListEntraDevices(r.Context(), r.URL.Query().Get("agent_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	settings, _ := s.store.GetAllSettings(r.Context())
	writeJSONResponse(w, entraDevicesResponse{Devices: list, Configured: settings[settingEntraSecret] != "",
		LastSync: settings[settingEntraLastSync], LastError: settings[settingEntraLastErr]})
}

// entraConfigResponse is what GET /api/admin/entra answers.
type entraConfigResponse struct {
	ClientID  string `json:"client_id"`
	LastError string `json:"last_error"`
	LastSync  string `json:"last_sync"`
	SecretSet bool   `json:"secret_set"`
	TenantID  string `json:"tenant_id"`
}

// GET /api/admin/entra and POST /api/admin/entra {"tenant_id","client_id","client_secret"}
func (s *Server) handleEntraConfig(w http.ResponseWriter, r *http.Request) {
	settings, _ := s.store.GetAllSettings(r.Context())
	writeJSONResponse(w, entraConfigResponse{TenantID: settings[settingEntraTenant], ClientID: settings[settingEntraClient],
		SecretSet: settings[settingEntraSecret] != "", LastSync: settings[settingEntraLastSync], LastError: settings[settingEntraLastErr]})
}

// saveEntraConfigRequest is the body of POST /api/admin/entra.
type saveEntraConfigRequest struct {
	Tenant *string `json:"tenant_id"`
	Client *string `json:"client_id"`
	Secret *string `json:"client_secret" api:"writeonly"`
}

func (s *Server) handleSaveEntraConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change the Entra ID connection") {
		return
	}
	var body saveEntraConfigRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	ctx, who := r.Context(), auth.CurrentUser(r.Context()).Username
	for _, f := range []struct {
		v   *string
		key string
	}{{body.Tenant, settingEntraTenant}, {body.Client, settingEntraClient}} {
		if f.v == nil {
			continue
		}
		v := strings.TrimSpace(*f.v)
		if v != "" && !entraGUID.MatchString(v) && !(f.key == settingEntraTenant && strings.Contains(v, ".")) {
			http.Error(w, "the tenant and client IDs are GUIDs (a tenant may also be its domain, e.g. contoso.onmicrosoft.com)", http.StatusBadRequest)
			return
		}
		_ = s.store.SetSetting(ctx, f.key, v, who)
	}
	if body.Secret != nil {
		sealed, err := s.sealSetting(settingEntraSecret, strings.TrimSpace(*body.Secret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = s.store.SetSetting(ctx, settingEntraSecret, sealed, who)
	}
	s.audit(ctx, auditEvent{Action: "settings.entra", Actor: who, Target: "Entra ID / Intune", Severity: "notice",
		Detail: map[string]any{"secret_changed": body.Secret != nil}})
	s.handleEntraConfig(w, r)
}

// POST /api/admin/entra/sync: sync now and say what was found.
func (s *Server) handleEntraSync(w http.ResponseWriter, r *http.Request) {
	counts, err := s.syncEntra(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSONResponse(w, counts)
}

var intuneActions = map[string]string{"sync": "syncDevice", "restart": "rebootNow"}

// intuneActionResponse is what POST /api/agents/{id}/intune/{action}
// answers.
type intuneActionResponse struct {
	Message string `json:"message"`
	OK      bool   `json:"ok"`
}

// POST /api/agents/{id}/intune/{action}: an Intune device action on the
// endpoint's managed device.
func (s *Server) handleIntuneAction(w http.ResponseWriter, r *http.Request) {
	agentID, action := r.PathValue("id"), r.PathValue("action")
	op, ok := intuneActions[action]
	if !ok {
		http.Error(w, "action must be sync or restart", http.StatusBadRequest)
		return
	}
	devices, err := s.store.ListEntraDevices(r.Context(), agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var intuneID, name string
	for _, d := range devices {
		if d.IntuneID != "" {
			intuneID, name = d.IntuneID, d.Name
		}
	}
	if intuneID == "" {
		http.Error(w, "Intune does not manage this endpoint", http.StatusNotFound)
		return
	}
	g, err := s.entraClient(r.Context())
	if err != nil || g == nil {
		http.Error(w, "Entra ID is not set up", http.StatusConflict)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	s.audit(r.Context(), auditEvent{Action: "intune." + action, Actor: who, Target: name, AgentID: agentID, Severity: "notice",
		Detail: map[string]any{"intune_id": intuneID}})
	if err := g.do(r.Context(), http.MethodPost, "/v1.0/deviceManagement/managedDevices/"+url.PathEscape(intuneID)+"/"+op, nil); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSONResponse(w, intuneActionResponse{OK: true, Message: "Intune accepted " + action + " for " + name})
}
