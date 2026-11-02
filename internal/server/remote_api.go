package server

// Remote desktop: RDP to Windows, VNC to macOS, SSH to Linux, opened from
// an endpoint's page.
//
// Mustra decides who may connect to what, with the checks a shell session
// already has (management rights, the shell action group, Jump Gate), and
// audits every connection; the provider carries the session. Off by
// default. Providers:
//
//   - guacamole: Apache Guacamole with its JSON auth extension. Mustra signs
//     a one-connection, short-lived ticket; Guacamole has no accounts of its
//     own and opens nothing without one. Served through this server at
//     /guacamole/, so it needs no hostname or tunnel of its own and only
//     signed-in users reach it.
//   - beyondtrust: hands the connection to BeyondTrust Privileged Remote
//     Access or Remote Support through its client scripting URL, which opens
//     a Jump session in the BeyondTrust console.
//   - custom: any URL template ({ip}, {hostname}, {protocol}, {port}).
//
// Shadowing (remote_shadow.go) is the exception that needs no provider:
// it hands the operator the Remote Desktop client's /shadow command for
// the signed-in user's own Windows session, which Windows lets that
// person accept or refuse. It passes the same checks and is audited the
// same way.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingRemoteProvider   = "remote.provider" // "", guacamole, beyondtrust, custom
	settingRemoteGuacURL    = "remote.guacamole_url"
	settingRemoteGuacKey    = "remote.guacamole_key"
	settingRemoteBTSite     = "remote.beyondtrust_site"
	settingRemoteCustomURL  = "remote.custom_url"
	guacamoleProxyPrefix    = "/guacamole/"
	guacamoleTicketLifetime = 2 * time.Minute
	remoteDefaultGuacamole  = "http://guacamole:8080/guacamole"
)

var remotePorts = map[string]string{"rdp": "3389", "vnc": "5900", "ssh": "22"}

type remoteConfig struct {
	Provider   string `json:"provider"`
	GuacURL    string `json:"guacamole_url,omitempty"`
	GuacKeySet bool   `json:"guacamole_key_set,omitempty"`
	BTSite     string `json:"beyondtrust_site,omitempty"`
	CustomURL  string `json:"custom_url,omitempty"`
	// JIT: "" (off), "offer" (the person opening chooses) or "always".
	JIT string `json:"jit"`
	// Record: Guacamole sessions are recorded unless turned off.
	Record      bool `json:"recording"`
	guacKey     []byte
	guacBaseURL *url.URL
}

func (s *Server) remoteConfig(ctx context.Context) (remoteConfig, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return remoteConfig{}, err
	}
	c := remoteConfig{
		Provider:  settings[settingRemoteProvider],
		GuacURL:   settings[settingRemoteGuacURL],
		BTSite:    settings[settingRemoteBTSite],
		CustomURL: settings[settingRemoteCustomURL],
		JIT:       settings[settingRemoteJIT],
		Record:    settings[settingRemoteRecording] != "off",
	}
	if c.Provider == "guacamole" {
		if c.GuacURL == "" {
			c.GuacURL = remoteDefaultGuacamole
		}
		if stored := settings[settingRemoteGuacKey]; stored != "" {
			c.GuacKeySet = true
			hexKey, err := s.openSetting(settingRemoteGuacKey, stored)
			if err != nil {
				return c, err
			}
			if c.guacKey, err = hex.DecodeString(strings.TrimSpace(hexKey)); err != nil || len(c.guacKey) != 16 {
				return c, errors.New("the Guacamole JSON secret must be 32 hex characters")
			}
		}
		if c.guacBaseURL, err = url.Parse(strings.TrimRight(c.GuacURL, "/")); err != nil {
			return c, err
		}
	}
	return c, nil
}

// remoteProtocols lists what an endpoint can be reached with.
func remoteProtocols(a store.AgentRecord) []string {
	switch {
	case a.Platform == "haos":
		return nil // Home Assistant OS has no SSH or desktop of its own to reach
	case a.OS == "windows":
		return []string{"rdp", "shadow"}
	case a.OS == "darwin":
		return []string{"vnc", "ssh"}
	case a.OS == "linux":
		return []string{"ssh"}
	}
	return nil
}

// remoteAddress picks the address to connect to: the first private IPv4
// the endpoint reports, then any IPv4, then its hostname.
func remoteAddress(a store.AgentRecord) string {
	var fallback string
	for _, raw := range a.IPs {
		ip := net.ParseIP(raw)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.IsPrivate() {
			return raw
		}
		if fallback == "" {
			fallback = raw
		}
	}
	if fallback != "" {
		return fallback
	}
	return a.Hostname
}

// remoteConfigResponse is what GET /api/remote/config answers: jit and
// recording for Guacamole, the connection settings for someone who may
// change them.
type remoteConfigResponse struct {
	BeyondTrustSite *string `json:"beyondtrust_site,omitempty"`
	CustomURL       *string `json:"custom_url,omitempty"`
	Enabled         bool    `json:"enabled"`
	GuacamoleKeySet *bool   `json:"guacamole_key_set,omitempty"`
	GuacamoleURL    *string `json:"guacamole_url,omitempty"`
	JIT             *string `json:"jit,omitempty"`
	Provider        string  `json:"provider"`
	Recording       *bool   `json:"recording,omitempty"`
}

// GET /api/remote/config: what the endpoint page should offer.
func (s *Server) handleRemoteConfig(w http.ResponseWriter, r *http.Request) {
	c, err := s.remoteConfig(r.Context())
	if err != nil {
		s.logger.Warn("read remote access settings", "error", err)
	}
	out := remoteConfigResponse{Provider: c.Provider, Enabled: remoteReady(c)}
	if c.Provider == "guacamole" {
		out.JIT, out.Recording = &c.JIT, &c.Record
	}
	if ok, _ := s.auth.HasPermission(r.Context(), auth.CurrentUser(r.Context()), auth.PermSettingsManage); ok {
		out.GuacamoleURL, out.GuacamoleKeySet = &c.GuacURL, &c.GuacKeySet
		out.BeyondTrustSite, out.CustomURL = &c.BTSite, &c.CustomURL
	}
	writeJSONResponse(w, out)
}

func remoteReady(c remoteConfig) bool {
	switch c.Provider {
	case "guacamole":
		return c.guacKey != nil
	case "beyondtrust":
		return c.BTSite != ""
	case "custom":
		return c.CustomURL != ""
	}
	return false
}

// saveRemoteConfigRequest is the body of POST /api/admin/remote.
type saveRemoteConfigRequest struct {
	Provider  *string `json:"provider"`
	GuacURL   *string `json:"guacamole_url"`
	GuacKey   *string `json:"guacamole_key" api:"writeonly"`
	BTSite    *string `json:"beyondtrust_site"`
	CustomURL *string `json:"custom_url"`
	JIT       *string `json:"jit"`
	Recording *bool   `json:"recording"`
}

// POST /api/admin/remote: change the provider. Administrators only: the
// Guacamole secret mints access to any endpoint the server can reach.
func (s *Server) handleSaveRemoteConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change remote desktop access") {
		return
	}
	var body saveRemoteConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	ctx, who := r.Context(), auth.CurrentUser(r.Context()).Username
	set := func(key, value string) bool {
		if err := s.store.SetSetting(ctx, key, value, who); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
		return true
	}
	if body.Provider != nil {
		switch *body.Provider {
		case "", "guacamole", "beyondtrust", "custom":
		default:
			http.Error(w, "provider must be guacamole, beyondtrust, custom or empty", http.StatusBadRequest)
			return
		}
		if !set(settingRemoteProvider, *body.Provider) {
			return
		}
	}
	if body.GuacURL != nil {
		v := strings.TrimRight(strings.TrimSpace(*body.GuacURL), "/")
		if v != "" {
			if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				http.Error(w, "the Guacamole URL must be http(s)://host[:port]/path", http.StatusBadRequest)
				return
			}
		}
		if !set(settingRemoteGuacURL, v) {
			return
		}
	}
	if body.GuacKey != nil {
		key := strings.ToLower(strings.TrimSpace(*body.GuacKey))
		if b, err := hex.DecodeString(key); key != "" && (err != nil || len(b) != 16) {
			http.Error(w, "the Guacamole JSON secret must be 32 hex characters (openssl rand -hex 16)", http.StatusBadRequest)
			return
		}
		sealed, err := s.sealSetting(settingRemoteGuacKey, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !set(settingRemoteGuacKey, sealed) {
			return
		}
	}
	if body.BTSite != nil {
		v := strings.TrimRight(strings.TrimSpace(*body.BTSite), "/")
		if v != "" && !strings.HasPrefix(v, "https://") {
			v = "https://" + v
		}
		if !set(settingRemoteBTSite, v) {
			return
		}
	}
	if body.CustomURL != nil {
		v := strings.TrimSpace(*body.CustomURL)
		if v != "" && !strings.Contains(v, "{") {
			http.Error(w, "the URL template needs at least one of {ip}, {hostname}, {protocol}, {port}", http.StatusBadRequest)
			return
		}
		if !set(settingRemoteCustomURL, v) {
			return
		}
	}
	if body.JIT != nil {
		switch *body.JIT {
		case "", "offer", "always":
		default:
			http.Error(w, "jit must be offer, always or empty", http.StatusBadRequest)
			return
		}
		if !set(settingRemoteJIT, *body.JIT) {
			return
		}
	}
	if body.Recording != nil {
		v := ""
		if !*body.Recording {
			v = "off"
		}
		if !set(settingRemoteRecording, v) {
			return
		}
	}
	s.audit(ctx, auditEvent{Action: "settings.remote_access", Actor: who, Target: "remote desktop", Severity: "notice",
		Detail: map[string]any{"provider": body.Provider, "secret_changed": body.GuacKey != nil, "jit": body.JIT, "recording": body.Recording}})
	s.handleRemoteConfig(w, r)
}

// openRemoteRequest is the body of POST /api/remote/sessions.
type openRemoteRequest struct {
	AgentID  string `json:"agent_id" api:"required"`
	Protocol string `json:"protocol" api:"required"`
	Reason   string `json:"reason"`
	// LocalAccount leaves the domain blank on a domain-joined machine,
	// for signing in with one of its own accounts.
	LocalAccount bool `json:"local_account"`
	// JIT asks for a temporary account when the setting is "offer".
	JIT bool `json:"jit"`
	// SessionID names the Windows session to shadow (protocol "shadow");
	// 0 picks the active session the endpoint last reported.
	SessionID int `json:"session_id,omitempty"`
	// Control asks to control the shadowed session rather than only view
	// it (protocol "shadow"); the person is told which and asked either way.
	Control bool `json:"control,omitempty"`
}

// openRemoteResponse is what POST /api/remote/sessions answers: a URL to
// open, or for shadowing (provider "shadow") the command to run.
type openRemoteResponse struct {
	Address    string     `json:"address"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	JITAccount string     `json:"jit_account,omitempty"`
	Provider   string     `json:"provider"`
	URL        string     `json:"url"`
	// Command is the Remote Desktop client command that shadows the
	// session, for the operator to run on their own Windows computer.
	Command string `json:"command,omitempty"`
	// SessionID and SessionUser are the Windows session being shadowed
	// and who is signed in to it, as the endpoint last reported.
	SessionID   int    `json:"session_id,omitempty"`
	SessionUser string `json:"session_user,omitempty"`
	// Control says whether the command asks to control the session.
	Control bool `json:"control,omitempty"`
	// Sessions are the endpoint's other signed-in sessions, so an
	// operator can shadow one of those instead.
	Sessions []shadowSession `json:"sessions,omitempty"`
	// ReportedAt is when the endpoint last reported its sessions.
	ReportedAt *time.Time `json:"reported_at,omitempty"`
}

// POST /api/remote/sessions {"agent_id","protocol","reason"} returns the URL
// to open, after the checks a shell session has.
func (s *Server) handleOpenRemote(w http.ResponseWriter, r *http.Request) {
	var body openRemoteRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	if body.Protocol == "shadow" {
		s.openShadow(w, r, body)
		return
	}
	c, err := s.remoteConfig(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !remoteReady(c) {
		http.Error(w, "remote desktop is not set up; see Access → Jump Gate", http.StatusConflict)
		return
	}
	target := s.agentByID(r.Context(), body.AgentID)
	if target == nil {
		http.Error(w, "no such endpoint", http.StatusNotFound)
		return
	}
	protocols := remoteProtocols(*target)
	if !containsString(protocols, body.Protocol) {
		http.Error(w, fmt.Sprintf("%s is not offered for %s", strings.ToUpper(body.Protocol), target.Hostname), http.StatusBadRequest)
		return
	}
	if !s.checkTargets(w, r, "shell", []string{target.AgentID}) {
		return
	}
	allowed, grantID, expires := s.jumpGate(w, r, target.AgentID, target.Hostname, body.Reason)
	if !allowed {
		return
	}
	addr, port := remoteAddress(*target), remotePorts[body.Protocol]
	who := auth.CurrentUser(r.Context()).Username
	var openURL string
	var sessionID, jitName string
	switch c.Provider {
	case "guacamole":
		sessionID, jitName, openURL, err = s.openGuacamole(r.Context(), c, *target, body.Protocol, addr, port, body.Reason, grantID, expires, useJIT(c, body.JIT), body.LocalAccount)
	case "beyondtrust":
		openURL = beyondTrustURL(c.BTSite, *target, body.Protocol, addr)
	case "custom":
		openURL = fillRemoteTemplate(c.CustomURL, *target, body.Protocol, addr, port)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "remote.open", Actor: who, Target: target.Hostname, AgentID: target.AgentID, Severity: "notice",
		Detail: map[string]any{"protocol": body.Protocol, "address": addr, "provider": c.Provider, "grant_id": grantID, "reason": body.Reason,
			"session_id": sessionID, "jit_account": jitName, "recorded": sessionID != "" && c.Record},
	})
	out := openRemoteResponse{URL: openURL, Provider: c.Provider, Address: addr}
	if jitName != "" {
		out.JITAccount = jitName
	}
	if expires != nil {
		out.ExpiresAt = expires
	}
	writeJSONResponse(w, out)
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func fillRemoteTemplate(tmpl string, a store.AgentRecord, protocol, addr, port string) string {
	return strings.NewReplacer(
		"{ip}", url.QueryEscape(addr), "{hostname}", url.QueryEscape(a.Hostname),
		"{protocol}", protocol, "{port}", port, "{agent_id}", url.QueryEscape(a.AgentID),
	).Replace(tmpl)
}

// beyondTrustURL builds a BeyondTrust client scripting link that asks the
// representative console to start a Jump session to the endpoint: Remote
// Desktop Protocol for RDP, the shell jump for SSH, VNC for VNC. Verify
// against the site's own API documentation; parameters differ between
// Privileged Remote Access and Remote Support versions.
func beyondTrustURL(site string, a store.AgentRecord, protocol, addr string) string {
	method := map[string]string{"rdp": "rdp", "ssh": "shell_jump", "vnc": "vnc"}[protocol]
	q := url.Values{}
	q.Set("type", "rep")
	q.Set("operation", "generate")
	q.Set("action", "start_jump_item_session")
	q.Set("search_string", addr)
	q.Set("jump.method", method)
	q.Set("client.hostname", a.Hostname)
	return site + "/api/client_script?" + q.Encode()
}

// guacamoleTicket signs a Guacamole JSON auth payload for one connection,
// trades it for a session token on the Guacamole server, and returns the
// client URL under this server's /guacamole/ proxy and that token, which
// endRemoteSessions needs to log the session out when its window closes.
//
// JSON auth: HMAC-SHA256 of the JSON with the secret, prepended to the JSON,
// AES-128-CBC with the same secret and a zero IV, base64. Guacamole prompts
// for whatever credentials the connection lacks: without a temporary
// account none are sent, and the person connecting types their own.
func (s *Server) guacamoleTicket(ctx context.Context, c remoteConfig, a store.AgentRecord, protocol, addr, port, domain string, creds remoteCredentials, recording string) (string, string, error) {
	name := fmt.Sprintf("%s (%s)", a.Hostname, strings.ToUpper(protocol))
	params := map[string]string{"hostname": addr, "port": port}
	if creds.Username != "" {
		params["username"] = creds.Username
		if creds.Password != "" {
			params["password"] = creds.Password
		}
		if creds.PrivateKey != "" {
			params["private-key"] = creds.PrivateKey
		}
	}
	if recording != "" {
		// Keystrokes are left out (recording-include-keys): they would put
		// every password typed during the session into the file.
		params["recording-path"] = guacdRecordingsDir
		params["recording-name"] = recording
		params["create-recording-path"] = "true"
		if protocol == "ssh" {
			params["typescript-path"] = guacdRecordingsDir
			params["typescript-name"] = recording + ".typescript"
			params["create-typescript-path"] = "true"
		}
	}
	switch protocol {
	case "rdp":
		params["security"] = "any"
		params["ignore-cert"] = "true"
		params["resize-method"] = "display-update"
		params["enable-wallpaper"] = "false"
		if domain != "" {
			// Pre-filled, so Guacamole asks only for the user name and
			// password; open with local_account to sign in without it.
			params["domain"] = domain
		}
	case "vnc":
		params["autoretry"] = "2"
	}
	payload, err := json.Marshal(map[string]any{
		"username": auth.CurrentUser(ctx).Username,
		"expires":  time.Now().Add(guacamoleTicketLifetime).UnixMilli(),
		"connections": map[string]any{
			name: map[string]any{"protocol": protocol, "parameters": params},
		},
	})
	if err != nil {
		return "", "", err
	}
	sealed, err := guacamoleSeal(c.guacKey, payload)
	if err != nil {
		return "", "", err
	}
	form := url.Values{"data": {sealed}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.guacBaseURL.String()+"/api/tokens", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", "", fmt.Errorf("Guacamole is not answering at %s: %w", c.GuacURL, err)
	}
	defer resp.Body.Close()
	var tok struct {
		AuthToken  string `json:"authToken"`
		DataSource string `json:"dataSource"`
		Message    string `json:"message"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	if resp.StatusCode != http.StatusOK || tok.AuthToken == "" {
		return "", "", fmt.Errorf("Guacamole refused the ticket (%d %s); check that its JSON_SECRET_KEY matches Mustra's", resp.StatusCode, tok.Message)
	}
	if tok.DataSource == "" {
		tok.DataSource = "json"
	}
	id := base64.StdEncoding.EncodeToString([]byte(name + "\x00c\x00" + tok.DataSource))
	return guacamoleProxyPrefix + "#/client/" + url.PathEscape(id) + "?token=" + url.QueryEscape(tok.AuthToken), tok.AuthToken, nil
}

// remoteSessionTokenAAD binds sealed Guacamole tokens to their purpose.
const remoteSessionTokenAAD = "remote.session_token"

// guacamoleLogout ends a Guacamole session. Guacamole closes every
// connection that session holds, so the desktop goes away mid-use.
func (s *Server) guacamoleLogout(ctx context.Context, c remoteConfig, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.guacBaseURL.String()+"/api/tokens/"+url.PathEscape(token), nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("Guacamole is not answering at %s: %w", c.GuacURL, err)
	}
	resp.Body.Close()
	// 404: the session already ended (logged out or timed out), which is
	// the outcome wanted.
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("Guacamole refused the logout (%d)", resp.StatusCode)
	}
	return nil
}

// endRemoteSessions logs out remote sessions whose Jump Gate window has
// ended, whose grant was revoked, or whose tunnel has been closed past the
// idle grace, then asks endpoints to remove the temporary accounts of
// ended sessions. A session whose logout fails stays open and is retried
// on the next sweep — unless it signed in with a temporary account:
// removing the account signs it out on the endpoint, which ends the
// desktop whatever Guacamole is doing, so that must not wait on it.
func (s *Server) endRemoteSessions(ctx context.Context) {
	defer s.removeJITAccounts(ctx)
	due, err := s.store.RemoteSessionsToEnd(ctx, remoteIdleGrace)
	if err != nil {
		s.logger.Warn("listing remote sessions to end failed", "error", err)
		return
	}
	if len(due) == 0 {
		return
	}
	c, err := s.remoteConfig(ctx)
	if err != nil {
		s.logger.Warn("remote sessions: reading the configuration failed", "error", err)
		return
	}
	for _, rs := range due {
		if rs.GuacToken != "" {
			if c.guacBaseURL == nil {
				err = errors.New("Guacamole is no longer configured")
			} else {
				var token string
				if token, err = s.openSetting(remoteSessionTokenAAD, rs.GuacToken); err == nil {
					err = s.guacamoleLogout(ctx, c, token)
				}
			}
			if err != nil {
				s.logger.Warn("ending remote session failed", "session", rs.ID, "error", err)
				if rs.JITUsername == "" {
					continue
				}
			}
		}
		if err := s.store.EndRemoteSession(ctx, rs.ID, rs.EndReason); err != nil {
			s.logger.Warn("recording remote session end failed", "session", rs.ID, "error", err)
			continue
		}
		s.audit(ctx, auditEvent{Action: "remote.ended", Actor: "system", Target: rs.Hostname, AgentID: rs.AgentID, Severity: "notice",
			Detail: map[string]any{"session_id": rs.ID, "user": rs.Username, "protocol": rs.Protocol, "grant_id": rs.GrantID, "reason": rs.EndReason}})
	}
}

func guacamoleSeal(key, payload []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	plain := append(mac.Sum(nil), payload...)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, plain)
	return base64.StdEncoding.EncodeToString(out), nil
}

// handleGuacamoleProxy serves Guacamole at /guacamole/ (page, API and the
// WebSocket tunnel), so it needs no hostname of its own and is reached only
// by signed-in users.
func (s *Server) handleGuacamoleProxy(w http.ResponseWriter, r *http.Request) {
	c, err := s.remoteConfig(r.Context())
	if err != nil || c.Provider != "guacamole" || c.guacBaseURL == nil {
		http.NotFound(w, r)
		return
	}
	base := c.guacBaseURL
	// Guacamole frames its own pages (blank.html for file transfer and the
	// clipboard); this server's DENY would block them. Same-origin only.
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = base.Scheme, base.Host
			pr.Out.URL.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimPrefix(pr.In.URL.Path, guacamoleProxyPrefix)
			pr.Out.URL.RawPath = ""
			pr.Out.Host = base.Host
			// Mustra's session cookie is for Mustra; Guacamole has its own token.
			pr.Out.Header.Del("Cookie")
		},
		FlushInterval: -1,
		// Guacamole 1.6 serves its stylesheets and scripts as
		// application/octet-stream, which this server's nosniff header
		// makes a browser refuse, leaving a blank page. Name them by
		// extension when the upstream type says nothing.
		ModifyResponse: func(resp *http.Response) error {
			if ct := resp.Header.Get("Content-Type"); ct == "" || strings.HasPrefix(ct, "application/octet-stream") {
				if t := mime.TypeByExtension(path.Ext(resp.Request.URL.Path)); t != "" {
					resp.Header.Set("Content-Type", t)
				}
			}
			return nil
		},
	}
	defer s.trackGuacamoleTunnel(r)()
	proxy.ServeHTTP(w, r)
}

// signInDomain is the domain to pre-fill for a Windows sign-in on an
// endpoint: none unless its Directory sensor says it is joined to Active
// Directory, and then the short (NetBIOS) name when that domain is the one
// the directory sync knows, else the DNS name the endpoint reported.
func (s *Server) signInDomain(ctx context.Context, agentID string) string {
	rec, err := s.store.GetSensorData(ctx, agentID, string(proto.SensorDirectory))
	if err != nil || rec == nil {
		return ""
	}
	var infos []proto.DirectoryInfo
	if json.Unmarshal(rec.Data, &infos) != nil || len(infos) == 0 {
		return ""
	}
	dns, _ := s.store.GetSetting(ctx, settingDirectoryDNSName)
	netbios, _ := s.store.GetSetting(ctx, settingDirectoryNetBIOSName)
	return pickSignInDomain(infos[0], dns, netbios)
}

func pickSignInDomain(d proto.DirectoryInfo, syncedDNS, syncedNetBIOS string) string {
	if !d.Joined || (d.Kind != "ad" && d.Kind != "hybrid") || d.Domain == "" {
		return ""
	}
	if syncedNetBIOS != "" && strings.EqualFold(d.Domain, syncedDNS) {
		return strings.ToUpper(syncedNetBIOS)
	}
	return d.Domain
}
