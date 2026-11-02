package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/vault"
)

// settingsView is what the admin Settings tab reads and edits. Secrets
// (the SCIM, update and Fleet tokens) are never returned, only whether
// each is set; the backdoor and uninstall passwords are stored only as
// hashes, so there is nothing to show back. An update that leaves a
// secret out keeps it; what an empty one does depends on the field (see
// updateSettingsRequest): an empty uninstall password, for one, removes
// the requirement.
type settingsView struct {
	// SSO providers are managed through their own API
	// (/api/admin/oidc-providers) — this is just the rolled-up state for
	// the section header.
	SSOStatus string `json:"sso_status"` // "disabled" | "discovering" | "active"
	// SSOAllowlist is who may sign in through SSO; see oidc_allowlist.go.
	SSOAllowlist ssoAllowlistView `json:"sso_allowlist"`
	// ImportAllowedHosts, one per line; see netguard.go.
	ImportAllowedHosts string `json:"import_allowed_hosts"`
	// WebhookAllowedHosts, one per line; see netguard.go.
	WebhookAllowedHosts string `json:"webhook_allowed_hosts"`

	BackdoorUsername    string `json:"backdoor_username"`
	BackdoorPasswordSet bool   `json:"backdoor_password_set"`

	// UninstallPasswordSet follows the backdoor password exactly: the hash
	// is all that is stored, so the field comes back blank and blank means
	// unchanged. Empty clears it, which leaves endpoints removable without
	// a password -- stated plainly in the UI, because "no password" is a
	// decision rather than an absence.
	UninstallPasswordSet bool `json:"uninstall_password_set"`

	// MacMDMEnrollURL is returned in full: it is not a password, though it
	// usually carries the MDM's enroll secret, and this route already
	// requires settings.manage.
	MacMDMEnrollURL string `json:"macos_mdm_enroll_url"`

	// SCIMToken and UpdateToken are never returned: a secret is shown
	// once, when it is set, and afterwards only whether one is set. Any
	// script running in a settings.manage session could otherwise read
	// them off this endpoint.
	SCIMToken    string `json:"scim_token"`
	SCIMTokenSet bool   `json:"scim_token_set"`
	SCIMEnabled  bool   `json:"scim_enabled"`

	StaleAfterSeconds    int    `json:"stale_after_seconds"`
	OfflineExpirySeconds int    `json:"offline_expiry_seconds"`
	AgentNATSURL         string `json:"agent_nats_url"`

	// The buffer between the agents and this server. The live size is
	// reported alongside the setting because it is the number that makes
	// the choice concrete: "four hours" means nothing until you can see
	// what four hours currently costs.
	StreamRetentionHours int    `json:"stream_retention_hours"`
	StreamMinHours       int    `json:"stream_min_hours"`
	StreamMaxHours       int    `json:"stream_max_hours"`
	StreamMessages       uint64 `json:"stream_messages"`
	StreamBytes          uint64 `json:"stream_bytes"`

	// Console branding — the uploaded logo itself is fetched as an image
	// from /branding/logo rather than shipped through this JSON.
	LogoURL string `json:"logo_url"`

	// Where the About page checks for a newer build. The token is never
	// returned, only whether one is set.
	UpdateRepo     string `json:"update_repo"`
	UpdateToken    string `json:"update_token"`
	UpdateTokenSet bool   `json:"update_token_set"`

	// The MDM that installs macOS itself on Apple Silicon (fleetmdm.go).
	// The token is never returned, only whether one is set.
	FleetURL        string `json:"fleet_url"`
	FleetTokenSet   bool   `json:"fleet_token_set"`
	FleetMacOSMajor bool   `json:"fleet_macos_major"`

	// Read-only, env-configured — shown for visibility only.
	NATSURL                   string `json:"nats_url"`
	HTTPAddr                  string `json:"http_addr"`
	CookieSecure              bool   `json:"cookie_secure"`
	CredentialVaultConfigured bool   `json:"credential_vault_configured"`

	// LocalMFARequired: every local account must use two-step sign-in.
	LocalMFARequired bool `json:"local_mfa_required"`
}

func (s *Server) currentSettingsView(r *http.Request) settingsView {
	providers := s.auth.Providers()
	ssoStatus := "disabled"
	if len(providers) > 0 {
		ssoStatus = "discovering"
		for _, p := range providers {
			if p.Ready {
				ssoStatus = "active"
				break
			}
		}
	}
	staleAfter, offlineExpiry, agentNATSURL, backdoorUsername := s.live.snapshot()

	settingsMap, _ := s.store.GetAllSettings(r.Context())

	// Best effort: an unreachable stream should render the settings page
	// with zeroes, not fail it. The page has plenty else on it.
	var streamMsgs, streamBytes uint64
	if st, err := s.js.Stream(r.Context(), bnats.AgentStreamName); err == nil {
		if info, err := st.Info(r.Context()); err == nil {
			streamMsgs, streamBytes = info.State.Msgs, info.State.Bytes
		}
	}

	return settingsView{
		SSOStatus:                 ssoStatus,
		SSOAllowlist:              s.ssoAllowlist(settingsMap, len(providers)),
		ImportAllowedHosts:        settingsMap[settingImportAllowedHosts],
		WebhookAllowedHosts:       settingsMap[settingWebhookAllowedHosts],
		BackdoorUsername:          backdoorUsername,
		BackdoorPasswordSet:       settingsMap[settingBackdoorPasswordHash] != "",
		UninstallPasswordSet:      settingsMap[settingUninstallPasswordHash] != "",
		MacMDMEnrollURL:           settingsMap[settingMacMDMEnrollURL],
		SCIMTokenSet:              settingsMap[settingSCIMToken] != "",
		SCIMEnabled:               s.scim.Enabled(),
		StaleAfterSeconds:         int(staleAfter.Seconds()),
		OfflineExpirySeconds:      int(offlineExpiry.Seconds()),
		AgentNATSURL:              agentNATSURL,
		StreamRetentionHours:      int(s.streamRetention(r.Context()).Hours()),
		StreamMinHours:            int(bnats.MinStreamRetention.Hours()),
		StreamMaxHours:            int(bnats.MaxStreamRetention.Hours()),
		StreamMessages:            streamMsgs,
		StreamBytes:               streamBytes,
		LogoURL:                   s.logoURL(),
		UpdateRepo:                settingsMap[settingUpdateRepo],
		UpdateTokenSet:            settingsMap[settingUpdateToken] != "",
		FleetURL:                  settingsMap[settingFleetURL],
		FleetTokenSet:             settingsMap[settingFleetToken] != "",
		FleetMacOSMajor:           settingsMap[settingFleetMacOSMajor] == "true",
		NATSURL:                   s.cfg.NATSURL,
		HTTPAddr:                  s.cfg.HTTPAddr,
		CookieSecure:              s.cfg.CookieSecure,
		CredentialVaultConfigured: s.vault != nil,
		LocalMFARequired:          settingsMap[settingLocalMFARequired] == "true",
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, s.currentSettingsView(r))
}

// updateSettingsRequest uses pointer fields so an omitted JSON key means
// "leave unchanged" — the admin form only sends the fields the user
// actually edited, and secret fields (password, client secret, SCIM token)
// stay untouched unless explicitly resent.
type updateSettingsRequest struct {
	BackdoorUsername *string `json:"backdoor_username"`
	BackdoorPassword *string `json:"backdoor_password" api:"writeonly"` // nil = unchanged
	// UninstallPassword: nil leaves it alone, "" removes the requirement,
	// anything else replaces it.
	UninstallPassword *string `json:"uninstall_password" api:"writeonly"`
	// MacMDMEnrollURL: nil leaves it alone, "" turns the offer off.
	MacMDMEnrollURL *string `json:"macos_mdm_enroll_url"`

	SCIMToken *string `json:"scim_token" api:"writeonly"`

	StaleAfterSeconds    *int    `json:"stale_after_seconds"`
	OfflineExpirySeconds *int    `json:"offline_expiry_seconds"`
	AgentNATSURL         *string `json:"agent_nats_url"`

	StreamRetentionHours *int `json:"stream_retention_hours"`

	UpdateRepo  *string `json:"update_repo"`
	UpdateToken *string `json:"update_token" api:"writeonly"`

	FleetURL        *string `json:"fleet_url"`
	FleetToken      *string `json:"fleet_token" api:"writeonly"`
	FleetMacOSMajor *bool   `json:"fleet_macos_major"`

	// ImportAllowedHosts: hosts "import from URL" may reach although they
	// are internal, and the only hosts a stored credential is sent to.
	ImportAllowedHosts *string `json:"import_allowed_hosts"`
	// WebhookAllowedHosts: hosts a Connect, report or Jump Gate webhook may
	// reach although they are internal (and the only ones allowed http).
	WebhookAllowedHosts *string `json:"webhook_allowed_hosts"`

	SSOAllowedDomains *string `json:"sso_allowed_domains"`
	SSOAllowedEmails  *string `json:"sso_allowed_emails"`
	SSOAllowedGroups  *string `json:"sso_allowed_groups"`
	SSOGroupsClaim    *string `json:"sso_groups_claim"`

	// LocalMFARequired makes every local account use two-step sign-in;
	// one without it sets it up at its next sign-in.
	LocalMFARequired *bool `json:"local_mfa_required"`
}

// handleUpdateSettings applies a partial update and takes effect
// immediately — no restart. Each section (SSO, backdoor, SCIM, agent
// knobs) is independent: editing one doesn't require resending the others.
func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	ctx := r.Context()

	if req.UninstallPassword != nil {
		// Empty clears the requirement rather than being ignored: taking a
		// password off is a thing an administrator may legitimately want,
		// and "leave blank to keep" would make it impossible to say.
		if *req.UninstallPassword == "" {
			if err := s.store.SetSetting(ctx, settingUninstallPasswordHash, "", u.Username); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.audit(ctx, auditEvent{Action: "settings.uninstall_password", Actor: u.Username,
				Target: "endpoint uninstaller", Severity: "warning",
				Detail: map[string]any{"state": "cleared"}})
		} else {
			h, err := auth.HashPassword(*req.UninstallPassword)
			if err != nil {
				http.Error(w, "hash password: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if err := s.store.SetSetting(ctx, settingUninstallPasswordHash, h, u.Username); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.audit(ctx, auditEvent{Action: "settings.uninstall_password", Actor: u.Username,
				Target: "endpoint uninstaller", Severity: "notice",
				Detail: map[string]any{"state": "set"}})
		}
	}

	if req.MacMDMEnrollURL != nil {
		enrollURL := strings.TrimSpace(*req.MacMDMEnrollURL)
		if err := validateMDMEnrollURL(enrollURL); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.store.SetSetting(ctx, settingMacMDMEnrollURL, enrollURL, u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		state := "set"
		if enrollURL == "" {
			state = "cleared"
		}
		// The URL itself stays out of the audit log: it usually carries the
		// MDM's enroll secret, and the log is readable more widely than
		// Settings is.
		s.audit(ctx, auditEvent{Action: "settings.macos_mdm_enroll_url", Actor: u.Username,
			Target: "macOS installer", Severity: "notice",
			Detail: map[string]any{"state": state}})
	}

	// The break-glass account is a full administrator, so changing it is an
	// administrator's call: settings.manage alone used to be able to set
	// its password and sign in as admin. Same for SCIM (whoever holds the
	// SCIM token provisions accounts) and the agents' bus address (where
	// every new endpoint connects and takes commands from).
	if (req.BackdoorUsername != nil || req.BackdoorPassword != nil) && !requireAdmin(w, r, "change the break-glass account") {
		return
	}
	if req.SCIMToken != nil && !s.requireAdminOr(w, r, auth.PermIdentityManage, "change the SCIM token") {
		return
	}
	// An MDM token can install, lock or erase Macs, so it and where it is
	// sent are an administrator's call too.
	if (req.FleetURL != nil || req.FleetToken != nil || req.FleetMacOSMajor != nil) && !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change the macOS MDM connection") {
		return
	}
	// Requiring two-step sign-in decides who can sign in at all.
	if req.LocalMFARequired != nil {
		if !s.requireAdminOr(w, r, auth.PermIdentityManage, "change the two-step sign-in requirement") {
			return
		}
		if *req.LocalMFARequired && !s.auth.MFAAvailable() {
			http.Error(w, "two-step sign-in needs the server's credential encryption key (MUSTRA_CREDENTIAL_ENCRYPTION_KEY); without it nobody could set it up", http.StatusConflict)
			return
		}
		if !s.auditIdentity(w, r, "settings.local_mfa_required", "local accounts", map[string]any{"required": *req.LocalMFARequired}) {
			return
		}
		if err := s.store.SetSetting(ctx, settingLocalMFARequired, strconv.FormatBool(*req.LocalMFARequired), u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if req.AgentNATSURL != nil {
		// The form resends the current value with every agent-settings
		// save; only an actual change needs the permission.
		_, _, current, _ := s.live.snapshot()
		if strings.TrimSpace(*req.AgentNATSURL) == current {
			req.AgentNATSURL = nil
		} else if !s.requireAdminOr(w, r, auth.PermAgentTrustManage, "change the agents' NATS address") {
			return
		}
	}
	if req.ImportAllowedHosts != nil {
		if !s.requireAdminOr(w, r, auth.PermAllowlistsManage, "change the import allowlist") {
			return
		}
		var hosts []string
		for _, h := range auth.SplitList(*req.ImportAllowedHosts) {
			h = strings.ToLower(strings.TrimSuffix(h, "."))
			if strings.ContainsAny(h, " /:@") {
				http.Error(w, "the import allowlist takes host names only (no scheme, port or path): "+h, http.StatusBadRequest)
				return
			}
			hosts = append(hosts, h)
		}
		if !s.auditIdentity(w, r, "settings.import_allowlist", "package import allowlist", map[string]any{"hosts": hosts}) {
			return
		}
		if err := s.store.SetSetting(ctx, settingImportAllowedHosts, strings.Join(hosts, "\n"), u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if req.WebhookAllowedHosts != nil {
		if !s.requireAdminOr(w, r, auth.PermAllowlistsManage, "change the internal destinations allowlist") {
			return
		}
		var hosts []string
		for _, h := range auth.SplitList(*req.WebhookAllowedHosts) {
			h = strings.ToLower(strings.TrimSuffix(h, "."))
			if strings.ContainsAny(h, " /:@") {
				http.Error(w, "the webhook allowlist takes host names only (no scheme, port or path): "+h, http.StatusBadRequest)
				return
			}
			hosts = append(hosts, h)
		}
		if !s.auditIdentity(w, r, "settings.webhook_allowlist", "webhook allowlist", map[string]any{"hosts": hosts}) {
			return
		}
		if err := s.store.SetSetting(ctx, settingWebhookAllowedHosts, strings.Join(hosts, "\n"), u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if !s.updateSSOAllowlist(w, r, req.SSOAllowedDomains, req.SSOAllowedEmails, req.SSOAllowedGroups, req.SSOGroupsClaim) {
		return
	}
	if req.SCIMToken != nil && *req.SCIMToken != "" && len(strings.TrimSpace(*req.SCIMToken)) < minSCIMTokenLen {
		http.Error(w, fmt.Sprintf("a SCIM token must be at least %d characters; use Generate", minSCIMTokenLen), http.StatusBadRequest)
		return
	}
	if req.BackdoorPassword != nil && *req.BackdoorPassword != "" && len(*req.BackdoorPassword) < minLocalPasswordLen {
		http.Error(w, fmt.Sprintf("the break-glass password must be at least %d characters", minLocalPasswordLen), http.StatusBadRequest)
		return
	}

	if req.BackdoorUsername != nil || req.BackdoorPassword != nil {
		if !s.auditIdentity(w, r, "settings.breakglass", "break-glass account", map[string]any{
			"username_changed": req.BackdoorUsername != nil && *req.BackdoorUsername != "" && *req.BackdoorUsername != s.backdoorUsername(),
			"password_changed": req.BackdoorPassword != nil && *req.BackdoorPassword != ""}) {
			return
		}
		curUsername := s.backdoorUsername()
		newUsername := curUsername
		if req.BackdoorUsername != nil && *req.BackdoorUsername != "" {
			newUsername = *req.BackdoorUsername
		}
		var hash string
		settingsMap, err := s.store.GetAllSettings(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hash = settingsMap[settingBackdoorPasswordHash]
		if req.BackdoorPassword != nil && *req.BackdoorPassword != "" {
			h, err := auth.HashPassword(*req.BackdoorPassword)
			if err != nil {
				http.Error(w, "hash password: "+err.Error(), http.StatusInternalServerError)
				return
			}
			hash = h
			if err := s.store.SetSetting(ctx, settingBackdoorPasswordHash, hash, u.Username); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if newUsername == "" || hash == "" {
			http.Error(w, "backdoor account needs both a username and a password", http.StatusBadRequest)
			return
		}
		if err := s.store.SetSetting(ctx, settingBackdoorUsername, newUsername, u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		bg, err := s.store.UpsertLocalAdmin(ctx, newUsername, hash)
		if err != nil {
			http.Error(w, "sync backdoor account: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// A new password signs out every existing break-glass session: the
		// reason to rotate it is usually that somebody else may know it.
		if bg != nil && req.BackdoorPassword != nil && *req.BackdoorPassword != "" {
			if err := s.store.DeleteSessionsForUser(ctx, bg.ID); err != nil {
				s.logger.Warn("signing out break-glass sessions failed", "error", err)
			}
		}
		if newUsername != curUsername && curUsername != "" {
			// The username changed: the old row is now a stray extra admin
			// account rather than "the" backdoor — deactivate it (not
			// delete, in case someone's still holding a session on it and
			// this was a mistake) rather than leaving a second full-admin
			// local account nobody remembers exists.
			if oldUser, err := s.store.GetUserByUsername(ctx, curUsername); err == nil && oldUser != nil {
				if _, err := s.store.SetUserActive(ctx, oldUser.ID, false); err != nil {
					s.logger.Warn("deactivate old backdoor account failed", "username", curUsername, "error", err)
				}
			}
		}
		s.live.setBackdoorUsername(newUsername)
		s.logger.Info("backdoor account settings updated", "updated_by", u.Username, "username", newUsername)
	}

	if req.SCIMToken != nil {
		*req.SCIMToken = strings.TrimSpace(*req.SCIMToken)
		if !s.auditIdentity(w, r, "settings.scim_token", "SCIM", map[string]any{"state": map[bool]string{true: "cleared", false: "set"}[*req.SCIMToken == ""]}) {
			return
		}
		sealed, err := sealWith(s.vault, vault.SettingAAD(settingSCIMToken), *req.SCIMToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.store.SetSetting(ctx, settingSCIMToken, sealed, u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.scim.SetToken(*req.SCIMToken)
		s.logger.Info("SCIM token updated", "updated_by", u.Username)
	}

	if req.StaleAfterSeconds != nil || req.OfflineExpirySeconds != nil || req.AgentNATSURL != nil {
		staleAfter, offlineExpiry, agentNATSURL, _ := s.live.snapshot()
		if req.StaleAfterSeconds != nil {
			if *req.StaleAfterSeconds < 5 {
				http.Error(w, "stale_after_seconds must be >= 5", http.StatusBadRequest)
				return
			}
			staleAfter = time.Duration(*req.StaleAfterSeconds) * time.Second
			if err := s.store.SetSetting(ctx, settingStaleAfterSeconds, strconv.Itoa(*req.StaleAfterSeconds), u.Username); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if req.OfflineExpirySeconds != nil {
			if *req.OfflineExpirySeconds < 60 {
				http.Error(w, "offline_expiry_seconds must be >= 60", http.StatusBadRequest)
				return
			}
			offlineExpiry = time.Duration(*req.OfflineExpirySeconds) * time.Second
			if err := s.store.SetSetting(ctx, settingOfflineExpirySeconds, strconv.Itoa(*req.OfflineExpirySeconds), u.Username); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if req.AgentNATSURL != nil {
			agentNATSURL = strings.TrimSpace(*req.AgentNATSURL)
			if err := validateAgentNATSURL(agentNATSURL); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !s.auditIdentity(w, r, "settings.agent_nats_url", "agent NATS URL", map[string]any{"url": agentNATSURL}) {
				return
			}
			if err := s.store.SetSetting(ctx, settingAgentNATSURL, agentNATSURL, u.Username); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		s.live.setAgent(staleAfter, offlineExpiry, agentNATSURL)
		s.logger.Info("agent settings updated", "updated_by", u.Username, "stale_after", staleAfter, "offline_expiry", offlineExpiry)
	}

	if req.StreamRetentionHours != nil {
		hours := *req.StreamRetentionHours
		if hours < int(bnats.MinStreamRetention.Hours()) || hours > int(bnats.MaxStreamRetention.Hours()) {
			http.Error(w, fmt.Sprintf("stream_retention_hours must be between %d and %d",
				int(bnats.MinStreamRetention.Hours()), int(bnats.MaxStreamRetention.Hours())),
				http.StatusBadRequest)
			return
		}
		// Applied to the running stream before it is stored, so a value that
		// NATS rejects is not left recorded as if it had taken. Shortening
		// discards anything already past the new window immediately.
		if _, err := bnats.EnsureAgentStream(ctx, s.nc, time.Duration(hours)*time.Hour); err != nil {
			http.Error(w, "apply retention to the stream: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.store.SetSetting(ctx, settingStreamRetentionHours, strconv.Itoa(hours), u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Worth an audit line of its own: this decides how long the control
		// plane may be down before published work is lost.
		s.audit(ctx, auditEvent{
			Action: "settings.stream_retention", Actor: u.Username,
			Target: "agent stream", Severity: "notice",
			Detail: map[string]any{"hours": hours},
		})
		s.logger.Info("agent stream retention updated", "hours", hours, "updated_by", u.Username)
	}

	if req.UpdateRepo != nil {
		if err := s.store.SetSetting(ctx, settingUpdateRepo, strings.TrimSpace(*req.UpdateRepo), u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if req.UpdateToken != nil {
		s.audit(ctx, auditEvent{Action: "settings.update_token", Actor: u.Username, Target: "update check", Severity: "notice",
			Detail: map[string]any{"state": map[bool]string{true: "cleared", false: "set"}[strings.TrimSpace(*req.UpdateToken) == ""]}})
		if err := s.store.SetSetting(ctx, settingUpdateToken, strings.TrimSpace(*req.UpdateToken), u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if req.FleetURL != nil {
		fleetURL := strings.TrimRight(strings.TrimSpace(*req.FleetURL), "/")
		if err := validateFleetURL(fleetURL); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.store.SetSetting(ctx, settingFleetURL, fleetURL, u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if req.FleetToken != nil {
		sealed, err := s.sealSetting(settingFleetToken, strings.TrimSpace(*req.FleetToken))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.store.SetSetting(ctx, settingFleetToken, sealed, u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if req.FleetMacOSMajor != nil {
		if err := s.store.SetSetting(ctx, settingFleetMacOSMajor, map[bool]string{true: "true", false: ""}[*req.FleetMacOSMajor], u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if req.FleetURL != nil || req.FleetToken != nil || req.FleetMacOSMajor != nil {
		s.audit(ctx, auditEvent{Action: "settings.macos_mdm", Actor: u.Username, Target: "macOS updates", Severity: "notice",
			Detail: map[string]any{"url_changed": req.FleetURL != nil, "token": map[bool]string{true: "unchanged", false: "set"}[req.FleetToken == nil],
				"major_upgrades": req.FleetMacOSMajor}})
	}

	writeJSONResponse(w, s.currentSettingsView(r))
}

// testFleetResponse is what POST /api/admin/settings/fleet-test answers.
type testFleetResponse struct {
	User string `json:"user"`
}

// handleTestFleet checks the saved Fleet URL and token.
func (s *Server) handleTestFleet(w http.ResponseWriter, r *http.Request) {
	fleet, _, err := s.fleetConfig(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if fleet == nil {
		http.Error(w, "save a Fleet URL and API token first", http.StatusBadRequest)
		return
	}
	who, err := fleet.me(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSONResponse(w, testFleetResponse{User: who})
}

// minSCIMTokenLen is the shortest SCIM bearer token accepted. The console's
// Generate button makes 48 hex characters.
const minSCIMTokenLen = 32

// validateAgentNATSURL accepts "" (unset) or a nats:// / tls:// URL with a
// host and nothing else: the value is written into install scripts.
func validateAgentNATSURL(raw string) error {
	if raw == "" {
		return nil
	}
	for _, c := range raw {
		if c <= ' ' || c > '~' || strings.ContainsRune(`'"\$`+"`"+`;|&<>(){}`, c) {
			return fmt.Errorf("the agent NATS URL contains %q, which no NATS address needs", c)
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "nats" && u.Scheme != "tls") || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("the agent NATS URL must look like nats://host:4222 or tls://host:4222")
	}
	return nil
}

// validateMDMEnrollURL accepts an empty string (off) or an https URL with a
// host. The URL is written into install.sh inside single quotes, so a quote,
// a backslash, whitespace or anything outside printable ASCII is refused here
// rather than escaped there: a real enrollment URL never contains one, and
// refusing is the version that cannot be got wrong.
func validateMDMEnrollURL(raw string) error {
	if raw == "" {
		return nil
	}
	for _, c := range raw {
		if c <= ' ' || c > '~' || c == '\'' || c == '\\' {
			return fmt.Errorf("the enrollment URL contains %q, which no enrollment URL needs; paste the address exactly as the MDM gives it", c)
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("the enrollment URL must be a full address such as https://mdm.example.com/enroll")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("the enrollment URL must use https: the Mac is being asked to trust a profile from it")
	}
	return nil
}
