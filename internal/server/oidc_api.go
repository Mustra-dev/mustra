package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
)

// Multi-IdP SSO: the console can sign people in against any number of OIDC
// providers at once (Entra ID, Google, Discord, Authentik, Okta, ...), each
// drawn as its own branded button on the login page. Everything here is
// plain OIDC discovery — `kind` only decides which logo and which setup
// instructions the UI shows, never how the protocol works.

var providerIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// knownProviderKinds is what the admin UI offers a logo and tailored setup
// steps for. Anything else is stored as "generic" and still works.
var knownProviderKinds = map[string]bool{
	"azure": true, "google": true, "discord": true, "authentik": true,
	"okta": true, "github": true, "keycloak": true, "generic": true,
}

// loadOIDCProviders reads every provider from Postgres and hands them to
// the auth layer, which (re)runs discovery for each.
func (s *Server) loadOIDCProviders(ctx context.Context) error {
	rows, err := s.store.ListOIDCProviders(ctx)
	if err != nil {
		return err
	}
	cfgs := make([]auth.OIDCConfig, 0, len(rows))
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		secret, err := openWith(s.vault, oidcSecretAAD(r.ID), r.ClientSecret)
		if err != nil {
			// One unreadable provider must not take every sign-in down.
			s.logger.Warn("SSO provider's client secret could not be decrypted; provider skipped", "provider", r.ID, "error", err)
			continue
		}
		cfgs = append(cfgs, auth.OIDCConfig{
			ID: r.ID, Label: r.Label, Kind: r.Kind, IssuerURL: r.IssuerURL,
			ClientID: r.ClientID, ClientSecret: secret, RedirectURL: r.RedirectURL,
		})
	}
	s.auth.SetProviders(cfgs)
	return nil
}

// migrateLegacyOIDCConfig moves a pre-multi-IdP single provider (the flat
// oidc.* settings rows) into oidc_providers on first boot after the
// upgrade. The migrated row keeps its original redirect URI — which has no
// provider slug on the end — and the legacy /login/sso and /auth/callback
// routes still resolve to it while it's the only provider, so an existing
// IdP application keeps working with no reconfiguration.
func (s *Server) migrateLegacyOIDCConfig(ctx context.Context, settings map[string]string) error {
	n, err := s.store.CountOIDCProviders(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	issuer := settings[settingOIDCIssuerURL]
	clientID := settings[settingOIDCClientID]
	clientSecret, err := openWith(s.vault, vault.SettingAAD(settingOIDCClientSecret), settings[settingOIDCClientSecret])
	if err != nil {
		return err
	}
	redirectURL := settings[settingOIDCRedirectURL]
	if issuer == "" || clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil
	}
	if clientSecret, err = sealWith(s.vault, oidcSecretAAD("sso"), clientSecret); err != nil {
		return err
	}
	kind := inferProviderKind(issuer)
	if _, err := s.store.UpsertOIDCProvider(ctx, store.OIDCProviderRow{
		ID: "sso", Label: providerKindLabel(kind), Kind: kind, IssuerURL: issuer,
		ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
		Enabled: true, CreatedBy: "legacy-migration",
	}); err != nil {
		return err
	}
	s.logger.Info("migrated the single-IdP SSO config into the providers table", "issuer", issuer, "kind", kind)
	return nil
}

// inferProviderKind guesses which IdP an issuer URL belongs to, so a
// migrated config gets the right logo without the admin re-picking it.
func inferProviderKind(issuer string) string {
	host := strings.ToLower(issuer)
	switch {
	case strings.Contains(host, "login.microsoftonline.com"), strings.Contains(host, "sts.windows.net"):
		return "azure"
	case strings.Contains(host, "accounts.google.com"):
		return "google"
	case strings.Contains(host, "discord.com"):
		return "discord"
	case strings.Contains(host, "okta.com"), strings.Contains(host, "oktapreview.com"):
		return "okta"
	case strings.Contains(host, "github.com"):
		return "github"
	case strings.Contains(host, "/application/o/"): // Authentik's issuer path shape
		return "authentik"
	case strings.Contains(host, "/realms/"): // Keycloak's issuer path shape
		return "keycloak"
	default:
		return "generic"
	}
}

func providerKindLabel(kind string) string {
	switch kind {
	case "azure":
		return "Microsoft"
	case "google":
		return "Google"
	case "discord":
		return "Discord"
	case "authentik":
		return "Authentik"
	case "okta":
		return "Okta"
	case "github":
		return "GitHub"
	case "keycloak":
		return "Keycloak"
	default:
		return "SSO"
	}
}

// oidcProviderRow is an entry of what GET /api/admin/oidc-providers
// answers. The client secret is write-only: it is never returned, only
// whether one is stored, so a settings.manage holder cannot read a
// configured IdP secret back out of the console.
type oidcProviderRow struct {
	oidcProviderView
	Ready bool `json:"ready"`
}

// listOIDCProvidersResponse is what GET /api/admin/oidc-providers answers.
type listOIDCProvidersResponse struct {
	Providers []oidcProviderRow `json:"providers"`
}

func (s *Server) handleListOIDCProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListOIDCProviders(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Discovery state is what tells an admin whether a provider they just
	// added actually resolves — pair each row with it.
	ready := map[string]bool{}
	for _, p := range s.auth.Providers() {
		ready[p.ID] = p.Ready
	}
	out := make([]oidcProviderRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, oidcProviderRow{oidcProviderView: redactOIDCProvider(r), Ready: ready[r.ID]})
	}
	writeJSONResponse(w, listOIDCProvidersResponse{Providers: out})
}

// oidcProviderView is a provider as the API shows it: the client secret is
// write-only, like every other credential the console stores. Reading the
// list takes only settings.manage, which does not let its holder change
// SSO, and handing them the secret would let them act as this relying
// party at the IdP. An edit that leaves the secret empty keeps the stored
// one, so the form never needs it back.
type oidcProviderView struct {
	store.OIDCProviderRow
	// ClientSecret hides the row's: redactOIDCProvider leaves it empty,
	// so the field is not sent at all rather than sent as "".
	ClientSecret    string `json:"client_secret,omitempty" api:"writeonly"`
	ClientSecretSet bool   `json:"client_secret_set"`
}

func redactOIDCProvider(r store.OIDCProviderRow) oidcProviderView {
	set := r.ClientSecret != ""
	r.ClientSecret = ""
	return oidcProviderView{OIDCProviderRow: r, ClientSecretSet: set}
}

type upsertOIDCProviderRequest struct {
	ID           string `json:"id"`
	Label        string `json:"label" api:"required"`
	Kind         string `json:"kind"`
	IssuerURL    string `json:"issuer_url" api:"required"`
	ClientID     string `json:"client_id" api:"required"`
	ClientSecret string `json:"client_secret" api:"writeonly"` // "" on an edit keeps the stored secret
	RedirectURL  string `json:"redirect_url" api:"required"`
	Enabled      *bool  `json:"enabled"`
	SortOrder    int    `json:"sort_order"`
}

func (s *Server) handleUpsertOIDCProvider(w http.ResponseWriter, r *http.Request) {
	var req upsertOIDCProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// On PUT the id comes from the path; on POST it's in the body.
	if id := r.PathValue("id"); id != "" {
		req.ID = id
	}
	if err := validateProviderRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// An identity provider decides who someone is. Adding or repointing
	// one is an administrator's decision, and is audited as identity.
	if !s.requireAdminOr(w, r, auth.PermIdentityManage, "add or change an identity provider") {
		return
	}
	if !s.auditIdentity(w, r, "sso.provider_save", req.ID, map[string]any{"issuer": req.IssuerURL, "kind": req.Kind, "client_id": req.ClientID}) {
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	u := auth.CurrentUser(r.Context())
	secret, err := sealWith(s.vault, oidcSecretAAD(req.ID), req.ClientSecret) // "" stays "": keep the stored one
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	row, err := s.store.UpsertOIDCProvider(r.Context(), store.OIDCProviderRow{
		ID: req.ID, Label: req.Label, Kind: req.Kind, IssuerURL: req.IssuerURL,
		ClientID: req.ClientID, ClientSecret: secret, RedirectURL: req.RedirectURL,
		Enabled: enabled, SortOrder: req.SortOrder, CreatedBy: u.Username,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.loadOIDCProviders(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("oidc provider saved", "provider", row.ID, "kind", row.Kind, "updated_by", u.Username)
	writeJSONResponse(w, redactOIDCProvider(*row))
}

func validateProviderRequest(req *upsertOIDCProviderRequest) error {
	req.ID = strings.TrimSpace(strings.ToLower(req.ID))
	if !providerIDPattern.MatchString(req.ID) {
		return fmt.Errorf("id must be lowercase letters, digits, and dashes (e.g. \"google\", \"entra-id\")")
	}
	if strings.TrimSpace(req.Label) == "" {
		return fmt.Errorf("label is required — it's what the sign-in button says")
	}
	if req.Kind == "" || !knownProviderKinds[req.Kind] {
		req.Kind = "generic"
	}
	if !strings.HasPrefix(req.IssuerURL, "https://") && !strings.HasPrefix(req.IssuerURL, "http://") {
		return fmt.Errorf("issuer URL must start with https:// (the IdP's OIDC issuer, not its login page)")
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return fmt.Errorf("client ID is required")
	}
	if strings.TrimSpace(req.RedirectURL) == "" {
		return fmt.Errorf("redirect URL is required")
	}
	return nil
}

// setOIDCProviderEnabledRequest is the body of POST /api/admin/oidc-providers/{id}/enabled.
type setOIDCProviderEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleSetOIDCProviderEnabled(w http.ResponseWriter, r *http.Request) {
	var req setOIDCProviderEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.requireAdminOr(w, r, auth.PermIdentityManage, "enable or disable an identity provider") {
		return
	}
	if !s.auditIdentity(w, r, "sso.provider_enabled", r.PathValue("id"), map[string]any{"enabled": req.Enabled}) {
		return
	}
	if err := s.store.SetOIDCProviderEnabled(r.Context(), r.PathValue("id"), req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.loadOIDCProviders(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIdentityManage, "remove an identity provider") {
		return
	}
	if !s.auditIdentity(w, r, "sso.provider_delete", r.PathValue("id"), nil) {
		return
	}
	if err := s.store.DeleteOIDCProvider(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.loadOIDCProviders(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := auth.CurrentUser(r.Context())
	s.logger.Info("oidc provider deleted", "provider", r.PathValue("id"), "deleted_by", u.Username)
	w.WriteHeader(http.StatusNoContent)
}
