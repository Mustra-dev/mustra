package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Who may sign in through SSO. Rules come from Settings (stored) and from
// the environment (MUSTRA_OIDC_ALLOWED_DOMAINS / _EMAILS / _GROUPS and
// MUSTRA_OIDC_GROUPS_CLAIM); a sign-in matching either is admitted. With no
// rule at all, SSO admits nobody: see auth.OIDCPolicy.

const (
	settingOIDCAllowedDomains = "oidc.allowed_domains"
	settingOIDCAllowedEmails  = "oidc.allowed_emails"
	settingOIDCAllowedGroups  = "oidc.allowed_groups"
	settingOIDCGroupsClaim    = "oidc.groups_claim"
)

// oidcPolicy is read on every SSO sign-in.
func (s *Server) oidcPolicy(ctx context.Context) auth.OIDCPolicy {
	p := auth.OIDCPolicy{
		AllowedDomains: append([]string{}, s.cfg.OIDCAllowedDomains...),
		AllowedEmails:  append([]string{}, s.cfg.OIDCAllowedEmails...),
		AllowedGroups:  append([]string{}, s.cfg.OIDCAllowedGroups...),
		GroupsClaim:    s.cfg.OIDCGroupsClaim,
	}
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		// Fail closed to the environment's rules only.
		s.logger.Warn("reading the SSO allowlist failed", "error", err)
		return p
	}
	p.AllowedDomains = append(p.AllowedDomains, auth.SplitList(settings[settingOIDCAllowedDomains])...)
	p.AllowedEmails = append(p.AllowedEmails, auth.SplitList(settings[settingOIDCAllowedEmails])...)
	p.AllowedGroups = append(p.AllowedGroups, auth.SplitList(settings[settingOIDCAllowedGroups])...)
	if c := strings.TrimSpace(settings[settingOIDCGroupsClaim]); c != "" {
		p.GroupsClaim = c
	}
	return p
}

// ssoAllowlistView is the Settings page's SSO allowlist section.
type ssoAllowlistView struct {
	Domains     string `json:"domains"`
	Emails      string `json:"emails"`
	Groups      string `json:"groups"`
	GroupsClaim string `json:"groups_claim"`
	// From the environment: shown, not editable here.
	EnvDomains string `json:"env_domains"`
	EnvEmails  string `json:"env_emails"`
	EnvGroups  string `json:"env_groups"`
	// Warning is set when SSO providers exist but no rule does, which means
	// every SSO sign-in is being refused.
	Warning string `json:"warning,omitempty"`
}

func (s *Server) ssoAllowlist(settings map[string]string, providers int) ssoAllowlistView {
	v := ssoAllowlistView{
		Domains:     strings.Join(auth.SplitList(settings[settingOIDCAllowedDomains]), "\n"),
		Emails:      strings.Join(auth.SplitList(settings[settingOIDCAllowedEmails]), "\n"),
		Groups:      strings.Join(auth.SplitList(settings[settingOIDCAllowedGroups]), "\n"),
		GroupsClaim: settings[settingOIDCGroupsClaim],
		EnvDomains:  strings.Join(s.cfg.OIDCAllowedDomains, ", "),
		EnvEmails:   strings.Join(s.cfg.OIDCAllowedEmails, ", "),
		EnvGroups:   strings.Join(s.cfg.OIDCAllowedGroups, ", "),
	}
	if v.GroupsClaim == "" {
		v.GroupsClaim = s.cfg.OIDCGroupsClaim
	}
	empty := v.Domains == "" && v.Emails == "" && v.Groups == "" &&
		len(s.cfg.OIDCAllowedDomains)+len(s.cfg.OIDCAllowedEmails)+len(s.cfg.OIDCAllowedGroups) == 0
	if providers > 0 && empty {
		v.Warning = "SSO is configured but no allowlist rule exists, so every SSO sign-in is refused. Add an email domain, an email address or a group below."
	}
	return v
}

// updateSSOAllowlist applies the allowlist fields of a settings update.
// Widening who may sign in needs identity.manage.
func (s *Server) updateSSOAllowlist(w http.ResponseWriter, r *http.Request, domains, emails, groups, claim *string) bool {
	if domains == nil && emails == nil && groups == nil && claim == nil {
		return true
	}
	if !s.requireAdminOr(w, r, auth.PermIdentityManage, "change who may sign in through SSO") {
		return false
	}
	norm := func(v *string) string { return strings.Join(auth.SplitList(*v), "\n") }
	detail := map[string]any{}
	set := map[string]string{}
	if domains != nil {
		var out []string
		for _, d := range auth.SplitList(*domains) {
			d = strings.ToLower(strings.TrimPrefix(d, "@"))
			if strings.ContainsAny(d, " /@") || !strings.Contains(d, ".") {
				http.Error(w, "not an email domain: "+d, http.StatusBadRequest)
				return false
			}
			out = append(out, d)
		}
		set[settingOIDCAllowedDomains] = strings.Join(out, "\n")
		detail["domains"] = out
	}
	if emails != nil {
		for _, e := range auth.SplitList(*emails) {
			if !strings.Contains(e, "@") || strings.ContainsAny(e, " ") {
				http.Error(w, "not an email address: "+e, http.StatusBadRequest)
				return false
			}
		}
		set[settingOIDCAllowedEmails] = norm(emails)
		detail["emails"] = auth.SplitList(*emails)
	}
	if groups != nil {
		set[settingOIDCAllowedGroups] = norm(groups)
		detail["groups"] = auth.SplitList(*groups)
	}
	if claim != nil {
		c := strings.TrimSpace(*claim)
		if strings.ContainsAny(c, " \t\n") || len(c) > 64 {
			http.Error(w, "the groups claim must be a single claim name", http.StatusBadRequest)
			return false
		}
		set[settingOIDCGroupsClaim] = c
		detail["groups_claim"] = c
	}
	if !s.auditIdentity(w, r, "settings.sso_allowlist", "SSO allowlist", detail) {
		return false
	}
	who := auth.CurrentUser(r.Context()).Username
	for k, v := range set {
		if err := s.store.SetSetting(r.Context(), k, v, who); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
	}
	return true
}
