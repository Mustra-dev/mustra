package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/updatesig"
)

// The console's public URL: the one base every agent-facing URL is built
// from — install one-liners, binary downloads, package and sensor
// downloads, the legacy update command.
//
// It used to be learned from whatever Host and X-Forwarded-Proto header the
// last unauthenticated /install.sh request carried, and then trusted as the
// place agents fetched and ran their updater from. One forged header made
// that the attacker's server. Now it is configuration: MUSTRA_PUBLIC_URL,
// or the setting an administrator enters in the console. A value the old
// code had remembered is shown there as a suggestion and is not used until
// somebody confirms it.

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// validatePublicURL returns the normalized scheme://host[:port], or why the
// value cannot be the console's public URL. Plain http is accepted only
// when allowHTTP, which is for local development: enrollment tokens and
// session cookies cross this URL.
func validatePublicURL(raw string, allowHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return "", errors.New("must be https (plain http is only accepted with the development override)")
		}
	default:
		return "", errors.New("must start with https://")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("must be just scheme://host[:port], with no credentials, query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("serving the console under a path is not supported; use the bare host")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip == nil && !hostnamePattern.MatchString(host) {
		return "", errors.New("host is not a valid hostname or IP address")
	}
	if port := u.Port(); port != "" {
		for _, c := range port {
			if c < '0' || c > '9' {
				return "", errors.New("port is not numeric")
			}
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

// errNoPublicURL is what agent-facing handlers report until one is set.
var errNoPublicURL = errors.New("the console's public URL is not configured: set MUSTRA_PUBLIC_URL, or enter it under Administration → Settings → Agent identity")

// agentPublicURL returns the configured public URL. It has the signature
// the old settingAgentConsoleURL read had, so callers swap one for the
// other.
func (s *Server) agentPublicURL(ctx context.Context) (string, error) {
	if s.trust != nil && s.trust.publicURLEnv != "" {
		return s.trust.publicURLEnv, nil
	}
	v, err := s.store.GetSetting(ctx, settingAgentPublicURL)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errNoPublicURL
	}
	httpOK, _ := s.store.GetSetting(ctx, settingAgentPublicURLHTTPOK)
	norm, err := validatePublicURL(v, httpOK == "true")
	if err != nil {
		return "", fmt.Errorf("the stored public URL is not valid (%v); correct it in Settings", err)
	}
	return norm, nil
}

// agentPublicURLOrEmpty has the exact semantics of the old
// GetSetting(settingAgentConsoleURL) read — "" with no error when nothing
// is configured — for callers that only need a URL in some cases.
func (s *Server) agentPublicURLOrEmpty(ctx context.Context) (string, error) {
	v, err := s.agentPublicURL(ctx)
	if errors.Is(err, errNoPublicURL) {
		return "", nil
	}
	return v, err
}

// Values spliced into the install scripts. Each is validated against a
// strict charset here, and every template still single-quotes it: the
// validation is what the value may be, the quoting is what makes the shell
// treat it as data whatever it turns out to be.
var (
	sitePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	natsURLPattern = regexp.MustCompile(`^(nats|tls)://[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^(nats|tls)://\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)
)

const defaultSite = "default"

func validSite(site string) bool { return sitePattern.MatchString(site) }

// sanitizeSite makes an agent-reported site safe to use as a subject token
// and to display. It does not refuse: an agent that reports a strange site
// still belongs in inventory.
func sanitizeSite(site string) string {
	if validSite(site) {
		return site
	}
	var b strings.Builder
	for _, r := range site {
		if b.Len() >= 64 {
			break
		}
		if r < 128 && (r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return defaultSite
	}
	return b.String()
}

// shQuote renders s as a POSIX shell single-quoted word.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// psQuoteString renders s as a PowerShell single-quoted string literal.
// PowerShell also treats the typographic quotes as quote characters, so
// those are doubled too.
func psQuoteString(s string) string {
	r := strings.NewReplacer("'", "''", "‘", "‘‘", "’", "’’", "‚", "‚‚", "‛", "‛‛")
	return "'" + r.Replace(s) + "'"
}

// --- Settings API ---------------------------------------------------------

type agentTrustSettings struct {
	PublicURL        string `json:"public_url"`
	PublicURLFromEnv bool   `json:"public_url_from_env"`
	AllowHTTP        bool   `json:"allow_http"`
	Suggestion       string `json:"suggestion,omitempty"`
	// LegacyAllowed is always false: the shared agent credential is
	// retired (#231). Kept so scripts reading it keep working.
	LegacyAllowed bool `json:"legacy_allowed"`
	// LegacyConfigured: the server still has the old shared password in
	// its environment (MUSTRA_NATS_AGENT_PASSWORD), which is now unused.
	LegacyConfigured  bool   `json:"legacy_configured"`
	NeedsReenrollment int    `json:"needs_reenrollment"`
	Enforced          bool   `json:"identity_enforced"`
	SigningKeyID      string `json:"signing_key_id,omitempty"`
	SigningMode       string `json:"signing_mode"`
	// CallerIsAdmin says the caller may change these fields: an
	// administrator, or someone holding agents.trust (handlePutAgentTrust).
	// The console shows them read-only to everyone else. The name predates
	// the permission.
	CallerIsAdmin bool `json:"caller_is_admin"`
}

func (s *Server) handleGetAgentTrust(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := agentTrustSettings{Enforced: s.identityEnforced(), SigningMode: "none", CallerIsAdmin: s.callerMayChange(ctx, auth.PermAgentTrustManage)}
	if s.trust != nil {
		out.LegacyConfigured = s.trust.legacyPassword != ""
		if s.trust.publicURLEnv != "" {
			out.PublicURL, out.PublicURLFromEnv, out.AllowHTTP = s.trust.publicURLEnv, true, s.trust.publicURLEnvHTTP
		}
		if s.trust.signPub != nil {
			out.SigningKeyID = updatesig.KeyID(s.trust.signPub)
			out.SigningMode = "release-signed"
			if s.trust.signKey != nil {
				out.SigningMode = "deployment key"
			}
		}
	}
	if !out.PublicURLFromEnv {
		out.PublicURL, _ = s.store.GetSetting(ctx, settingAgentPublicURL)
		v, _ := s.store.GetSetting(ctx, settingAgentPublicURLHTTPOK)
		out.AllowHTTP = v == "true"
	}
	// The URL the old code remembered from request headers. Offered, never
	// used: it may have been written by anyone who could send a request.
	if remembered, _ := s.store.GetSetting(ctx, settingAgentConsoleURL); remembered != "" && out.PublicURL == "" {
		out.Suggestion = remembered
	}
	out.LegacyAllowed = s.legacyAllowed(ctx)
	if ids, err := s.store.ListAgentIdentities(ctx); err == nil {
		for _, a := range ids {
			if !a.Enrolled {
				out.NeedsReenrollment++
			}
		}
	}
	writeJSONResponse(w, out)
}

// putAgentTrustRequest is the body of PUT /api/agent-trust. A field left
// out keeps its current value.
type putAgentTrustRequest struct {
	// PublicURL is the root agents download from; empty clears it.
	PublicURL *string `json:"public_url"`
	// AllowHTTP accepts an http:// public URL. It is checked together
	// with the URL, stored or sent, so false under an http:// URL is
	// refused.
	AllowHTTP *bool `json:"allow_http"`
	// LegacyAllowed may only be false: the shared credential is retired,
	// and asking for true is refused with 409.
	LegacyAllowed *bool `json:"legacy_allowed"`
}

func (s *Server) handlePutAgentTrust(w http.ResponseWriter, r *http.Request) {
	// settings.manage reads these, but the public URL is the download root
	// for every install and update (binary, checksum, CA), so changing it is reserved to
	// an administrator — the same line escalation.go draws for the agents'
	// NATS address and the break-glass account.
	if !s.requireAdminOr(w, r, auth.PermAgentTrustManage, "change the agent trust settings (public URL and legacy credential)") {
		return
	}
	var req putAgentTrustRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.LegacyAllowed != nil && *req.LegacyAllowed {
		http.Error(w, "the legacy shared agent credential is retired and cannot be allowed again; enroll agents with a token", http.StatusConflict)
		return
	}
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	if req.PublicURL != nil || req.AllowHTTP != nil {
		if s.trust != nil && s.trust.publicURLEnv != "" {
			http.Error(w, "the public URL is set by MUSTRA_PUBLIC_URL and cannot be changed here", http.StatusConflict)
			return
		}
		// Either one left out keeps its stored value. allow_http used to
		// read as false whenever it was missing, which turned a URL change
		// into an opt-out of plain HTTP. The pair is validated together, so
		// switching HTTP off under an http:// URL is refused.
		var publicURL string
		if req.PublicURL != nil {
			publicURL = *req.PublicURL
		} else {
			stored, err := s.store.GetSetting(ctx, settingAgentPublicURL)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			publicURL = stored
		}
		var allowHTTP bool
		if req.AllowHTTP != nil {
			allowHTTP = *req.AllowHTTP
		} else {
			stored, err := s.store.GetSetting(ctx, settingAgentPublicURLHTTPOK)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			allowHTTP = stored == "true"
		}
		value := ""
		if strings.TrimSpace(publicURL) != "" {
			norm, err := validatePublicURL(publicURL, allowHTTP)
			if err != nil {
				http.Error(w, "public URL: "+err.Error(), http.StatusBadRequest)
				return
			}
			value = norm
		}
		httpValue := "false"
		if allowHTTP {
			httpValue = "true"
		}
		if err := s.store.SetSetting(ctx, settingAgentPublicURLHTTPOK, httpValue, who); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.store.SetSetting(ctx, settingAgentPublicURL, value, who); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(ctx, auditEvent{Action: "settings.public_url", Actor: who, Target: value, Severity: "critical",
			Detail: map[string]any{"allow_http": allowHTTP}})
	}
	s.handleGetAgentTrust(w, r)
}
