// Package auth is the console's authentication layer: OIDC single sign-on
// (against Authentik or any standards-compliant IdP), a local "break-glass"
// account that never depends on the IdP being reachable, and the
// server-side session/cookie plumbing both share.
//
// SCIM provisioning (internal/server/scim) writes to the same users/groups
// tables this package reads, but SCIM's bearer-token auth is independent of
// everything here — a SCIM sync from Authentik doesn't require anyone to be
// logged into the console.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mustra-dev/mustra/internal/store"
)

// SessionTTL is the default absolute lifetime of a login: however active
// it is, a session older than this signs in again. Twelve hours covers a
// working day and stays inside NIST SP 800-63B's AAL2 limit of one
// reauthentication every 24 hours.
const SessionTTL = 12 * time.Hour

// SessionIdleTimeout is the default server-side idle limit, the hour
// 800-63B allows at AAL2. The console also signs an idle tab out per the
// user's preference, but a control kept only in the browser is one a
// stolen cookie does not obey. An open console polls, so this mostly ends
// sessions whose tab was closed.
const SessionIdleTimeout = time.Hour

// HashSessionToken is what the sessions table stores in place of the
// cookie value: SHA-256, hex. A 256-bit random token needs no salt or
// stretching; the hash only has to make a copy of the table useless.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// OIDCConfig configures single sign-on against one external IdP. Any
// required field left empty disables that provider — the console still
// works via the local backdoor account, and via any other provider.
type OIDCConfig struct {
	// ID is the URL slug this provider is addressed by: /login/sso/<id>
	// and its redirect URI, /auth/callback/<id>.
	ID    string
	Label string // shown on the login button ("Sign in with Microsoft")
	// Kind selects the button's logo and the setup instructions shown in
	// the admin UI ("azure", "google", "discord", "authentik", "okta",
	// "github", "generic"). It never changes the protocol — every provider
	// is plain OIDC discovery — so an IdP that isn't on the list works
	// fine as "generic".
	Kind         string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string // e.g. https://mustra.example.com/auth/callback/google
}

func (c OIDCConfig) enabled() bool {
	return c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
}

// liveProvider is one provider's configuration plus whatever discovery has
// managed to resolve for it so far. oauth2Cfg/verifier stay nil until
// discovery against that issuer succeeds; the login page only offers a
// provider once they're set.
type liveProvider struct {
	cfg       OIDCConfig
	provider  *oidc.Provider
	oauth2Cfg *oauth2.Config
	verifier  *oidc.IDTokenVerifier
}

// ProviderStatus is the login page's view of one provider: enough to draw
// a branded button, and whether it's actually usable yet.
type ProviderStatus struct {
	ID    string
	Label string
	Kind  string
	Ready bool
}

// Auth wires OIDC + local-password + session handling together.
type Auth struct {
	store       *store.Store
	logger      *slog.Logger
	cookieName  string
	cookieHTTPS bool
	bgCtx       context.Context // retained so SetProviders can start fresh discovery goroutines later, not just at New

	mu        sync.RWMutex
	providers map[string]*liveProvider
	// order preserves the admin's provider ordering for the login page,
	// which a map can't.
	order []string

	// discoveryGen guards against a stale discovery goroutine (started
	// before an admin changed the provider list) winning a race against a
	// newer one and clobbering the config it just set.
	discoveryGen atomic.Uint64

	// limiter throttles failed local sign-ins; see ratelimit.go.
	limiter *loginLimiter

	// policy returns the SSO allowlist; see oidc_policy.go.
	policy func(ctx context.Context) OIDCPolicy

	// sessionTTL and sessionIdle bound every session server-side; see
	// SetSessionLimits.
	sessionTTL  time.Duration
	sessionIdle time.Duration

	// mfa is two-step sign-in for local accounts; see totp.go.
	mfa MFAConfig
}

// SetSessionLimits overrides the absolute and idle session lifetimes.
// Zero keeps the default for that limit.
func (a *Auth) SetSessionLimits(absolute, idle time.Duration) {
	if absolute > 0 {
		a.sessionTTL = absolute
	}
	if idle > 0 {
		a.sessionIdle = idle
	}
}

// SessionCookieName is the cookie a session travels in. With Secure
// cookies it carries the __Host- prefix, which browsers only accept from a
// secure origin, for the exact host, path "/" and no Domain attribute — so
// a sibling subdomain can neither set nor overwrite it.
func SessionCookieName(secure bool) string {
	if secure {
		return "__Host-mustra_session"
	}
	return "mustra_session"
}

// New constructs Auth and attempts OIDC discovery in the background if
// oidcCfg is set. Discovery failure (IdP down, misconfigured issuer) never
// blocks startup or disables the local backdoor login — it just means the
// "Sign in with SSO" button won't work until discovery succeeds. This is
// deliberate: it's exactly the scenario the backdoor account exists for.
func New(ctx context.Context, st *store.Store, providers []OIDCConfig, cookieHTTPS bool, logger *slog.Logger) *Auth {
	if logger == nil {
		logger = slog.Default()
	}
	a := &Auth{
		store:       st,
		logger:      logger,
		cookieName:  SessionCookieName(cookieHTTPS),
		sessionTTL:  SessionTTL,
		sessionIdle: SessionIdleTimeout,
		cookieHTTPS: cookieHTTPS,
		bgCtx:       ctx,
		providers:   map[string]*liveProvider{},
		limiter:     newLoginLimiter(),
	}
	a.SetProviders(providers)
	return a
}

// SetProviders replaces the whole provider set (called at startup and from
// the admin API whenever a provider is added, edited, or removed) and kicks
// off fresh discovery for each — no server restart needed. Providers are
// dropped and rebuilt wholesale rather than diffed: discovery is cheap,
// and a rebuild can't leave a half-updated provider behind.
func (a *Auth) SetProviders(cfgs []OIDCConfig) {
	next := map[string]*liveProvider{}
	order := make([]string, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg.ID == "" {
			continue
		}
		next[cfg.ID] = &liveProvider{cfg: cfg}
		order = append(order, cfg.ID)
	}

	a.mu.Lock()
	a.providers = next
	a.order = order
	a.mu.Unlock()

	// One generation for the whole set: any goroutine started for an older
	// set sees the bump and abandons its result rather than writing it into
	// the new one.
	gen := a.discoveryGen.Add(1)
	enabled := 0
	for _, cfg := range cfgs {
		if !cfg.enabled() {
			continue
		}
		enabled++
		go a.discoverProviderWithRetry(a.bgCtx, gen, cfg)
	}
	if enabled == 0 {
		a.logger.Info("no OIDC providers configured; local break-glass login only")
	} else {
		a.logger.Info("OIDC providers configured", "count", enabled)
	}
}

// Providers returns each configured provider and whether discovery has
// resolved it, in the admin's chosen order — what the login page draws
// its buttons from.
func (a *Auth) Providers() []ProviderStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]ProviderStatus, 0, len(a.order))
	for _, id := range a.order {
		p := a.providers[id]
		if p == nil {
			continue
		}
		out = append(out, ProviderStatus{
			ID: p.cfg.ID, Label: p.cfg.Label, Kind: p.cfg.Kind,
			Ready: p.oauth2Cfg != nil && p.verifier != nil,
		})
	}
	return out
}

// lookup returns the live provider for id, or — when id is empty — the
// single configured provider if there is exactly one. The empty case is
// what keeps the pre-multi-IdP URLs (/login/sso, /auth/callback) working
// for an existing single-provider deployment, whose redirect URI is already
// registered at the IdP without a provider slug on the end.
func (a *Auth) lookup(id string) *liveProvider {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if id != "" {
		return a.providers[id]
	}
	if len(a.order) == 1 {
		return a.providers[a.order[0]]
	}
	return nil
}

func (a *Auth) discoverProviderWithRetry(ctx context.Context, gen uint64, cfg OIDCConfig) {
	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second
	for {
		provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
		if a.discoveryGen.Load() != gen {
			return // superseded by a newer SetProviders call; abandon silently
		}
		if err == nil {
			oauth2Cfg := &oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				RedirectURL:  cfg.RedirectURL,
				Endpoint:     provider.Endpoint(),
				Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
			}
			verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

			a.mu.Lock()
			if lp := a.providers[cfg.ID]; lp != nil {
				lp.provider = provider
				lp.oauth2Cfg = oauth2Cfg
				lp.verifier = verifier
			}
			a.mu.Unlock()
			a.logger.Info("OIDC discovery succeeded", "provider", cfg.ID, "issuer", cfg.IssuerURL)
			return
		}
		a.logger.Warn("OIDC discovery failed, will retry", "provider", cfg.ID, "issuer", cfg.IssuerURL, "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if a.discoveryGen.Load() != gen {
			return
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// SSOAvailable reports whether at least one provider is ready to sign
// someone in.
func (a *Auth) SSOAvailable() bool {
	for _, p := range a.Providers() {
		if p.Ready {
			return true
		}
	}
	return false
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand read failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// setSessionCookie issues a new session for userID and sets the cookie.
func (a *Auth) setSessionCookie(ctx context.Context, w http.ResponseWriter, userID string) error {
	token := newToken()
	if _, err := a.store.CreateSession(ctx, HashSessionToken(token), userID, a.sessionTTL); err != nil {
		return err
	}
	// Roll the sign-in stamps here rather than in each login handler, so
	// every way in — local form, SSO — records it without having to
	// remember to. A failure is logged, not fatal: nobody should be locked
	// out because the console could not update a timestamp it shows for
	// information.
	if err := a.store.RecordSignIn(ctx, userID); err != nil {
		a.logger.Warn("could not record sign-in time", "user_id", userID, "error", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cookieHTTPS,
		// Strict: the session is never sent on a request another site
		// started, not even a top-level link. The two places that breaks
		// are handled where they happen: the OIDC callback finishes with a
		// same-origin hop (finishSignIn), and a cross-site link into the
		// console is re-requested from our own origin once (RequireAuth's
		// bounce) so the cookie can be sent.
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(a.sessionTTL.Seconds()),
	})
	return nil
}

// writeAuthError renders a plain-text error response that names the stage
// that failed and includes the underlying error, which is what makes a
// broken OIDC configuration debuggable from the browser. A 500 is replaced
// with a generic message and a request ID by the server's error middleware
// (internal/server/errorscrub.go), so database and other internal failures
// still stay in the log.
func writeAuthError(w http.ResponseWriter, status int, stage string, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	if err != nil {
		fmt.Fprintf(w, "sign-in failed at: %s\n\n%v\n", stage, err)
	} else {
		fmt.Fprintf(w, "sign-in failed at: %s\n", stage)
	}
}

func (a *Auth) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cookieHTTPS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
