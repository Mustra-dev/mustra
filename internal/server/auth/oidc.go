package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// resolveOIDCUser finds or creates the console account for an IdP
// identity, keyed on (issuer, subject).
//
// An account created before identities were keyed this way (source oidc,
// or a SCIM-provisioned one whose externalId is the subject) is linked on
// first sign-in only while exactly one provider is configured — the
// single-IdP deployment those rows came from. With more than one, a bare
// subject cannot say which IdP it belongs to, so a new account is created
// instead of guessing.
//
// The username is chosen once. Later sign-ins refresh email and display
// name, never the username.
func (a *Auth) resolveOIDCUser(ctx context.Context, providerID, issuer, subject, preferred, email, name string) (*store.User, error) {
	u, err := a.store.GetUserByOIDCIdentity(ctx, issuer, subject)
	if err != nil {
		return nil, err
	}
	if u == nil && a.providerCount() == 1 {
		legacy, err := a.store.GetUserByExternalID(ctx, subject)
		if err != nil {
			return nil, err
		}
		if legacy != nil && (legacy.Source == "oidc" || legacy.Source == "scim") {
			u = legacy
		}
	}
	if u == nil {
		base := usernameFromClaims(preferred, email, subject)
		for _, candidate := range []string{base, disambiguatedUsername(base, issuer, subject)} {
			display := name
			if display == "" {
				display = candidate
			}
			created, err := a.store.CreateOIDCUser(ctx, idgen.New("usr-oidc-"), candidate, email, display)
			if err != nil {
				return nil, err
			}
			if created != nil {
				u = created
				break
			}
		}
		if u == nil {
			return nil, fmt.Errorf("no free username for %q", base)
		}
		a.logger.Info("sso account created", "username", u.Username, "provider", providerID, "issuer", issuer)
	}
	if err := a.store.LinkOIDCIdentity(ctx, issuer, subject, u.ID, providerID); err != nil {
		return nil, err
	}
	display := name
	if display == "" {
		display = u.DisplayName
	}
	if err := a.store.RefreshOIDCProfile(ctx, u.ID, email, display); err != nil {
		a.logger.Warn("refreshing sso profile failed", "username", u.Username, "error", err)
	}
	return u, nil
}

func (a *Auth) providerCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.order)
}

const (
	stateCookieName = "mustra_oidc_state"
	nextCookieName  = "mustra_oidc_next"
	// nonceCookieName binds the ID token to this browser's flow (replay of
	// a token issued for another sign-in fails), and pkceCookieName holds
	// the PKCE verifier, so an intercepted authorization code is useless
	// without it.
	nonceCookieName = "mustra_oidc_nonce"
	pkceCookieName  = "mustra_oidc_pkce"
	oidcCookieTTL   = 5 * time.Minute
)

// HandleSSOLogin starts the OIDC authorization code flow for the provider
// named in the {provider} path value (empty on the legacy /login/sso path,
// which resolves to the only provider when there is exactly one). If
// discovery hasn't completed, it reports 503 rather than redirecting
// somewhere broken — the login page only offers providers that are ready,
// so reaching this handler otherwise means a stale page or a direct hit;
// either way 503 is honest.
func (a *Auth) HandleSSOLogin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	lp := a.lookup(id)
	if lp == nil {
		writeAuthError(w, http.StatusNotFound, "provider lookup", fmt.Errorf("no identity provider %q is configured", id))
		return
	}
	a.mu.RLock()
	oauth2Cfg := lp.oauth2Cfg
	a.mu.RUnlock()
	if oauth2Cfg == nil {
		writeAuthError(w, http.StatusServiceUnavailable, "SSO availability check", fmt.Errorf("discovery against %q has not succeeded yet (check server logs for \"OIDC discovery failed\")", lp.cfg.IssuerURL))
		return
	}
	state := newToken()
	nonce := newToken()
	verifier := oauth2.GenerateVerifier()
	next := sanitizeNext(r.URL.Query().Get("next"))

	setShortCookie(w, stateCookieName, state, oidcCookieTTL, a.cookieHTTPS)
	setShortCookie(w, nextCookieName, next, oidcCookieTTL, a.cookieHTTPS)
	setShortCookie(w, nonceCookieName, nonce, oidcCookieTTL, a.cookieHTTPS)
	setShortCookie(w, pkceCookieName, verifier, oidcCookieTTL, a.cookieHTTPS)

	http.Redirect(w, r, oauth2Cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// HandleSSOCallback completes the flow: verifies state (CSRF), exchanges
// the code, verifies the ID token, and upserts a local user record keyed on
// the IdP's subject claim. Which provider it's completing comes from the
// {provider} path value, so two IdPs can be mid-flow in different tabs
// without their callbacks being confused for each other.
func (a *Auth) HandleSSOCallback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	lp := a.lookup(id)
	if lp == nil {
		writeAuthError(w, http.StatusNotFound, "provider lookup", fmt.Errorf("no identity provider %q is configured", id))
		return
	}
	a.mu.RLock()
	oauth2Cfg := lp.oauth2Cfg
	verifier := lp.verifier
	providerID := lp.cfg.ID
	a.mu.RUnlock()
	if oauth2Cfg == nil || verifier == nil {
		writeAuthError(w, http.StatusServiceUnavailable, "SSO availability check", fmt.Errorf("discovery against %q has not succeeded yet (check server logs for \"OIDC discovery failed\")", lp.cfg.IssuerURL))
		return
	}

	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil {
		writeAuthError(w, http.StatusBadRequest, "state cookie", fmt.Errorf("missing %s cookie (did too much time pass, or are cookies blocked?): %w", stateCookieName, err))
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(stateCookie.Value)) != 1 {
		writeAuthError(w, http.StatusBadRequest, "state check", fmt.Errorf("the state parameter did not match — possible CSRF or a stale/replayed callback URL"))
		return
	}
	next := "/"
	if nextCookie, err := r.Cookie(nextCookieName); err == nil {
		next = sanitizeNext(nextCookie.Value)
	}
	nonceCookie, nerr := r.Cookie(nonceCookieName)
	pkceCookie, perr := r.Cookie(pkceCookieName)
	clearShortCookie(w, stateCookieName, a.cookieHTTPS)
	clearShortCookie(w, nextCookieName, a.cookieHTTPS)
	clearShortCookie(w, nonceCookieName, a.cookieHTTPS)
	clearShortCookie(w, pkceCookieName, a.cookieHTTPS)
	if nerr != nil || perr != nil || nonceCookie.Value == "" || pkceCookie.Value == "" {
		writeAuthError(w, http.StatusBadRequest, "sign-in flow cookies", fmt.Errorf("the sign-in was started in another browser or too long ago; start again"))
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		errParam := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		writeAuthError(w, http.StatusBadRequest, "authorization redirect", fmt.Errorf("no authorization code in callback (idp reported error=%q description=%q)", errParam, errDesc))
		return
	}

	ctx := r.Context()
	token, err := oauth2Cfg.Exchange(ctx, code, oauth2.VerifierOption(pkceCookie.Value))
	if err != nil {
		a.logger.Error("oidc code exchange failed", "error", err)
		writeAuthError(w, http.StatusBadGateway, "token exchange (code -> tokens at the IdP's token endpoint)", err)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		a.logger.Error("oidc token response missing id_token")
		writeAuthError(w, http.StatusBadGateway, "token exchange", fmt.Errorf("token response had no id_token field — check the client is requesting the openid scope"))
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		a.logger.Error("oidc id_token verification failed", "error", err)
		writeAuthError(w, http.StatusBadGateway, "id_token verification (signature/issuer/audience/expiry check)", err)
		return
	}

	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonceCookie.Value)) != 1 {
		a.logger.Warn("oidc id_token nonce mismatch", "provider", providerID)
		writeAuthError(w, http.StatusBadRequest, "id_token nonce check", fmt.Errorf("the ID token was not issued for this sign-in"))
		return
	}

	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	raw := map[string]any{}
	if err := idToken.Claims(&claims); err != nil || idToken.Claims(&raw) != nil {
		a.logger.Error("oidc claims decode failed", "error", err)
		writeAuthError(w, http.StatusBadGateway, "decoding id_token claims", err)
		return
	}
	if claims.Subject == "" {
		writeAuthError(w, http.StatusBadGateway, "id_token claims", fmt.Errorf("the ID token has no subject"))
		return
	}

	// The allowlist. No rule means no SSO sign-in at all: an IdP anyone can
	// make an account at must not be a way into the console.
	if ok, why := a.oidcPolicy(ctx).Allows(raw); !ok {
		a.logger.Warn("sso login refused by allowlist", "provider", providerID, "issuer", idToken.Issuer,
			"subject", claims.Subject, "email", claims.Email, "reason", why)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "sign-in refused: %s.\nAsk an administrator to allow your account under Settings -> SSO allowlist.\n", why)
		return
	}

	user, err := a.resolveOIDCUser(ctx, providerID, idToken.Issuer, claims.Subject, claims.PreferredUsername, claims.Email, claims.Name)
	if err != nil {
		a.logger.Error("resolving oidc user failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "saving the user record", fmt.Errorf("the account could not be saved"))
		return
	}
	if !user.Active {
		a.logger.Warn("sso login for an inactive account", "username", user.Username)
		writeAuthError(w, http.StatusForbidden, "account state", fmt.Errorf("this account is deactivated"))
		return
	}
	username := user.Username
	if err := a.setSessionCookie(ctx, w, user.ID); err != nil {
		a.logger.Error("create session failed", "error", err)
		writeAuthError(w, http.StatusInternalServerError, "creating the session", err)
		return
	}
	a.logger.Info("sso login succeeded", "provider", providerID, "username", username, "subject", claims.Subject)
	// Not a 302: this request was started by the IdP's site, and the new
	// SameSite=Strict session cookie would not ride along a redirect
	// chain that began there. A same-origin hop does carry it.
	WriteSameOriginRedirect(w, next)
}

func setShortCookie(w http.ResponseWriter, name, value string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func clearShortCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
