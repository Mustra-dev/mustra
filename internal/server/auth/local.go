package auth

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

// loginFloor is the least time a failed sign-in takes to answer. Unknown
// accounts already pay for a bcrypt comparison against a dummy hash; the
// floor also hides the database lookup and any difference between "no such
// user", "inactive" and "wrong password".
const loginFloor = 400 * time.Millisecond

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// dummyPasswordHash is a real bcrypt hash of nothing anyone knows, so a
// sign-in for an account that does not exist costs what one that does
// costs.
func dummyPasswordHash() string {
	dummyHashOnce.Do(func() {
		h, err := HashPassword(newToken())
		if err == nil {
			dummyHash = h
		}
	})
	return dummyHash
}

// HandleLocalLogin is the break-glass login path: username/password checked
// against the bcrypt hash in Postgres, with no dependency on the OIDC
// provider being reachable at all. This is what makes it usable when SSO is
// down — it's a completely separate code path, not a fallback bolted onto
// the OIDC flow.
func (a *Auth) HandleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectLoginError(w, r, "could not parse the login form: "+err.Error())
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	next := sanitizeNext(r.FormValue("next"))
	ip := ClientIP(r)
	started := time.Now()
	// Every failure leaves at the same pace, whatever the reason.
	slowFail := func(reason string) {
		if d := loginFloor - time.Since(started); d > 0 {
			time.Sleep(d)
		}
		redirectLoginError(w, r, reason)
	}

	if wait := a.limiter.blocked(ip, username); wait > 0 {
		a.logger.Warn("local login throttled", "username", username, "ip", ip, "retry_in", wait.Round(time.Second))
		w.Header().Set("Retry-After", itoa(int(wait.Seconds())+1))
		slowFail("too many failed sign-in attempts; try again later")
		return
	}

	user, err := a.store.GetUserByUsername(r.Context(), username)
	if err != nil {
		a.logger.Error("local login lookup failed", "error", err)
		slowFail("sign-in is temporarily unavailable")
		return
	}
	// Credential failures (unknown user, wrong source, inactive, bad
	// password) deliberately stay generic — unlike the operational errors
	// above, detail here would just help someone enumerate valid usernames.
	// The comparison always runs, against a dummy hash when there is no
	// usable account, so the time it takes says nothing either.
	hash := dummyPasswordHash()
	usable := user != nil && user.Source == "local" && user.Active && user.PasswordHash != ""
	if usable {
		hash = user.PasswordHash
	}
	if !VerifyPassword(hash, password) || !usable {
		a.limiter.fail(ip, username)
		a.logger.Warn("local login failed", "username", username, "ip", ip)
		slowFail("invalid username or password")
		return
	}
	a.limiter.succeed(ip, username)

	// A code may still be owed (or, where an administrator requires it,
	// an authenticator to set up) before any session exists.
	if a.secondStep(w, r, user, next) {
		return
	}

	if err := a.setSessionCookie(r.Context(), w, user.ID); err != nil {
		a.logger.Error("create session failed", "error", err)
		redirectLoginError(w, r, "creating the session failed: "+err.Error())
		return
	}
	a.logger.Info("local login succeeded", "username", username)
	http.Redirect(w, r, next, http.StatusFound)
}

func redirectLoginError(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(reason), http.StatusFound)
}

// HandleLogout clears the session both client- and server-side.
func (a *Auth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(a.cookieName); err == nil {
		if err := a.store.DeleteSession(r.Context(), HashSessionToken(cookie.Value)); err != nil {
			a.logger.Warn("delete session on logout failed", "error", err)
		}
	}
	a.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// sanitizeNext only allows a same-site relative path, never an absolute URL
// (open-redirect prevention) — a login form field is attacker-controllable
// input.
//
// Browsers treat a backslash as a slash and drop tabs and newlines inside
// a URL, so "/\evil.example" and "/\t/evil.example" both navigate off-site
// even though neither starts with "//". Anything with a backslash or a
// control character is refused outright, and what remains must parse as a
// bare path: no scheme, no host.
func sanitizeNext(next string) string {
	if next == "" || next[0] != '/' || len(next) > 1 && (next[1] == '/' || next[1] == '\\') {
		return "/"
	}
	if len(next) > 2048 || strings.ContainsRune(next, '\\') || strings.IndexFunc(next, unicode.IsControl) >= 0 {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return next
}

func itoa(n int) string {
	if n <= 0 {
		return "1"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
