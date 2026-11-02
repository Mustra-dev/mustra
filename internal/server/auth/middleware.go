package auth

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/mustra-dev/mustra/internal/store"
)

type ctxKey int

const userCtxKey ctxKey = 0

func withUser(ctx context.Context, u *store.User) context.Context {
	return context.WithValue(ctx, userCtxKey, u)
}

// WithUser attaches a user to a context that did not come from a browser
// request. It exists for replaying an operation somebody approved: the
// work runs later, under the identity of whoever asked for it, so the
// audit trail and every permission check name the requester rather than
// the approver or the server itself.
func WithUser(ctx context.Context, u *store.User) context.Context {
	return withUser(ctx, u)
}

// CurrentUser returns the authenticated user for this request, or nil if
// called outside RequireAuth (shouldn't happen for any protected route).
func CurrentUser(ctx context.Context) *store.User {
	u, _ := ctx.Value(userCtxKey).(*store.User)
	return u
}

// RequireAuth protects a handler behind a valid session. API routes get a
// plain 401 (the console JS handles that by redirecting to /login itself);
// everything else gets an HTTP redirect to /login carrying the original URL
// so login lands the user back where they started.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An API token is checked first: a request carrying one is a script,
		// not a browser, so a failed token should 401 rather than redirect
		// into a login page it can't use.
		if token := bearerToken(r); token != "" {
			user, grant := a.authenticateToken(r.Context(), token)
			if user == nil {
				http.Error(w, "invalid or expired API token", http.StatusUnauthorized)
				return
			}
			ctx := WithToken(withUser(r.Context(), user), grant.perms, grant.info)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		cookie, err := r.Cookie(a.cookieName)
		if err != nil || cookie.Value == "" {
			a.denyOrRedirect(w, r)
			return
		}
		user, err := a.store.GetSessionUser(r.Context(), HashSessionToken(cookie.Value), a.sessionIdle)
		if err != nil {
			a.logger.Error("session lookup failed", "error", err)
			http.Error(w, "session lookup failed", http.StatusInternalServerError)
			return
		}
		if user == nil {
			a.denyOrRedirect(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

// HasPermission checks u's effective permissions: the legacy is_admin flag
// is a fast path granting everything unconditionally (what makes the
// backdoor account, and any SCIM/OIDC user promoted the old way, fully
// privileged without needing a seeded role-assignment row); otherwise it's
// the union of every role assigned directly to u or to any group u belongs
// to.
func (a *Auth) HasPermission(ctx context.Context, u *store.User, perm string) (bool, error) {
	if u == nil {
		return false, nil
	}
	// An API token carries its own permission set and never inherits admin,
	// so it's answered from the context rather than the role tables.
	if perms, ok := TokenPermissions(ctx); ok {
		for _, p := range perms {
			if p == perm {
				return true, nil
			}
		}
		return false, nil
	}
	if u.IsAdmin {
		return true, nil
	}
	perms, err := a.store.EffectivePermissions(ctx, u.ID)
	if err != nil {
		return false, err
	}
	return perms[perm], nil
}

// GrantedPermissions returns every permission key u currently holds — the
// legacy is_admin flag short-circuits to the full set, otherwise it's
// whatever EffectivePermissions in the store computes. Used by /api/me so
// the console's own JS knows which admin tabs to show without probing each
// admin route.
func (a *Auth) GrantedPermissions(ctx context.Context, u *store.User) ([]string, error) {
	if u == nil {
		return nil, nil
	}
	if perms, ok := TokenPermissions(ctx); ok {
		return perms, nil
	}
	if u.IsAdmin {
		return AllPermissions, nil
	}
	perms, err := a.store.EffectivePermissions(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(perms))
	for p := range perms {
		out = append(out, p)
	}
	return out, nil
}

// RequirePermission protects a handler behind both a valid session (must be
// composed inside RequireAuth) and a specific permission. API routes 403
// with a plain-text reason rather than redirecting — every caller here is
// the console's own JS, not a browser navigation.
func (a *Auth) RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := CurrentUser(r.Context())
			ok, err := a.HasPermission(r.Context(), u, perm)
			if err != nil {
				a.logger.Error("permission check failed", "error", err, "permission", perm)
				http.Error(w, "permission check failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "forbidden: this action requires the \""+perm+"\" permission", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission admits a caller holding any one of several
// permissions. It exists for routes two different jobs legitimately reach
// from opposite directions — a Direct Connect transcript is read by the
// operator who ran the session and by an auditor who may not open one —
// where demanding a single key would force one of them to hold the
// other's powers.
func (a *Auth) RequireAnyPermission(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := CurrentUser(r.Context())
			for _, p := range perms {
				ok, err := a.HasPermission(r.Context(), u, p)
				if err != nil {
					a.logger.Error("permission check failed", "error", err, "permission", p)
					http.Error(w, "permission check failed: "+err.Error(), http.StatusInternalServerError)
					return
				}
				if ok {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "forbidden: this action requires one of \""+strings.Join(perms, "\", \"")+"\"", http.StatusForbidden)
		})
	}
}

func (a *Auth) denyOrRedirect(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// A link from another site (a chat message, a ticket) arrives without
	// the SameSite=Strict session cookie even when the browser holds one.
	// Asking the browser to load the same URL again from our own page makes
	// it a same-origin navigation, which does carry the cookie. Only once,
	// and only for a plain page load: the second arrival says same-origin.
	if r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Site") == "cross-site" && r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		WriteSameOriginRedirect(w, sanitizeNext(r.URL.RequestURI()))
		return
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
}

// WriteSameOriginRedirect answers with a page that navigates to target
// from this origin. A 302 would keep the navigation attributed to the site
// that started it, and a SameSite=Strict cookie would not be sent with the
// follow-up request. target must already be a sanitized local path.
func WriteSameOriginRedirect(w http.ResponseWriter, target string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	esc := html.EscapeString(target)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8">` +
		`<meta http-equiv="refresh" content="0;url=` + esc + `"><title>Signing in…</title></head>` +
		`<body><p><a href="` + esc + `">Continue</a></p></body></html>`))
}

// SafeNext is sanitizeNext for callers outside this package: a local path
// that is safe to redirect to, or "/".
func SafeNext(next string) string { return sanitizeNext(next) }
