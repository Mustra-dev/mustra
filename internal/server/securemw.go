package server

import (
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// The outermost layer of every HTTP response: cross-origin request refusal
// and the security headers that are not page-specific. (The HTML pages'
// Content-Security-Policy is set where the pages are served.)

// secureHandler wraps the whole router.
func (s *Server) secureHandler(next http.Handler) http.Handler {
	trusted := trustedOrigins(os.Getenv("MUSTRA_TRUSTED_ORIGINS"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, r, s.cfg.CookieSecure)
		applyBodyLimits(w, r)
		if !safeMethod(r.Method) && !csrfExempt(r) {
			if reason := crossOriginReason(r, trusted); reason != "" {
				if s.logger != nil {
					s.logger.Warn("cross-origin request refused", "method", r.Method, "path", r.URL.Path,
						"origin", r.Header.Get("Origin"), "sec_fetch_site", r.Header.Get("Sec-Fetch-Site"), "reason", reason)
				}
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// setSecurityHeaders applies the response headers every route shares.
// Handlers that need something different (the self-service preview frame)
// overwrite them after this runs.
func setSecurityHeaders(w http.ResponseWriter, r *http.Request, secureMode bool) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()")
	// HSTS only when the console is actually HTTPS from the browser's point
	// of view: secure-cookie mode says so (a tunnel terminates TLS before
	// us), and so does a direct TLS connection. Sending it over a plain
	// LAN listener would be ignored at best.
	if secureMode || r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		// API responses carry fleet data and, in a few places, secrets
		// shown once. Nothing in between should keep a copy.
		h.Set("Cache-Control", "no-store")
	}
}

// Request size and time limits.
//
// The server's ReadTimeout bounds how long a client may take to send a
// request; a few routes legitimately take longer (multi-gigabyte uploads)
// or hold the connection open on purpose (server-sent event streams), and
// get their own deadline here. Every body is capped: most JSON handlers
// decoded r.Body with no limit at all.
const (
	defaultBodyLimit = 16 << 20
	unauthBodyLimit  = 64 << 10
	uploadDeadline   = 4 * time.Hour
)

// uploadLimits are the routes whose bodies are files, by pattern.
var uploadLimits = []struct {
	re    *regexp.Regexp
	limit int64
}{
	{regexp.MustCompile(`^/api/software/[^/]+/files$`), maxPackageFileBytes + 1<<20},
	{regexp.MustCompile(`^/api/backups/restore$`), maxUploadedBackup + 1<<20},
	{regexp.MustCompile(`^/api/deploy/packages/[^/]+/revisions$`), 64 << 20},
	{regexp.MustCompile(`^/api/compliance/import$`), 64 << 20},
}

func applyBodyLimits(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	if r.Method == http.MethodGet && (strings.HasSuffix(r.URL.Path, "/stream") || strings.Contains(r.Header.Get("Accept"), "text/event-stream")) {
		// A live stream reads nothing after the request line; without this
		// the server's read deadline would cancel it.
		_ = rc.SetReadDeadline(time.Time{})
		return
	}
	if safeMethod(r.Method) || r.Body == nil || r.Body == http.NoBody {
		return
	}
	limit := int64(defaultBodyLimit)
	switch {
	case r.URL.Path == "/login/local" || r.URL.Path == "/setup" || r.URL.Path == "/logout" ||
		strings.HasPrefix(r.URL.Path, "/hooks/"):
		limit = unauthBodyLimit
	default:
		for _, u := range uploadLimits {
			if u.re.MatchString(r.URL.Path) {
				limit = u.limit
				_ = rc.SetReadDeadline(time.Now().Add(uploadDeadline))
				break
			}
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions || m == http.MethodTrace
}

// csrfExempt names the requests the browser-origin check does not apply
// to, because they are not authenticated by an ambient browser credential:
//
//   - Authorization: Bearer — API tokens and SCIM. A cross-site page cannot
//     attach an Authorization header without a CORS preflight, which this
//     server never approves, so its presence proves the caller is not a
//     forged browser request.
//   - /hooks/playbook/{token} — called server-to-server by outside systems;
//     the unguessable token in the path is the whole credential and no
//     cookie is consulted.
//
// Agent-facing downloads are all GET and never reach the check.
func csrfExempt(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/hooks/playbook/") {
		return true
	}
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return true
	}
	return false
}

// crossOriginReason returns why a state-changing request must be refused,
// or "" to let it through. The request's own origin is the scheme-less
// host it was sent to: a browser always sets Host to the site it is
// talking to, and an attacker's page cannot make it name ours while
// sending its own Origin.
//
// Order of evidence: Origin, then Sec-Fetch-Site, then Referer. A request
// with none of the three is not from a modern browser (curl, a script with
// a session cookie it was handed) and is allowed: CSRF is a browser attack.
func crossOriginReason(r *http.Request, trusted map[string]bool) string {
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin == "null" {
			return "opaque origin"
		}
		if originMatches(origin, r.Host, trusted) {
			return ""
		}
		return "origin mismatch"
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return ""
	case "":
	default:
		return "sec-fetch-site " + r.Header.Get("Sec-Fetch-Site")
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if originMatches(ref, r.Host, trusted) {
			return ""
		}
		return "referer mismatch"
	}
	return ""
}

// originMatches reports whether an Origin or Referer value names this host
// (or one of the explicitly trusted origins).
func originMatches(raw, host string, trusted map[string]bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	if trusted[strings.ToLower(u.Scheme+"://"+u.Host)] {
		return true
	}
	return host != "" && strings.EqualFold(u.Host, host)
}

// trustedOrigins parses MUSTRA_TRUSTED_ORIGINS: extra scheme://host[:port]
// origins allowed to make state-changing requests, for a console reached
// through a proxy that rewrites Host.
func trustedOrigins(v string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		u, err := url.Parse(part)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		out[strings.ToLower(u.Scheme+"://"+u.Host)] = true
	}
	return out
}
