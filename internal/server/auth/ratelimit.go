package auth

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Login throttling.
//
// A password form on a console that can run commands as root on a fleet is
// worth guessing at, so failed sign-ins are counted under two keys:
//
//	ip+username  the ordinary case: one client hammering one account
//	ip           one address spraying many accounts
//
// Each key locks out with exponential backoff once it passes its own
// threshold. The lock applies whether or not the account exists, so the
// throttle itself says nothing about which usernames are real.
//
// There is deliberately no account-wide (username-only) key. This is the
// break-glass login — the one way back in when SSO is down — so a key that
// locked an account across every address would let anyone, from anywhere,
// lock the owner out of their own emergency access by failing a handful of
// times. Per-address limits still bound every guesser; a distributed guess
// is slowed per address rather than answered by locking the real owner out.

type loginAttempt struct {
	failures int
	until    time.Time
	last     time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
	now     func() time.Time
}

const (
	limitPerIPUser   = 5
	limitPerIP       = 50
	loginBackoffBase = 2 * time.Second
	loginBackoffMax  = 15 * time.Minute
	// loginForgetAfter drops an entry nobody has failed against for this
	// long; the map stays bounded by recent activity.
	loginForgetAfter = time.Hour
	loginMaxEntries  = 50000
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: map[string]*loginAttempt{}, now: time.Now}
}

func loginKeys(ip, username string) []struct {
	key   string
	limit int
} {
	u := strings.ToLower(strings.TrimSpace(username))
	return []struct {
		key   string
		limit int
	}{
		{"iu|" + ip + "|" + u, limitPerIPUser},
		{"i|" + ip, limitPerIP},
	}
}

// blocked reports how long the caller must still wait, or zero.
func (l *loginLimiter) blocked(ip, username string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var wait time.Duration
	for _, k := range loginKeys(ip, username) {
		if e := l.entries[k.key]; e != nil && now.Before(e.until) {
			if d := e.until.Sub(now); d > wait {
				wait = d
			}
		}
	}
	return wait
}

// fail records a failed attempt under every key.
func (l *loginLimiter) fail(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) >= loginMaxEntries {
		for k, e := range l.entries {
			if now.Sub(e.last) > loginForgetAfter || (now.After(e.until) && e.failures < limitPerIPUser) {
				delete(l.entries, k)
			}
		}
	}
	for _, k := range loginKeys(ip, username) {
		e := l.entries[k.key]
		if e == nil || now.Sub(e.last) > loginForgetAfter {
			e = &loginAttempt{}
			l.entries[k.key] = e
		}
		e.failures++
		e.last = now
		if over := e.failures - k.limit; over >= 0 {
			d := loginBackoffBase << min(over, 20)
			if d > loginBackoffMax || d <= 0 {
				d = loginBackoffMax
			}
			e.until = now.Add(d)
		}
	}
}

// succeed clears the ip+username counter after a correct password. The
// per-address one is left alone: one good password does not excuse a
// spray against everybody else.
func (l *loginLimiter) succeed(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, loginKeys(ip, username)[0].key)
}

// trustedProxies are the addresses whose forwarding headers are believed.
// Empty by default: a header any client can send is not an address, and
// trusting it would let a guesser pick a fresh "IP" per attempt.
// MUSTRA_TRUSTED_PROXIES is a comma-separated list of CIDRs or addresses
// (for example the cloudflared container's network).
var trustedProxies = parseTrustedProxies(os.Getenv("MUSTRA_TRUSTED_PROXIES"))

func parseTrustedProxies(v string) []*net.IPNet {
	var out []*net.IPNet
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
			continue
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ClientIP is the address a request came from: the TCP peer, or — only
// when that peer is a configured trusted proxy — the client it names in
// CF-Connecting-IP or the last X-Forwarded-For hop.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || !ipTrusted(peer) {
		return host
	}
	if cf := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); cf != nil {
		return cf.String()
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops := strings.Split(xff, ",")
		if ip := net.ParseIP(strings.TrimSpace(hops[len(hops)-1])); ip != nil {
			return ip.String()
		}
	}
	return host
}

func ipTrusted(ip net.IP) bool {
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
