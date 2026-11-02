package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Outbound fetches the server makes on an operator's behalf.
//
// "Import from URL" downloads a package file, optionally sending a vault
// credential. Left open, it was both a request forgery primitive (any URL
// the server can reach: the metadata service, Postgres' HTTP neighbours,
// the NATS monitor) and a way to mail a stored secret to any host the
// caller named. Now:
//
//   - only https;
//   - the host is resolved once, every address is checked, and the
//     connection goes to the checked address — a DNS answer that changes
//     between check and dial (rebinding) cannot redirect it;
//   - loopback, private, link-local (including cloud metadata), CGNAT,
//     multicast and unspecified addresses are refused unless an
//     administrator allowlisted the host;
//   - a vault credential is only ever sent to an allowlisted host;
//   - every redirect hop goes through the same checks.

const settingImportAllowedHosts = "deploy.import_allowed_hosts"

// importAllowedHosts is the admin-maintained list of hosts an import may
// reach even when they are internal, and the only hosts a credential is
// sent to. MUSTRA_IMPORT_ALLOWED_HOSTS adds to it.
func (s *Server) importAllowedHosts(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	add := func(v string) {
		for _, h := range auth.SplitList(v) {
			out[strings.ToLower(strings.TrimSuffix(h, "."))] = true
		}
	}
	add(os.Getenv("MUSTRA_IMPORT_ALLOWED_HOSTS"))
	if s.store != nil {
		if settings, err := s.store.GetAllSettings(ctx); err == nil {
			add(settings[settingImportAllowedHosts])
		}
	}
	return out
}

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
		// NAT64: the well-known prefix (RFC 6052) and the local-use prefix
		// (RFC 8215); both map an embedded IPv4 that may be internal.
		"64:ff9b::/96", "64:ff9b:1::/48",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// blockedAddr reports whether an address is one an un-allowlisted import
// must never reach.
func blockedAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// guardedHTTPClient fetches only from https URLs whose resolved addresses
// pass the checks above (or whose host is allowlisted).
func guardedHTTPClient(allowed map[string]bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		// No proxy: a proxy would resolve the name itself, after the check.
		Proxy:               nil,
		TLSHandshakeTimeout: 15 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("%s did not resolve", host)
			}
			if !allowed[strings.ToLower(strings.TrimSuffix(host, "."))] {
				for _, ip := range ips {
					if blockedAddr(ip) {
						return nil, fmt.Errorf("%s resolves to %s, an internal address; add the host under Administration → Network Allowlists to reach it", host, ip.Unmap())
					}
				}
			}
			// Dial the address that was checked, never the name again.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
		},
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		if next.URL.Scheme != "https" {
			return fmt.Errorf("redirect must remain HTTPS")
		}
		// Credentials stay with the host they were meant for.
		if !strings.EqualFold(next.URL.Host, via[0].URL.Host) {
			next.Header.Del("Authorization")
		}
		return nil
	}}
}

// Operator-configured webhooks (Connect exports, report delivery, Jump
// Gate notifications) are the same request-forgery primitive as import: a
// settings.manage holder could point one at the metadata service, the NATS
// monitor or Postgres' neighbours and read the response status back. They
// go through the guarded client too. Because pointing an export at an
// in-house collector (Loki, a SIEM) is legitimate, an administrator can
// allowlist such hosts; only an allowlisted host may use plain http.

const settingWebhookAllowedHosts = "connect.webhook_allowed_hosts"

// webhookAllowedHosts is the admin-maintained list of hosts a webhook may
// reach although they are internal. MUSTRA_WEBHOOK_ALLOWED_HOSTS adds to it.
func (s *Server) webhookAllowedHosts(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	add := func(v string) {
		for _, h := range auth.SplitList(v) {
			out[strings.ToLower(strings.TrimSuffix(h, "."))] = true
		}
	}
	add(os.Getenv("MUSTRA_WEBHOOK_ALLOWED_HOSTS"))
	if s.store != nil {
		if v, err := s.store.GetSetting(ctx, settingWebhookAllowedHosts); err == nil {
			add(v)
		}
	}
	return out
}

// checkWebhookURL refuses a webhook URL that is not http(s), or plain http
// to a host nobody allowlisted. Address checks happen at dial time.
func checkWebhookURL(raw string, allowed map[string]bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("the webhook URL is not a valid absolute URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowed[host] {
			return nil
		}
		return fmt.Errorf("a webhook must use https unless %s is on the internal destinations allowlist (Administration → Network Allowlists)", host)
	}
	return fmt.Errorf("a webhook must be an https URL")
}

// webhookClient is the HTTP client for operator-configured webhooks.
func (s *Server) webhookClient(ctx context.Context) (*http.Client, map[string]bool) {
	allowed := s.webhookAllowedHosts(ctx)
	c := guardedHTTPClient(allowed, 30*time.Second)
	// Redirects are not followed: a webhook answering with one is almost
	// always misconfigured, and following it would carry the payload and
	// any configured headers to a host nobody configured.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c, allowed
}

// guardedDial is the raw-socket form of guardedHTTPClient, for the
// destinations an operator configures that are not HTTP: the directory's
// LDAP server, audit syslog forwarding and Connect's syslog exports. The
// host is resolved once and every address checked; an internal one is
// refused unless an administrator allowlisted the host (the same list as
// webhooks, which is where an in-house SIEM already is), and the
// connection goes to the checked address.
func guardedDial(ctx context.Context, network, addr string, allowed map[string]bool, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s did not resolve", host)
	}
	if !allowed[strings.ToLower(strings.TrimSuffix(host, "."))] {
		for _, ip := range ips {
			if blockedAddr(ip) {
				return nil, fmt.Errorf("%s resolves to %s, an internal address; an administrator must add %s to the internal destinations allowlist (Settings) to reach it", host, ip.Unmap(), host)
			}
		}
	}
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
}

// settingInternalDestinationsMigrated marks that the destinations set up
// before guardedDial existed have been carried into the allowlist.
const settingInternalDestinationsMigrated = "netguard.internal_destinations_migrated"

// allowlistExistingInternalDestinations runs once, on the first start
// after guardedDial began guarding LDAP and syslog. A directory or syslog
// collector already configured on an internal address (a domain
// controller, an in-house SIEM) was set up while nothing checked it;
// refusing it now would silently stop directory sync and audit
// forwarding. Those hosts are added to the allowlist, and the addition is
// audited. New ones need an administrator.
func (s *Server) allowlistExistingInternalDestinations(ctx context.Context) {
	if done, _ := s.store.GetSetting(ctx, settingInternalDestinationsMigrated); done == "true" {
		return
	}
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		s.logger.Warn("allowlisting existing internal destinations failed", "error", err)
		return
	}
	var hosts []string
	if u, err := url.Parse(settings[settingDirectoryURL]); err == nil && u.Hostname() != "" {
		hosts = append(hosts, u.Hostname())
	}
	syslogHost := func(target string) {
		_, addr := parseSyslogTarget(strings.TrimSpace(target))
		if h, _, err := net.SplitHostPort(addr); err == nil && h != "" {
			hosts = append(hosts, h)
		}
	}
	if t := settings["log_forward_target"]; t != "" {
		syslogHost(t)
	}
	if exports, err := s.store.ListExportConfigs(ctx); err == nil {
		for _, e := range exports {
			if e.Destination == "syslog" {
				syslogHost(e.Target)
			}
		}
	}
	allowed := s.webhookAllowedHosts(ctx)
	var added []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if allowed[h] || !resolvesInternal(ctx, h) {
			continue
		}
		allowed[h] = true
		added = append(added, h)
	}
	if len(added) > 0 {
		current := strings.TrimSpace(settings[settingWebhookAllowedHosts])
		next := strings.TrimSpace(current + "\n" + strings.Join(added, "\n"))
		if err := s.store.SetSetting(ctx, settingWebhookAllowedHosts, next, "system"); err != nil {
			s.logger.Warn("allowlisting existing internal destinations failed", "error", err)
			return
		}
		s.audit(ctx, auditEvent{Action: "settings.webhook_allowlist", Actor: "system", Target: "internal destinations allowlist", Severity: "notice",
			Detail: map[string]any{"added": added, "reason": "already configured for LDAP or syslog before those were checked"}})
		s.logger.Info("allowlisted internal destinations already in use", "hosts", added)
	}
	_ = s.store.SetSetting(ctx, settingInternalDestinationsMigrated, "true", "system")
}

// resolvesInternal reports whether host is, or resolves to, an address
// guardedDial refuses without an allowlist entry.
func resolvesInternal(ctx context.Context, host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return blockedAddr(a)
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if blockedAddr(ip) {
			return true
		}
	}
	return false
}
