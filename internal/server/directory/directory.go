// Package directory reads a domain -- its users, groups, computers and
// memberships -- over LDAP, so that Impact can join "who can administer
// this endpoint" to "and what else can they reach".
//
// It is a reader. Nothing here writes to the directory, and the bind
// account it needs is an ordinary domain user: every attribute it asks for
// is readable by authenticated users in a default Active Directory. The
// one exception worth knowing about is lastLogonTimestamp, which some
// hardened domains restrict; it is optional and a missing value is simply
// unknown.
package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/mustra-dev/mustra/internal/store"
)

// Config is everything a sync needs. URL is ldap:// or ldaps://; StartTLS
// upgrades an ldap:// connection before binding, which is what a default
// domain controller accepts on 389 -- a password sent over plain LDAP is
// a password on the wire, and the sync refuses to do that unless
// AllowInsecure says so in as many words.
type Config struct {
	URL                string
	BindDN             string
	BindPassword       string
	BaseDN             string
	StartTLS           bool
	InsecureSkipVerify bool
	AllowInsecure      bool
	// CAPEM, when set, is the only certificate authority trusted for the
	// connection -- the way to verify a domain controller's self-signed
	// LDAPS certificate without turning verification off altogether.
	CAPEM   string
	Timeout time.Duration
	// Dial, when set, opens the TCP connection to the server (host:port).
	// The server passes one that refuses internal addresses nobody
	// allowlisted.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Result is a whole domain, ready for store.ReplaceDirectory. Unresolved
// is how many membership references pointed at something the sync did not
// see -- objects outside the base DN, foreign security principals -- so a
// count of zero can be believed and a large one investigated.
type Result struct {
	Domain     string
	NetBIOS    string
	Objects    []store.DirectoryObject
	Members    []store.DirectoryMember
	Unresolved int
	Elapsed    time.Duration
}

// Windows userAccountControl bits.
const (
	uacAccountDisabled    = 0x0002
	uacServerTrustAccount = 0x2000 // a domain controller's computer account
)

// Sync reads the domain. It pages, because AD refuses unpaged searches
// past 1,000 entries and a fleet's worth of users is easily more.
func Sync(ctx context.Context, cfg Config) (*Result, error) {
	start := time.Now()
	conn, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res := &Result{}
	res.Domain, res.NetBIOS = domainNames(conn, cfg.BaseDN)

	bySID := map[string]*store.DirectoryObject{}
	byDN := map[string]string{} // DN -> SID, for resolving group members
	var domainSID string
	add := func(o store.DirectoryObject) {
		o.Domain = res.NetBIOS
		res.Objects = append(res.Objects, o)
		bySID[o.SID] = &res.Objects[len(res.Objects)-1]
		byDN[strings.ToLower(o.DN)] = o.SID
		if domainSID == "" {
			if i := strings.LastIndex(o.SID, "-"); i > 0 {
				domainSID = o.SID[:i]
			}
		}
	}

	// Users. primaryGroupID is the one membership AD does not put in
	// memberOf, and it is how every user belongs to Domain Users.
	primaryGroup := map[string]string{} // user SID -> primary group SID
	users, err := search(ctx, conn, cfg.BaseDN, "(&(objectCategory=person)(objectClass=user))",
		[]string{"objectSid", "sAMAccountName", "displayName", "distinguishedName", "userAccountControl", "adminCount", "primaryGroupID", "lastLogonTimestamp", "description"})
	if err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}
	for _, e := range users {
		sid := sidString(e.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue
		}
		uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
		o := store.DirectoryObject{
			SID: sid, Kind: "user", Name: e.GetAttributeValue("sAMAccountName"),
			DisplayName: e.GetAttributeValue("displayName"), DN: e.DN,
			Enabled:     uac&uacAccountDisabled == 0,
			AdminCount:  e.GetAttributeValue("adminCount") == "1",
			Description: e.GetAttributeValue("description"),
			LastLogon:   fileTime(e.GetAttributeValue("lastLogonTimestamp")),
		}
		add(o)
		if pg := e.GetAttributeValue("primaryGroupID"); pg != "" {
			primaryGroup[sid] = pg
		}
	}

	groups, err := search(ctx, conn, cfg.BaseDN, "(objectClass=group)",
		[]string{"objectSid", "sAMAccountName", "displayName", "distinguishedName", "member", "adminCount", "description"})
	if err != nil {
		return nil, fmt.Errorf("groups: %w", err)
	}
	groupMembers := map[string][]string{} // group SID -> member DNs
	for _, e := range groups {
		sid := sidString(e.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue
		}
		add(store.DirectoryObject{
			SID: sid, Kind: "group", Name: e.GetAttributeValue("sAMAccountName"),
			DisplayName: e.GetAttributeValue("displayName"), DN: e.DN, Enabled: true,
			AdminCount:  e.GetAttributeValue("adminCount") == "1",
			Description: e.GetAttributeValue("description"),
		})
		groupMembers[sid] = e.GetAttributeValues("member")
	}

	computers, err := search(ctx, conn, cfg.BaseDN, "(objectClass=computer)",
		[]string{"objectSid", "sAMAccountName", "distinguishedName", "userAccountControl", "dNSHostName", "operatingSystem", "description", "lastLogonTimestamp"})
	if err != nil {
		return nil, fmt.Errorf("computers: %w", err)
	}
	for _, e := range computers {
		sid := sidString(e.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue
		}
		uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
		add(store.DirectoryObject{
			SID: sid, Kind: "computer", Name: strings.TrimSuffix(e.GetAttributeValue("sAMAccountName"), "$"),
			DN: e.DN, Enabled: uac&uacAccountDisabled == 0,
			DomainController: uac&uacServerTrustAccount != 0,
			DNSHostName:      e.GetAttributeValue("dNSHostName"),
			OperatingSystem:  e.GetAttributeValue("operatingSystem"),
			Description:      e.GetAttributeValue("description"),
			LastLogon:        fileTime(e.GetAttributeValue("lastLogonTimestamp")),
		})
	}

	// Memberships: group member DNs resolved to SIDs, plus every user's
	// primary group. Domain SID + RID is how AD itself spells the latter.
	seen := map[string]bool{}
	edge := func(group, member string) {
		key := group + "|" + member
		if group == "" || member == "" || seen[key] || bySID[group] == nil {
			return
		}
		seen[key] = true
		res.Members = append(res.Members, store.DirectoryMember{GroupSID: group, MemberSID: member})
	}
	for group, dns := range groupMembers {
		for _, dn := range dns {
			sid, ok := byDN[strings.ToLower(dn)]
			if !ok {
				res.Unresolved++
				continue
			}
			edge(group, sid)
		}
	}
	for user, rid := range primaryGroup {
		if domainSID != "" {
			edge(domainSID+"-"+rid, user)
		}
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// Test binds and counts, for the settings page's "test connection".
func Test(ctx context.Context, cfg Config) (string, error) {
	conn, err := connect(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	dns, netbios := domainNames(conn, cfg.BaseDN)
	n := 0
	for _, f := range []string{"(&(objectCategory=person)(objectClass=user))", "(objectClass=group)", "(objectClass=computer)"} {
		entries, err := search(ctx, conn, cfg.BaseDN, f, []string{"objectSid"})
		if err != nil {
			return "", err
		}
		n += len(entries)
	}
	return fmt.Sprintf("bound as %s; %s (%s): %d objects readable under %s", cfg.BindDN, dns, netbios, n, cfg.BaseDN), nil
}

func connect(ctx context.Context, cfg Config) (*ldap.Conn, error) {
	if cfg.URL == "" || cfg.BindDN == "" || cfg.BaseDN == "" {
		return nil, fmt.Errorf("directory needs a server URL, a bind DN and a base DN")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("directory URL: %w", err)
	}
	host := u.Hostname()
	tlsCfg, err := tlsConfigFor(cfg, host)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ldap.DefaultTimeout = timeout
	var conn *ldap.Conn
	if cfg.Dial == nil {
		if conn, err = ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsCfg)); err != nil {
			return nil, fmt.Errorf("connect to %s: %w", cfg.URL, err)
		}
	} else {
		port := u.Port()
		if port == "" {
			port = map[string]string{"ldap": "389", "ldaps": "636"}[u.Scheme]
		}
		dctx, cancel := context.WithTimeout(ctx, timeout)
		raw, err := cfg.Dial(dctx, "tcp", net.JoinHostPort(host, port))
		cancel()
		if err != nil {
			return nil, fmt.Errorf("connect to %s: %w", cfg.URL, err)
		}
		if u.Scheme == "ldaps" {
			tc := tls.Client(raw, tlsCfg)
			hctx, cancel := context.WithTimeout(ctx, timeout)
			err := tc.HandshakeContext(hctx)
			cancel()
			if err != nil {
				raw.Close()
				return nil, fmt.Errorf("connect to %s: %w", cfg.URL, err)
			}
			raw = tc
		}
		conn = ldap.NewConn(raw, u.Scheme == "ldaps")
		conn.Start()
	}
	conn.SetTimeout(timeout)
	if u.Scheme == "ldap" {
		switch {
		case cfg.StartTLS:
			if err := conn.StartTLS(tlsCfg); err != nil {
				conn.Close()
				return nil, fmt.Errorf("StartTLS with %s: %w", host, err)
			}
		case !cfg.AllowInsecure:
			conn.Close()
			return nil, fmt.Errorf("refusing to send the bind password over plain LDAP to %s: use ldaps://, enable StartTLS, or allow insecure explicitly", host)
		}
	}
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind as %s: %w", cfg.BindDN, err)
	}
	return conn, nil
}

func search(ctx context.Context, conn *ldap.Conn, base, filter string, attrs []string) ([]*ldap.Entry, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	res, err := conn.SearchWithPaging(req, 500)
	if err != nil {
		return nil, fmt.Errorf("search %s: %w", filter, err)
	}
	return res.Entries, nil
}

// domainNames returns the DNS domain from the base DN and the NetBIOS name
// from the configuration partition, which is what a Windows endpoint puts
// in front of a backslash. A domain that will not show its partitions
// falls back to the first DC= label, which is usually the same thing.
func domainNames(conn *ldap.Conn, baseDN string) (dns, netbios string) {
	var labels []string
	for _, part := range strings.Split(baseDN, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(k, "dc") {
			labels = append(labels, v)
		}
	}
	dns = strings.Join(labels, ".")
	if len(labels) > 0 {
		netbios = strings.ToUpper(labels[0])
	}
	req := ldap.NewSearchRequest("CN=Partitions,CN=Configuration,"+baseDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=crossRef)(nETBIOSName=*))", []string{"nETBIOSName", "nCName"}, nil)
	if res, err := conn.Search(req); err == nil {
		for _, e := range res.Entries {
			if strings.EqualFold(e.GetAttributeValue("nCName"), baseDN) {
				netbios = e.GetAttributeValue("nETBIOSName")
			}
		}
	}
	return dns, netbios
}

// sidString renders a binary objectSid the way Windows does:
// S-<revision>-<authority>-<subauthority>... Little-endian sub-authorities
// after a big-endian 48-bit authority, which is the one place the format
// is easy to get subtly wrong.
func sidString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	revision := int(b[0])
	count := int(b[1])
	if len(b) < 8+4*count {
		return ""
	}
	authority := uint64(0)
	for _, x := range b[2:8] {
		authority = authority<<8 | uint64(x)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", revision, authority)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String()
}

// fileTime converts an AD timestamp (100-nanosecond ticks since 1601) to
// a time; zero or unparseable means unknown.
func fileTime(s string) *time.Time {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	// Ticks are counted from 1601; the offset to 1970 is 116444736000000000
	// of them. Split into seconds and nanoseconds before multiplying, since
	// the tick count times 100 overflows int64 for any modern date.
	const epochDiff = 116444736000000000
	n -= epochDiff
	if n <= 0 {
		return nil
	}
	t := time.Unix(n/1e7, (n%1e7)*100).UTC()
	return &t
}

// tlsConfigFor builds the TLS settings for a directory URL. With a pinned
// CA the chain must verify against it and nothing else. When the URL names
// an address rather than a host, a self-signed DC certificate usually does
// not carry that address as a SAN, so the name check is relaxed in exactly
// one case: the presented certificate *is* the pinned one. Pinning the
// exact certificate is a stronger check than a name, not a weaker one.
func tlsConfigFor(cfg Config, host string) (*tls.Config, error) {
	tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: cfg.InsecureSkipVerify, MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(cfg.CAPEM) == "" {
		return tlsCfg, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.CAPEM)) {
		return nil, fmt.Errorf("the CA certificate is not valid PEM")
	}
	tlsCfg.RootCAs = pool
	tlsCfg.InsecureSkipVerify = false
	if net.ParseIP(host) == nil {
		return tlsCfg, nil
	}
	// Verification is done by hand below; the standard verifier would
	// insist on an IP SAN before ever consulting the pool.
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("no certificate presented")
		}
		leaf := cs.PeerCertificates[0]
		opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		chains, err := leaf.Verify(opts)
		if err != nil {
			return fmt.Errorf("certificate not signed by the pinned CA: %w", err)
		}
		if leaf.VerifyHostname(host) == nil {
			return nil
		}
		for _, chain := range chains {
			if len(chain) == 1 {
				return nil // the leaf itself is the pinned certificate
			}
		}
		return fmt.Errorf("certificate does not name %s and is not the pinned certificate itself", host)
	}
	return tlsCfg, nil
}
