package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// tlsDiagnosis explains a certificate verification failure in log fields:
// which CA file the agent trusts, and what the server actually presented.
// "certificate signed by unknown authority" alone says neither, and the one
// endpoint that hit it (a CA file that stopped matching overnight) took a
// reinstall to clear with no record of what had been wrong.
//
// The server's chain comes from a separate handshake that only reads the
// certificates: nothing is sent, nothing is trusted, and it is never used
// for traffic.
func tlsDiagnosis(natsURL, caFile string) []any {
	fields := []any{"ca_file", caFile}
	if caFile == "" {
		fields = append(fields, "ca", "none configured (system roots)")
	} else if raw, err := os.ReadFile(caFile); err != nil {
		fields = append(fields, "ca", "unreadable: "+err.Error())
	} else if ca := firstCertificate(raw); ca == nil {
		fields = append(fields, "ca", "no PEM certificate in the file", "ca_file_bytes", len(raw))
	} else {
		fields = append(fields, "ca_subject", ca.Subject.String(), "ca_sha256", fingerprint(ca),
			"ca_valid", validity(ca))
	}
	u, err := url.Parse(natsURL)
	if err != nil || u.Host == "" {
		return append(fields, "server_cert", "unparseable url")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "4222")
	}
	chain, err := presentedChain(host, u.Hostname())
	if err != nil {
		return append(fields, "server_cert", "could not read: "+err.Error())
	}
	leaf := chain[0]
	fields = append(fields, "server_subject", leaf.Subject.String(), "server_issuer", leaf.Issuer.String(),
		"server_sha256", fingerprint(leaf), "server_valid", validity(leaf),
		"server_names", strings.Join(append(leaf.DNSNames, ipStrings(leaf.IPAddresses)...), ","))
	return fields
}

func firstCertificate(raw []byte) *x509.Certificate {
	for len(raw) > 0 {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			return nil
		}
		if b.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				return c
			}
		}
	}
	return nil
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func validity(c *x509.Certificate) string {
	return c.NotBefore.UTC().Format(time.RFC3339) + " to " + c.NotAfter.UTC().Format(time.RFC3339)
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// presentedChain is the certificate chain a server offers, read without
// verifying it. NATS speaks first in plain text (an INFO line) and upgrades
// to TLS after, so the INFO line is read and discarded before the handshake.
func presentedChain(hostport, serverName string) ([]*x509.Certificate, error) {
	conn, err := net.DialTimeout("tcp", hostport, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf); err != nil {
			return nil, err
		}
		if buf[0] == '\n' {
			break
		}
	}
	tc := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) // #nosec G402 -- read-only diagnosis, never used for traffic
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	chain := tc.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errNoChain
	}
	return chain, nil
}

type diagErr string

func (e diagErr) Error() string { return string(e) }

const errNoChain = diagErr("server presented no certificate")

// isCertificateError reports a TLS verification failure, as opposed to the
// broker being unreachable or refusing the credential.
func isCertificateError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "x509:")
}
