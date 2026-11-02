package agent

import (
	"context"
	"crypto/sha1" //nolint:gosec // the Windows thumbprint is SHA-1 by definition
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Certificates that do not live in a file the walk can find. Without these
// the fleet's Windows servers and Macs reported none at all, and nothing
// said which service presents which certificate, which is what renewing
// one needs to know.

// collectExtraCertificates adds the OS certificate store and the
// certificates local services present. Each source is best effort: one that
// fails or is missing leaves the others and the file walk standing.
func collectExtraCertificates(ctx context.Context) []proto.CertificateInfo {
	var out []proto.CertificateInfo
	switch runtime.GOOS {
	case "windows":
		out = append(out, windowsStoreCertificates(ctx)...)
	case "darwin":
		out = append(out, keychainCertificates(ctx)...)
	}
	return append(out, servedCertificates(ctx)...)
}

func certInfo(cert *x509.Certificate, path string) proto.CertificateInfo {
	fp := sha256.Sum256(cert.Raw)
	return describeCertificate(cert, hex.EncodeToString(fp[:]), path)
}

// windowsStoreCertificates reads the LocalMachine stores that hold a
// machine's own certificates: Personal (IIS, LDAPS, WinRM, anything bound
// to a service), Web Hosting and Remote Desktop. The Root and intermediate
// stores are trust stores, like /etc/ssl/certs, and are not read. The
// stores are read in-process (certstore_windows.go); this used to start
// PowerShell every sensor interval.
func windowsStoreCertificates(ctx context.Context) []proto.CertificateInfo {
	var out []proto.CertificateInfo
	for _, store := range []string{"My", "WebHosting", "Remote Desktop"} {
		for _, der := range machineStoreCertificates(store) {
			if ctx.Err() != nil {
				return out
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			fp := sha256.Sum256(cert.Raw)
			thumb := strings.ToUpper(hex.EncodeToString(sha1Sum(cert.Raw)))
			out = append(out, describeCertificate(cert, hex.EncodeToString(fp[:]), `Cert:\LocalMachine\`+store+`\`+thumb))
		}
	}
	return out
}

// keychainCertificates reads the System keychain, where a Mac keeps the
// certificates the machine itself uses (802.1X, VPN, device identities).
// The bundled roots live elsewhere (SystemRootCertificates) and are not read.
func keychainCertificates(ctx context.Context) []proto.CertificateInfo {
	const keychain = "/Library/Keychains/System.keychain"
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(cctx, "security", "find-certificate", "-a", "-p", keychain).Output()
	if err != nil {
		return nil
	}
	var out []proto.CertificateInfo
	for _, cert := range parseCertificates(raw) {
		out = append(out, certInfo(cert, "keychain:"+keychain))
	}
	return out
}

// tlsPorts are the ports a local service conventionally serves TLS on.
// Only these are tried, and only when something listens there: a TLS hello
// sent to an arbitrary port lands in some other protocol's logs as noise.
var tlsPorts = map[uint32]bool{
	443: true, 8443: true, 4443: true, 9443: true, 10443: true,
	8006: true, 8007: true, // Proxmox VE, Proxmox Backup Server
	636: true, 3269: true, // LDAPS, global catalog over TLS
	5986: true, // WinRM over HTTPS
	993:  true, 995: true, 465: true,
	6443: true, 2376: true, 8883: true, 853: true,
}

// servedCertificates connects to each local TLS port and records the
// certificate the service presents, as tls://address:port. The same
// certificate found as a file has the same fingerprint, so the console
// shows one certificate with both locations: where it is stored and where
// it is served, which is what renewing it needs.
func servedCertificates(ctx context.Context) []proto.CertificateInfo {
	conns, err := gnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil
	}
	host, _ := os.Hostname()
	seen := map[string]bool{}
	// A service listening on both 127.0.0.1 and ::1 is one service: the
	// same certificate on the same port is reported once.
	servedOn := map[string]bool{}
	var out []proto.CertificateInfo
	for _, c := range conns {
		if c.Status != "LISTEN" || !tlsPorts[c.Laddr.Port] {
			continue
		}
		addr := c.Laddr.IP
		switch addr {
		case "", "0.0.0.0", "*":
			addr = "127.0.0.1"
		case "::":
			addr = "::1"
		}
		target := net.JoinHostPort(addr, strconv.Itoa(int(c.Laddr.Port)))
		if seen[target] || len(seen) >= 20 {
			continue
		}
		seen[target] = true
		cert := presentedCertificate(ctx, target, host)
		if cert == nil {
			continue
		}
		info := certInfo(cert, "tls://"+target)
		if key := info.Fingerprint + "|" + strconv.Itoa(int(c.Laddr.Port)); !servedOn[key] {
			servedOn[key] = true
			out = append(out, info)
		}
	}
	return out
}

func presentedCertificate(ctx context.Context, target, serverName string) *x509.Certificate {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{
		// Read, never trusted: the point is to see what is served,
		// including expired and self-signed certificates.
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         serverName,
	}}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", target)
	if err != nil {
		return nil
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	return state.PeerCertificates[0]
}

// sha1Sum is the certificate's Windows thumbprint, which names it in the
// store (Cert:\LocalMachine\My\<thumbprint>).
func sha1Sum(b []byte) []byte {
	h := sha1.Sum(b) //nolint:gosec
	return h[:]
}
