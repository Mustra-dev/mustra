package agent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Certificate Manager, endpoint half: find the X.509 certificates actually
// installed on this machine and report when they expire.
//
// The value here is not cryptographic, it's operational. Certificates fail
// on a date, silently, and almost always on the machine nobody remembers
// owning. An inventory that says "this expires in nine days and it lives
// on that host at that path" is the entire product.
//
// Only paths that conventionally hold certificates are walked, with a
// depth and count bound, because "search the filesystem for certificates"
// on a fileserver is a good way to turn a sensor into an outage. Private
// keys are never read — the agent parses certificates, which are public by
// construction, and skips anything that isn't one.

const (
	maxCertDepth = 6
	maxCertFiles = 4000
	maxCertBytes = 1 << 20 // a 1 MB "certificate" is not a certificate
)

func certSearchPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\ProgramData\certs`,
			`C:\inetpub`,
			`C:\ProgramData\Docker\certs.d`,
		}
	case "darwin":
		return []string{
			"/etc/ssl/certs", "/usr/local/etc/ssl", "/opt/homebrew/etc",
			"/Library/Application Support",
		}
	default:
		return []string{
			"/etc/ssl", "/etc/pki", "/etc/letsencrypt/live", "/etc/nginx",
			"/etc/apache2", "/etc/httpd", "/etc/haproxy", "/etc/traefik",
			"/etc/docker/certs.d", "/etc/postgresql", "/etc/mysql",
			"/var/lib/rancher", "/opt/certs", "/srv/certs",
			// Proxmox VE's web and API certificates, and Backup Server's.
			"/etc/pve", "/etc/proxmox-backup",
			// Pi-hole 6 keeps its web certificate (and key) in tls.pem.
			"/etc/pihole",
		}
	}
}

var certExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".cert": true, ".ca-bundle": true,
}

func collectCertificates(ctx context.Context) ([]proto.CertificateInfo, error) {
	out := []proto.CertificateInfo{}
	seen := map[string]bool{} // fingerprint+path, so a symlink farm reports once
	files := 0

	for _, root := range certSearchPaths() {
		if ctx.Err() != nil {
			break
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable subtree is not a reason to abandon the walk
			}
			if ctx.Err() != nil || files > maxCertFiles {
				return filepath.SkipAll
			}
			if d.IsDir() {
				if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth > maxCertDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if !certExtensions[strings.ToLower(filepath.Ext(path))] {
				return nil
			}
			files++

			st, err := d.Info()
			if err != nil || st.Size() > maxCertBytes {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, cert := range parseCertificates(data) {
				fp := sha256.Sum256(cert.Raw)
				fingerprint := hex.EncodeToString(fp[:])
				key := fingerprint + "|" + path
				if seen[key] {
					continue
				}
				seen[key] = true
				info := describeCertificate(cert, fingerprint, path)
				info.TrustStore = isTrustStorePath(path)
				out = append(out, info)
			}
			return nil
		})
	}
	for _, info := range collectExtraCertificates(ctx) {
		if key := info.Fingerprint + "|" + info.Path; !seen[key] {
			seen[key] = true
			out = append(out, info)
		}
	}
	return out, nil
}

// parseCertificates pulls every CERTIFICATE block out of a PEM file. A
// bundle legitimately holds a chain, and reporting only the leaf would
// hide an intermediate that expires first — which is a real and annoying
// way for TLS to break.
func parseCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue // never touch a PRIVATE KEY block
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		// Might be DER rather than PEM.
		if cert, err := x509.ParseCertificate(data); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

func describeCertificate(cert *x509.Certificate, fingerprint, path string) proto.CertificateInfo {
	names := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	if cert.Subject.CommonName != "" && !contains(names, cert.Subject.CommonName) {
		names = append(names, cert.Subject.CommonName)
	}

	return proto.CertificateInfo{
		Path:         path,
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		SerialNumber: cert.SerialNumber.Text(16),
		Fingerprint:  fingerprint,
		NotBefore:    cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     cert.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:     int(time.Until(cert.NotAfter).Hours() / 24),
		DNSNames:     names,
		IsCA:         cert.IsCA,
		SelfSigned:   cert.Issuer.CommonName == cert.Subject.CommonName,
		KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SigAlgorithm: cert.SignatureAlgorithm.String(),
	}
}

// trustStorePaths hold the OS's bundled CA list. A certificate found here
// is one the vendor shipped, not one this machine serves — nobody renews
// these, and treating them as findings drowns the few that matter.
var trustStorePaths = []string{
	"/etc/ssl/certs/",
	"/etc/pki/ca-trust/",
	"/etc/pki/tls/certs/ca-bundle",
	"/usr/share/ca-certificates/",
	"/usr/local/share/ca-certificates/",
	"/etc/ca-certificates/",
	"/private/etc/ssl/certs/",
}

func isTrustStorePath(path string) bool {
	clean := filepath.ToSlash(path)
	for _, p := range trustStorePaths {
		if strings.HasPrefix(clean, p) {
			return true
		}
	}
	return strings.Contains(filepath.Base(clean), "ca-certificates.crt") ||
		strings.Contains(filepath.Base(clean), "ca-bundle.crt")
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
