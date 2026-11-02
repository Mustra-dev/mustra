package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Certificate renewal, endpoint half. The private key is generated here and
// never leaves the machine: the server only ever sees the CSR and returns
// the signed certificate. Installing backs up what was there, writes the new
// files with the old owner and mode, reloads the service, checks the service
// now presents the new certificate, and puts everything back if any of that
// fails.

var pendingCertKeys = struct {
	sync.Mutex
	m map[string]pendingKey
}{m: map[string]pendingKey{}}

type pendingKey struct {
	key *ecdsa.PrivateKey
	at  time.Time
}

const pendingKeyTTL = 30 * time.Minute

func certCSR(job proto.CertJob) (string, error) {
	if job.RequestID == "" || len(job.Names) == 0 {
		return "", errors.New("a request id and at least one name are required")
	}
	if isWinStore(job.CertPath) {
		return winStoreCSR(job)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: job.Names[0]}}
	for _, n := range job.Names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", err
	}
	pendingCertKeys.Lock()
	for id, p := range pendingCertKeys.m {
		if time.Since(p.at) > pendingKeyTTL {
			delete(pendingCertKeys.m, id)
		}
	}
	pendingCertKeys.m[job.RequestID] = pendingKey{key: key, at: time.Now()}
	pendingCertKeys.Unlock()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// certInstall returns the new certificate's fingerprint and what it did.
func certInstall(ctx context.Context, job proto.CertJob) (string, error) {
	// The Windows store keeps its own pending key (certs_winstore.go).
	if isWinStore(job.CertPath) {
		return winStoreInstall(ctx, job)
	}
	// An uploaded certificate brings its own key (certs_upload.go).
	if job.KeyPEM != "" {
		return installUploaded(ctx, job)
	}
	pendingCertKeys.Lock()
	pk, ok := pendingCertKeys.m[job.RequestID]
	delete(pendingCertKeys.m, job.RequestID)
	pendingCertKeys.Unlock()
	if !ok {
		return "", errors.New("no key for this request on the endpoint (the agent restarted or the request is over 30 minutes old); renew again")
	}
	if strings.HasPrefix(job.CertPath, `Cert:\`) {
		return "", errors.New("Cert Manager installs into Cert:\\LocalMachine\\My; choose that store")
	}
	block, _ := pem.Decode([]byte(job.CertPEM))
	if block == nil {
		return "", errors.New("the server sent no certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&pk.key.PublicKey) {
		return "", errors.New("the signed certificate does not match the key generated for it")
	}
	keyDER, err := x509.MarshalECPrivateKey(pk.key)
	if err != nil {
		return "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certChain := strings.TrimSpace(job.CertPEM) + "\n"
	if c := strings.TrimSpace(job.ChainPEM); c != "" {
		certChain += c + "\n"
	}
	return installMaterial(ctx, job, keyPEM, certChain, leaf)
}

// installUploaded installs a certificate that came with its key, after
// checking the key is the certificate's.
func installUploaded(ctx context.Context, job proto.CertJob) (string, error) {
	block, _ := pem.Decode([]byte(job.CertPEM))
	if block == nil {
		return "", errors.New("the server sent no certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	kb, _ := pem.Decode([]byte(job.KeyPEM))
	if kb == nil {
		return "", errors.New("the server sent no key")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	type publicKeyer interface{ Public() crypto.PublicKey }
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pk, ok := key.(publicKeyer)
	if !ok {
		return "", errors.New("unsupported key")
	}
	if eq, ok := pk.Public().(equaler); !ok || !eq.Equal(leaf.PublicKey) {
		return "", errors.New("the key does not belong to the certificate")
	}
	certChain := strings.TrimSpace(job.CertPEM) + "\n"
	if c := strings.TrimSpace(job.ChainPEM); c != "" {
		certChain += c + "\n"
	}
	return installMaterial(ctx, job, []byte(job.KeyPEM), certChain, leaf)
}

// installMaterial writes a key and certificate chain where the job says,
// reloads, verifies, and puts the old files back on any failure.
func installMaterial(ctx context.Context, job proto.CertJob, keyPEM []byte, certChain string, leaf *x509.Certificate) (string, error) {
	sum := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(sum[:])

	combined := job.KeyPath == "" || job.KeyPath == job.CertPath
	type write struct {
		path string
		data []byte
		mode fs.FileMode
	}
	var writes []write
	if combined {
		writes = []write{{job.CertPath, append(append([]byte{}, keyPEM...), certChain...), 0o600}}
	} else {
		writes = []write{{job.CertPath, []byte(certChain), 0o644}, {job.KeyPath, keyPEM, 0o600}}
	}

	// Back up, then write each file atomically with the old owner and mode.
	var backups []string
	restore := func() {
		for i, w := range writes {
			if i < len(backups) && backups[i] != "" {
				_ = os.Rename(backups[i], w.path)
			}
		}
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for _, w := range writes {
		// A first install may name a directory that does not exist yet.
		if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
			restore()
			return "", fmt.Errorf("create %s: %w", filepath.Dir(w.path), err)
		}
		bak := ""
		if st, err := os.Stat(w.path); err == nil {
			w.mode = st.Mode().Perm()
			bak = w.path + ".mustra-bak-" + stamp
			if err := copyFile(w.path, bak, st); err != nil {
				restore()
				return "", fmt.Errorf("back up %s: %w", w.path, err)
			}
		}
		backups = append(backups, bak)
		if err := writeLike(w.path, w.data, w.mode); err != nil {
			restore()
			return "", fmt.Errorf("write %s: %w", w.path, err)
		}
	}
	var report bytes.Buffer
	fmt.Fprintf(&report, "Wrote %s", job.CertPath)
	if !combined {
		fmt.Fprintf(&report, " and %s", job.KeyPath)
	}
	fmt.Fprintf(&report, " (backups kept as *.mustra-bak-%s).\n", stamp)

	fail := func(why string) (string, error) {
		restore()
		if job.ReloadCmd != "" {
			_, _ = runReload(ctx, job.ReloadCmd)
		}
		return report.String(), fmt.Errorf("%s; the previous certificate was restored", why)
	}
	if job.ReloadCmd != "" {
		out, err := runReload(ctx, job.ReloadCmd)
		if err != nil {
			return fail(fmt.Sprintf("reload failed: %v %s", err, strings.TrimSpace(out)))
		}
		fmt.Fprintf(&report, "Reloaded with: %s\n", job.ReloadCmd)
	}
	if job.VerifyPort > 0 {
		target := net.JoinHostPort("127.0.0.1", strconv.Itoa(job.VerifyPort))
		served := ""
		for i := 0; i < 10; i++ {
			if c := presentedCertificate(ctx, target, leaf.Subject.CommonName); c != nil {
				s := sha256.Sum256(c.Raw)
				if served = hex.EncodeToString(s[:]); served == fingerprint {
					break
				}
			}
			time.Sleep(1500 * time.Millisecond)
		}
		if served != fingerprint {
			return fail(fmt.Sprintf("port %d still presents a different certificate after the reload", job.VerifyPort))
		}
		fmt.Fprintf(&report, "Verified: port %d presents the new certificate.\n", job.VerifyPort)
	}
	return report.String() + "fingerprint " + fingerprint, nil
}

func runReload(ctx context.Context, cmdline string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(cctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", cmdline)
	} else {
		cmd = exec.CommandContext(cctx, "/bin/sh", "-c", cmdline)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func copyFile(src, dst string, st fs.FileInfo) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, st.Mode().Perm()); err != nil {
		return err
	}
	// The backup holds a private key: give it exactly the original's mode,
	// whatever the umask or an existing file left behind.
	if err := os.Chmod(dst, st.Mode().Perm()); err != nil && !modeManagedByFS(err) {
		return err
	}
	chownLike(dst, st)
	return nil
}

// writeLike replaces path atomically, keeping the old file's owner and mode
// when there was one (Pi-hole's tls.pem belongs to the pihole user).
func writeLike(path string, data []byte, mode fs.FileMode) error {
	old, statErr := os.Stat(path)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mustra-cert-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil && !modeManagedByFS(err) {
		os.Remove(name)
		return err
	}
	if statErr == nil {
		chownLike(name, old)
	}
	return os.Rename(name, path)
}

// modeManagedByFS reports a chmod refused by a filesystem that sets
// permissions itself: Proxmox's /etc/pve (pmxcfs) gives every file there
// root:www-data 0640 and answers chmod with EPERM. The file is written and
// as protected as that filesystem makes it, so the install carries on.
func modeManagedByFS(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}

// certTailscale gets the endpoint's own certificate for its tailnet name
// from Tailscale (Let's Encrypt, trusted everywhere): tailscaled makes the
// key on this machine, so it never leaves it either. HTTPS certificates must
// be enabled for the tailnet, and the name must be this node's.
func certTailscale(ctx context.Context, job proto.CertJob) (string, error) {
	if len(job.Names) == 0 || !strings.HasSuffix(job.Names[0], ".ts.net") {
		return "", errors.New("the first name must be this endpoint's tailnet name (…ts.net)")
	}
	if strings.HasPrefix(job.CertPath, `Cert:\`) {
		return "", errors.New("installing into the Windows certificate store is not supported yet; manage a file-based certificate")
	}
	dir, err := os.MkdirTemp("", "mustra-tscert-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(cctx, "tailscale", "cert", "--cert-file", certFile, "--key-file", keyFile, job.Names[0]).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tailscale cert: %v %s", err, strings.TrimSpace(string(out)))
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	chain, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(chain)
	if block == nil {
		return "", errors.New("tailscale returned no certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	report, err := installMaterial(ctx, job, keyPEM, string(chain), leaf)
	return "expires " + leaf.NotAfter.UTC().Format(time.RFC3339) + "\n" + report, err
}
