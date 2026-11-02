//go:build windows

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

func certADCSSubmit(ctx context.Context, job proto.CertJob) (string, error) {
	if err := checkADCSJob(job.CSRPEM, job.CAConfig, job.Template); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "mustra-adcs-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	reqFile, certFile, caFile := filepath.Join(dir, "req.csr"), filepath.Join(dir, "cert.cer"), filepath.Join(dir, "ca.cer")
	if err := os.WriteFile(reqFile, []byte(job.CSRPEM), 0o600); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	// -q: never show UI (there is no desktop for a service); the template
	// rides as a request attribute, as the CA's policy module expects.
	out, err := exec.CommandContext(cctx, "certreq.exe", "-submit", "-q", "-config", job.CAConfig,
		"-attrib", "CertificateTemplate:"+job.Template, reqFile, certFile).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if id, pending := certreqPending(text); pending {
		return text, fmt.Errorf("the CA is holding request %s for a CA manager's approval; approve it in certsrv.msc (Pending Requests), then Renew now again", id)
	}
	if err != nil {
		return text, fmt.Errorf("certreq: %v", err)
	}
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return text, fmt.Errorf("the CA issued nothing: %s", text)
	}
	leaf, err := pemCertificates(certData)
	if err != nil {
		return text, err
	}
	// The CA's own certificate, so the endpoint can serve the full chain.
	chain := ""
	if out, err := exec.CommandContext(cctx, "certutil.exe", "-config", job.CAConfig, "-ca.cert", caFile).CombinedOutput(); err == nil {
		if data, err := os.ReadFile(caFile); err == nil {
			chain, _ = pemCertificates(data)
		}
	} else {
		text += "\nCA certificate not fetched: " + strings.TrimSpace(string(out))
	}
	return leaf + chain, nil
}

// certADCSCA returns the enterprise CA's own certificate, for Cert
// Manager's trusted roots.
func certADCSCA(ctx context.Context, job proto.CertJob) (string, error) {
	if !adcsConfigRe.MatchString(job.CAConfig) {
		return "", fmt.Errorf(`the CA config must be host\CA name`)
	}
	dir, err := os.MkdirTemp("", "mustra-adcs-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	caFile := filepath.Join(dir, "ca.cer")
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := exec.CommandContext(cctx, "certutil.exe", "-config", job.CAConfig, "-ca.cert", caFile).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("certutil -ca.cert: %v", err)
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return string(out), err
	}
	return pemCertificates(data)
}

// adcsSerialRe is a certificate serial as Cert Manager records it: hex.
var adcsSerialRe = regexp.MustCompile(`^[0-9a-fA-F]{1,80}$`)

// certADCSRevoke revokes a serial at the enterprise CA and publishes a new
// CRL, so the revocation is visible without waiting for the CA's schedule.
// The endpoint's computer account needs Issue and Manage Certificates on
// the CA, which it has when it is the CA server.
func certADCSRevoke(ctx context.Context, job proto.CertJob) (string, error) {
	if !adcsConfigRe.MatchString(job.CAConfig) {
		return "", fmt.Errorf(`the CA config must be host\CA name`)
	}
	if !adcsSerialRe.MatchString(job.Serial) {
		return "", fmt.Errorf("not a certificate serial number: %q", job.Serial)
	}
	if job.Reason < 0 || job.Reason > 10 {
		return "", fmt.Errorf("revocation reason %d is out of range", job.Reason)
	}
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := exec.CommandContext(cctx, "certutil.exe", "-config", job.CAConfig, "-revoke", job.Serial, strconv.Itoa(job.Reason)).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("certutil -revoke: %v", err)
	}
	crl, err := exec.CommandContext(cctx, "certutil.exe", "-config", job.CAConfig, "-CRL").CombinedOutput()
	if err != nil {
		return string(out) + string(crl), fmt.Errorf("revoked, but publishing the CRL failed: %v", err)
	}
	return string(out) + string(crl), nil
}
