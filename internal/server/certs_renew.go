package server

// Certificate renewal (Cert Manager). A managed certificate names a file on
// an endpoint, the names it covers, the CA that signs it, how many days
// before expiry to renew, whether a person approves each renewal, and how
// to reload the service. Renewing: the agent makes a key and CSR (the key
// never leaves the endpoint), a CA signs it, the agent installs it, reloads,
// checks the service presents it, and restores the old one on any failure.
//
// CAs: "private" (Mustra's own CA, made on first use; download its root to
// trust it), "acme" (Let's Encrypt, DNS-01 through the Cloudflare API),
// "cloudflare_origin" (Cloudflare Origin CA, for origins behind Cloudflare's
// proxy), "adcs" (Active Directory Certificate Services: a Windows endpoint
// in the domain submits the CSR to the enterprise CA with certreq) and
// "tailscale" (the endpoint fetches its own tailnet certificate).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingCACert         = "certs.ca_cert"
	settingCAKey          = "certs.ca_key"
	settingCFToken        = "certs.cloudflare_token"
	settingACMEEmail      = "certs.acme_email"
	settingACMEStaging    = "certs.acme_staging"
	settingACMEAccountKey = "certs.acme_account_key"
	settingADCSAgent      = "certs.adcs_agent"
	settingADCSConfig     = "certs.adcs_config"
	settingADCSTemplate   = "certs.adcs_template"

	privateLeafLifetime = 180 * 24 * time.Hour
	certRetryAfter      = 12 * time.Hour
)

var certCAs = map[string]string{
	"private":           "Mustra Private CA",
	"acme":              "Let's Encrypt (Cloudflare DNS)",
	"cloudflare_origin": "Cloudflare Origin CA",
	"adcs":              "Active Directory Certificate Services",
	"tailscale":         "Tailscale HTTPS (Let's Encrypt, tailnet names)",
	"upload":            "Your own certificate (uploaded)",
}

// --- private CA -------------------------------------------------------------

// privateCA returns Mustra's CA, making it the first time it is needed.
func (s *Server) privateCA(ctx context.Context) (*x509.Certificate, crypto.Signer, string, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	if certPEM, keyStored := settings[settingCACert], settings[settingCAKey]; certPEM != "" && keyStored != "" {
		keyPEM, err := s.openSetting(settingCAKey, keyStored)
		if err != nil {
			return nil, nil, "", err
		}
		cb, _ := pem.Decode([]byte(certPEM))
		kb, _ := pem.Decode([]byte(keyPEM))
		if cb == nil || kb == nil {
			return nil, nil, "", errors.New("the stored private CA is unreadable")
		}
		cert, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			return nil, nil, "", err
		}
		key, err := x509.ParseECPrivateKey(kb.Bytes)
		if err != nil {
			return nil, nil, "", err
		}
		return cert, key, certPEM, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Mustra Private CA", Organization: []string{"mustra"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	sealed, err := s.sealSetting(settingCAKey, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	if err != nil {
		return nil, nil, "", err
	}
	if err := s.store.SetSettingIfAbsent(ctx, settingCAKey, sealed, "system"); err != nil {
		return nil, nil, "", err
	}
	if err := s.store.SetSettingIfAbsent(ctx, settingCACert, certPEM, "system"); err != nil {
		return nil, nil, "", err
	}
	s.logger.Info("created the Mustra private CA")
	return s.privateCA(ctx) // read back: another server may have won the race
}

func (s *Server) signPrivate(ctx context.Context, csr *x509.CertificateRequest, names []string) (string, string, error) {
	caCert, caKey, caPEM, err := s.privateCA(ctx)
	if err != nil {
		return "", "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(privateLeafLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// Where to check whether it has been revoked (certs_lifecycle.go).
	if crl := s.privateCRLURL(ctx); crl != "" {
		tmpl.CRLDistributionPoints = []string{crl}
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), caPEM, nil
}

// --- Cloudflare (DNS-01 and Origin CA) --------------------------------------

func (s *Server) cloudflareToken(ctx context.Context) (string, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return "", err
	}
	stored := settings[settingCFToken]
	if stored == "" {
		return "", errors.New("no Cloudflare API token is set (Certificates → Certificate authorities)")
	}
	return s.openSetting(settingCFToken, stored)
}

func cfCall(ctx context.Context, token, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare: %w", err)
	}
	defer resp.Body.Close()
	var env struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  json.RawMessage            `json:"result"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if json.Unmarshal(data, &env) != nil || !env.Success {
		msg := strings.TrimSpace(string(data))
		if len(env.Errors) > 0 {
			msg = env.Errors[0].Message
		}
		return fmt.Errorf("Cloudflare %s %s: %s", method, path, safeTruncate(msg, 200))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// cfZone finds the Cloudflare zone a name lives in by trying its suffixes.
func cfZone(ctx context.Context, token, name string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		var zones []struct{ ID string }
		if err := cfCall(ctx, token, "GET", "/zones?name="+strings.Join(labels[i:], "."), nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("no Cloudflare zone holds %s (or the token cannot see it)", name)
}

func (s *Server) signCloudflareOrigin(ctx context.Context, csrPEM string, names []string) (string, error) {
	token, err := s.cloudflareToken(ctx)
	if err != nil {
		return "", err
	}
	var res struct {
		Certificate string `json:"certificate"`
	}
	err = cfCall(ctx, token, "POST", "/certificates", map[string]any{
		"hostnames": names, "requested_validity": 365, "request_type": "origin-ecc", "csr": csrPEM,
	}, &res)
	return res.Certificate, err
}

// --- ACME (Let's Encrypt over Cloudflare DNS) -------------------------------

func (s *Server) signACME(ctx context.Context, csrDER []byte, names []string) (string, string, error) {
	token, err := s.cloudflareToken(ctx)
	if err != nil {
		return "", "", err
	}
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return "", "", err
	}
	email := settings[settingACMEEmail]
	if email == "" {
		return "", "", errors.New("set an ACME account email (Certificates → Certificate authorities)")
	}
	for _, n := range names {
		if net.ParseIP(n) != nil || !strings.Contains(n, ".") {
			return "", "", fmt.Errorf("Let's Encrypt cannot issue for %q; it needs a public domain name — use the private CA", n)
		}
	}
	accountKey, err := s.acmeAccountKey(ctx)
	if err != nil {
		return "", "", err
	}
	dir := acme.LetsEncryptURL
	if settings[settingACMEStaging] == "true" {
		dir = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: dir}
	if _, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + email}}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return "", "", fmt.Errorf("ACME account: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return "", "", fmt.Errorf("ACME order: %w", err)
	}
	type record struct{ zone, id string }
	var created []record
	defer func() {
		for _, rec := range created {
			_ = cfCall(context.WithoutCancel(ctx), token, "DELETE", "/zones/"+rec.zone+"/dns_records/"+rec.id, nil, nil)
		}
	}()
	var pending []*acme.Authorization
	for _, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return "", "", err
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
			}
		}
		if chal == nil {
			return "", "", fmt.Errorf("no dns-01 challenge offered for %s", authz.Identifier.Value)
		}
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return "", "", err
		}
		fqdn := "_acme-challenge." + strings.TrimPrefix(authz.Identifier.Value, "*.")
		zone, err := cfZone(ctx, token, fqdn)
		if err != nil {
			return "", "", err
		}
		var rec struct{ ID string }
		if err := cfCall(ctx, token, "POST", "/zones/"+zone+"/dns_records", map[string]any{
			"type": "TXT", "name": fqdn, "content": value, "ttl": 60,
		}, &rec); err != nil {
			return "", "", err
		}
		created = append(created, record{zone, rec.ID})
		authz.Challenges = []*acme.Challenge{chal}
		pending = append(pending, authz)
	}
	// Let the TXT records reach Cloudflare's authoritative servers.
	if len(pending) > 0 {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(20 * time.Second):
		}
	}
	for _, authz := range pending {
		if _, err := client.Accept(ctx, authz.Challenges[0]); err != nil {
			return "", "", fmt.Errorf("ACME accept %s: %w", authz.Identifier.Value, err)
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			return "", "", fmt.Errorf("ACME validation of %s: %w", authz.Identifier.Value, err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return "", "", fmt.Errorf("ACME order: %w", err)
	}
	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return "", "", fmt.Errorf("ACME finalize: %w", err)
	}
	var leaf, chain bytes.Buffer
	for i, d := range ders {
		b := &leaf
		if i > 0 {
			b = &chain
		}
		_ = pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	return leaf.String(), chain.String(), nil
}

func (s *Server) acmeAccountKey(ctx context.Context) (crypto.Signer, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}
	if stored := settings[settingACMEAccountKey]; stored != "" {
		keyPEM, err := s.openSetting(settingACMEAccountKey, stored)
		if err != nil {
			return nil, err
		}
		b, _ := pem.Decode([]byte(keyPEM))
		if b == nil {
			return nil, errors.New("the stored ACME account key is unreadable")
		}
		return x509.ParseECPrivateKey(b.Bytes)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(key)
	sealed, err := s.sealSetting(settingACMEAccountKey, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	if err != nil {
		return nil, err
	}
	if err := s.store.SetSettingIfAbsent(ctx, settingACMEAccountKey, sealed, "system"); err != nil {
		return nil, err
	}
	return s.acmeAccountKey(ctx)
}

// --- Active Directory Certificate Services ----------------------------------

// signADCS relays a CSR to the enterprise CA through the Windows endpoint
// configured to submit (Certificates → Certificate authorities). That
// endpoint's machine account needs Enroll on the template, and the template
// must take the subject from the request (as WebServer does).
func (s *Server) signADCS(ctx context.Context, csrPEM string) (string, string, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return "", "", err
	}
	agentID, config, template := settings[settingADCSAgent], settings[settingADCSConfig], settings[settingADCSTemplate]
	if agentID == "" || config == "" {
		return "", "", errors.New("AD CS is not set up: choose the submitting endpoint and the CA (Certificates → Certificate authorities)")
	}
	if template == "" {
		template = "WebServer"
	}
	submitter := s.agentByID(ctx, agentID)
	if submitter == nil || !submitter.Online {
		return "", "", errors.New("the AD CS submitting endpoint is offline")
	}
	res, err := s.agentCertCommand(ctx, agentID, "cert_adcs_submit", proto.CertJob{RequestID: idgen.New("adcs-"), CSRPEM: csrPEM, CAConfig: config, Template: template}, 2*time.Minute)
	if err != nil || !res.OK {
		return "", "", fmt.Errorf("AD CS (%s, template %s) via %s: %s (agent 0.57.26 or newer)\n%s", config, template, submitter.Hostname, firstNonEmpty(res.Error, errString(err)), res.Output)
	}
	return splitLeafChain(res.Output)
}

// splitLeafChain separates the issued certificate from the CA certificates
// that follow it.
func splitLeafChain(bundle string) (string, string, error) {
	rest := []byte(bundle)
	var leaf, chain bytes.Buffer
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if leaf.Len() == 0 {
			_ = pem.Encode(&leaf, b)
		} else {
			_ = pem.Encode(&chain, b)
		}
	}
	if leaf.Len() == 0 {
		return "", "", errors.New("the CA returned no certificate")
	}
	return leaf.String(), chain.String(), nil
}

// --- renewing ---------------------------------------------------------------

func (s *Server) agentCertCommand(ctx context.Context, agentID, cmd string, job proto.CertJob, timeout time.Duration) (proto.AgentCommandResult, error) {
	payload, err := json.Marshal(proto.AgentCommand{Cmd: cmd, Cert: &job})
	if err != nil {
		return proto.AgentCommandResult{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(agentID), payload)
	if err != nil {
		return proto.AgentCommandResult{}, fmt.Errorf("the endpoint did not answer: %w", err)
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &res); err != nil {
		return res, err
	}
	return res, nil
}

// renewManagedCert runs one renewal end to end and records the outcome.
func (s *Server) renewManagedCert(ctx context.Context, id, by string) error {
	mc, err := s.store.GetManagedCert(ctx, id)
	if err != nil || mc == nil {
		return errors.New("no such managed certificate")
	}
	if mc.CA == "upload" {
		return errors.New("Mustra cannot renew a certificate it did not issue: upload its replacement with Upload new version (certs_upload.go)")
	}
	fail := func(why string) error {
		_ = s.store.SetManagedCertState(ctx, mc.ID, "failed", why, false, nil)
		s.notify(ctx, "warning", "Certificates", "Certificate renewal failed: "+mc.Name, safeTruncate(why, 300), "/certificates#renewal")
		s.audit(ctx, auditEvent{Action: "certs.renew", Actor: by, Target: mc.Name, AgentID: mc.AgentID, Outcome: "failed", Severity: "warning",
			Detail: map[string]any{"ca": mc.CA, "path": mc.CertPath, "error": why}})
		s.emitCompleted("certificate", "Certificate renewal failed: "+mc.Name, "failed", "warning", safeTruncate(why, 300), mc.Name, "/certificates", nil)
		return errors.New(why)
	}
	agent := s.agentByID(ctx, mc.AgentID)
	if agent == nil || !agent.Online {
		return fail("the endpoint is offline")
	}
	if mc.CA == "tailscale" {
		return s.renewViaTailscale(ctx, *mc, by, fail)
	}
	_ = s.store.SetManagedCertState(ctx, mc.ID, "renewing", "Asking the endpoint for a key and request", false, nil)
	reqID := idgen.New("crq-")
	friendly := "Mustra: " + mc.Name
	res, err := s.agentCertCommand(ctx, mc.AgentID, "cert_csr", proto.CertJob{RequestID: reqID, Names: mc.Names, CertPath: mc.CertPath, FriendlyName: friendly}, time.Minute)
	if err != nil || !res.OK {
		return fail("creating the key and request on the endpoint: " + firstNonEmpty(res.Error, errString(err)) + " (agent 0.57.20 or newer is needed)")
	}
	block, _ := pem.Decode([]byte(res.Output))
	if block == nil {
		return fail("the endpoint returned no certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return fail("the endpoint's certificate request is invalid")
	}
	_ = s.store.SetManagedCertState(ctx, mc.ID, "renewing", "Signing with "+certCAs[mc.CA], false, nil)
	var certPEM, chainPEM string
	switch mc.CA {
	case "private":
		certPEM, chainPEM, err = s.signPrivate(ctx, csr, mc.Names)
	case "acme":
		certPEM, chainPEM, err = s.signACME(ctx, block.Bytes, mc.Names)
	case "cloudflare_origin":
		certPEM, err = s.signCloudflareOrigin(ctx, res.Output, mc.Names)
	case "adcs":
		certPEM, chainPEM, err = s.signADCS(ctx, res.Output)
	default:
		err = fmt.Errorf("unknown CA %q", mc.CA)
	}
	if err != nil {
		return fail(err.Error())
	}
	cb, _ := pem.Decode([]byte(certPEM))
	leaf, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return fail("the CA returned an unreadable certificate")
	}
	_ = s.store.SetManagedCertState(ctx, mc.ID, "renewing", "Installing on the endpoint and reloading", false, nil)
	res, err = s.agentCertCommand(ctx, mc.AgentID, "cert_install", proto.CertJob{
		RequestID: reqID, Names: mc.Names, CertPath: mc.CertPath, KeyPath: mc.KeyPath, CertPEM: certPEM, ChainPEM: chainPEM,
		ReloadCmd: mc.ReloadCmd, VerifyPort: mc.VerifyPort, WinBind: mc.WinBind, IISSite: mc.IISSite, FriendlyName: friendly,
	}, 3*time.Minute)
	if err != nil || !res.OK {
		return fail("installing: " + firstNonEmpty(res.Error, errString(err)) + "\n" + res.Output)
	}
	expires := leaf.NotAfter
	detail := fmt.Sprintf("Issued by %s and installed; valid until %s.\n%s", certCAs[mc.CA], expires.UTC().Format("2006-01-02"), res.Output)
	_ = s.store.SetManagedCertState(ctx, mc.ID, "idle", detail, true, &expires)
	s.recordIssuance(ctx, *mc, leaf, certPEM, by)
	s.audit(ctx, auditEvent{Action: "certs.renew", Actor: by, Target: mc.Name, AgentID: mc.AgentID, Severity: "notice",
		Detail: map[string]any{"ca": mc.CA, "path": mc.CertPath, "expires": expires}})
	s.emitCompleted("certificate", "Certificate renewed: "+mc.Name, "succeeded", "info",
		"Valid until "+expires.UTC().Format("2 Jan 2006")+".", mc.Name, "/certificates", map[string]any{"expires": expires})
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// winStoreCertPath is where a Windows store certificate is managed; the
// agent reports each one as Cert:\LocalMachine\My\<thumbprint>.
const winStoreCertPath = `Cert:\LocalMachine\My`

func isWinStorePath(p string) bool {
	return strings.EqualFold(strings.TrimRight(strings.TrimSpace(p), `\`), winStoreCertPath)
}

// managedCertAt reports whether a discovered certificate is the managed
// one: at its file, served on its port, or, in the Windows store, under
// its first name (the thumbprint changes with every renewal).
func managedCertAt(mc store.ManagedCert, c proto.CertificateInfo) bool {
	if c.IsCA {
		return false
	}
	if isWinStorePath(mc.CertPath) {
		if !strings.HasPrefix(strings.ToLower(c.Path), strings.ToLower(winStoreCertPath)+`\`) || len(mc.Names) == 0 {
			return false
		}
		if strings.EqualFold(c.Subject, mc.Names[0]) {
			return true
		}
		for _, n := range c.DNSNames {
			if strings.EqualFold(n, mc.Names[0]) {
				return true
			}
		}
		return false
	}
	served := mc.VerifyPort > 0 && strings.HasPrefix(c.Path, "tls://") && strings.HasSuffix(c.Path, fmt.Sprintf(":%d", mc.VerifyPort))
	return c.Path == mc.CertPath || served
}

// managedCertExpiry is the certificate's current expiry from discovery: the
// file at its path, or what its verify port serves.
func (s *Server) managedCertExpiry(ctx context.Context, mc store.ManagedCert) *time.Time {
	rec, err := s.store.GetSensorData(ctx, mc.AgentID, string(proto.SensorCertificates))
	if err != nil || rec == nil {
		return nil
	}
	// A scan from before the last renewal still shows the old certificate;
	// trusting it made a just-renewed certificate look due again, and it was
	// renewed twice in a minute.
	if mc.LastRenewedAt != nil && !rec.CollectedAt.After(*mc.LastRenewedAt) {
		return nil
	}
	var certs []proto.CertificateInfo
	if json.Unmarshal(rec.Data, &certs) != nil {
		return nil
	}
	// A file and the port serving it are one certificate: the soonest
	// expiry wins. In the Windows store, older ones Mustra replaced may
	// linger, so the newest counts.
	store := isWinStorePath(mc.CertPath)
	var best *time.Time
	for _, c := range certs {
		if !managedCertAt(mc, c) {
			continue
		}
		t, err := time.Parse(time.RFC3339, c.NotAfter)
		if err == nil && (best == nil || (!store && t.Before(*best)) || (store && t.After(*best))) {
			best = &t
		}
	}
	return best
}

// certRenewLoop checks every managed certificate hourly: renews the ones
// due, or asks for approval when the certificate wants one.
func (s *Server) certRenewLoop(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		s.checkManagedCerts(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) checkManagedCerts(ctx context.Context) {
	list, err := s.store.ListManagedCerts(ctx)
	if err != nil {
		return
	}
	for _, mc := range list {
		if exp := s.managedCertExpiry(ctx, mc); exp != nil {
			_ = s.store.SetManagedCertExpiry(ctx, mc.ID, *exp)
			mc.ExpiresAt = exp
		}
		// An uploaded certificate is renewed by uploading; expiry alerts remind.
		if !mc.Enabled || mc.CA == "upload" || mc.ExpiresAt == nil || time.Until(*mc.ExpiresAt) > time.Duration(mc.RenewDays)*24*time.Hour {
			continue
		}
		switch mc.State {
		case "renewing", "awaiting_approval":
			continue
		case "failed":
			if mc.LastAttemptAt != nil && time.Since(*mc.LastAttemptAt) < certRetryAfter {
				continue
			}
		}
		if mc.Approval == "approve" {
			_ = s.store.SetManagedCertState(ctx, mc.ID, "awaiting_approval",
				fmt.Sprintf("Due: expires %s. Approve the renewal under Certificates → Renewal.", mc.ExpiresAt.UTC().Format("2006-01-02")), false, nil)
			s.notifyRequest(ctx, "notice", "Certificates", "Certificate renewal waiting for approval: "+mc.Name,
				"Expires "+mc.ExpiresAt.UTC().Format("2006-01-02"), "/certificates#renewal", "cert", mc.ID, false)
			continue
		}
		go func(id string) { _ = s.renewManagedCert(context.WithoutCancel(ctx), id, "schedule") }(mc.ID)
	}
}

// --- API --------------------------------------------------------------------

// listManagedCertsResponse is what GET /api/certificates/managed answers.
type listManagedCertsResponse struct {
	ACMEEmail          string              `json:"acme_email"`
	ACMEStaging        bool                `json:"acme_staging"`
	ADCSAgent          string              `json:"adcs_agent"`
	ADCSConfig         string              `json:"adcs_config"`
	ADCSTemplate       string              `json:"adcs_template"`
	CAs                map[string]string   `json:"cas"`
	CloudflareTokenSet bool                `json:"cloudflare_token_set"`
	Managed            []store.ManagedCert `json:"managed"`
	PrivateCAReady     bool                `json:"private_ca_ready"`
}

func (s *Server) handleListManagedCerts(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListManagedCerts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	settings, _ := s.store.GetAllSettings(r.Context())
	writeJSONResponse(w, listManagedCertsResponse{
		Managed: list, CAs: certCAs,
		PrivateCAReady: settings[settingCACert] != "", CloudflareTokenSet: settings[settingCFToken] != "",
		ACMEEmail: settings[settingACMEEmail], ACMEStaging: settings[settingACMEStaging] == "true",
		ADCSAgent: settings[settingADCSAgent], ADCSConfig: settings[settingADCSConfig], ADCSTemplate: settings[settingADCSTemplate],
	})
}

func (s *Server) handleSaveManagedCert(w http.ResponseWriter, r *http.Request) {
	var m store.ManagedCert
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	// The path decides which record is written: a POST creates one under
	// an ID minted here, whatever the body says, and a PUT updates the one
	// it names. A body ID once let a create overwrite an existing
	// certificate, endpoint, CA and paths included.
	//
	// This handler and the other save handlers that share the pattern
	// (client profiles, deployment templates and plans, maintenance
	// windows, patch lists, like approval policies) look the record up and
	// then upsert it. A PUT racing a DELETE of the same record can
	// therefore recreate it under its old ID. That needs two operators
	// acting on one record at once, and the result is what the PUT asked
	// for, so the check is not made atomic.
	if id := r.PathValue("id"); id != "" {
		old, err := s.store.GetManagedCert(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if old == nil {
			http.Error(w, "no such certificate", http.StatusNotFound)
			return
		}
		m.ID = id
	} else {
		m.ID = idgen.New("mc-")
		m.CreatedBy = auth.CurrentUser(r.Context()).Username
	}
	var clean []string
	for _, n := range m.Names {
		if n = strings.TrimSpace(n); n != "" {
			clean = append(clean, n)
		}
	}
	m.Names, m.CertPath, m.KeyPath = clean, strings.TrimSpace(m.CertPath), strings.TrimSpace(m.KeyPath)
	switch {
	case m.AgentID == "" || m.CertPath == "" || len(m.Names) == 0:
		http.Error(w, "an endpoint, a certificate path and at least one name are required", http.StatusBadRequest)
		return
	case certCAs[m.CA] == "":
		http.Error(w, "unknown CA", http.StatusBadRequest)
		return
	case m.RenewDays < 1 || m.RenewDays > 365:
		http.Error(w, "renew between 1 and 365 days before expiry", http.StatusBadRequest)
		return
	case m.Approval != "auto" && m.Approval != "approve":
		http.Error(w, "approval must be auto or approve", http.StatusBadRequest)
		return
	}
	if m.VerifyPort < 0 || m.VerifyPort > 65535 {
		http.Error(w, "verify port out of range", http.StatusBadRequest)
		return
	}
	// The Windows certificate store, and what to bind there.
	if isWinStorePath(m.CertPath) {
		a := s.agentByID(r.Context(), m.AgentID)
		switch {
		case a == nil || a.OS != "windows":
			http.Error(w, "the Windows certificate store is only on Windows endpoints", http.StatusBadRequest)
			return
		case m.CA == "tailscale":
			http.Error(w, "Tailscale certificates are written as files; choose a file path", http.StatusBadRequest)
			return
		case m.WinBind != "" && m.WinBind != "iis" && m.WinBind != "rdp":
			http.Error(w, "bind to iis, rdp or nothing", http.StatusBadRequest)
			return
		case m.WinBind == "iis" && (strings.TrimSpace(m.IISSite) == "" || m.VerifyPort == 0):
			http.Error(w, "an IIS binding needs the site name and its https port", http.StatusBadRequest)
			return
		}
		m.CertPath, m.KeyPath, m.IISSite = winStoreCertPath, "", strings.TrimSpace(m.IISSite)
		if m.WinBind != "iis" {
			m.IISSite = ""
		}
		if m.WinBind == "rdp" {
			m.VerifyPort = 0
		}
	} else {
		m.WinBind, m.IISSite = "", ""
	}
	if m.Name == "" {
		m.Name = m.Names[0]
	}
	if err := s.store.SaveManagedCert(r.Context(), m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Answer with what was stored, not the body's state, history and
	// creator, which the save ignores.
	saved, err := s.store.GetManagedCert(r.Context(), m.ID)
	if err == nil && saved == nil {
		err = fmt.Errorf("it was deleted meanwhile")
	}
	if err != nil {
		http.Error(w, "saved, but could not read it back: "+err.Error(), http.StatusInternalServerError)
		return
	}
	m = *saved
	// ?issue=1: issue and install it now (Certificates → New certificate).
	if r.URL.Query().Get("issue") == "1" && m.CA != "upload" {
		if a := s.agentByID(r.Context(), m.AgentID); a == nil || !a.Online {
			http.Error(w, "saved, but the endpoint is offline, so nothing was issued; use Renew now once it is back", http.StatusConflict)
			return
		}
		s.issueNow(r.Context(), m.ID, auth.CurrentUser(r.Context()).Username)
		m.State = "renewing"
	}
	s.audit(r.Context(), auditEvent{Action: "certs.manage", Actor: auth.CurrentUser(r.Context()).Username, Target: m.Name,
		AgentID: m.AgentID, Severity: "notice", Detail: map[string]any{"ca": m.CA, "path": m.CertPath, "renew_days": m.RenewDays, "approval": m.Approval}})
	go s.checkManagedCerts(context.WithoutCancel(r.Context()))
	writeJSONResponse(w, m)
}

func (s *Server) handleDeleteManagedCert(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteManagedCert(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/certificates/managed/{id}/renew: renew now. For a certificate
// waiting on approval this is the approval.
func (s *Server) handleRenewManagedCert(w http.ResponseWriter, r *http.Request) {
	who := auth.CurrentUser(r.Context()).Username
	if err := s.renewManagedCert(r.Context(), r.PathValue("id"), who); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	mc, _ := s.store.GetManagedCert(r.Context(), r.PathValue("id"))
	writeJSONResponse(w, mc)
}

// GET /api/certificates/ca.crt: the private CA's root, to install as trusted.
func (s *Server) handleDownloadCA(w http.ResponseWriter, r *http.Request) {
	_, _, certPEM, err := s.privateCA(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="mustra-private-ca.crt"`)
	_, _ = io.WriteString(w, certPEM)
}

// saveCertAuthoritiesRequest is the body of POST /api/admin/cert-authorities.
type saveCertAuthoritiesRequest struct {
	ACMEEmail   *string `json:"acme_email"`
	ACMEStaging *bool   `json:"acme_staging"`
	CFToken     *string `json:"cloudflare_token" api:"writeonly"`
	ADCSAgent   *string `json:"adcs_agent"`
	ADCSConfig  *string `json:"adcs_config"`
	ADCSTmpl    *string `json:"adcs_template"`
}

// POST /api/admin/cert-authorities: ACME email, staging, Cloudflare token.
func (s *Server) handleSaveCertAuthorities(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change certificate authorities") {
		return
	}
	var body saveCertAuthoritiesRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	ctx, who := r.Context(), auth.CurrentUser(r.Context()).Username
	if body.ADCSConfig != nil {
		if v := strings.TrimSpace(*body.ADCSConfig); v != "" && !strings.Contains(v, `\`) {
			http.Error(w, `the CA must be given as host\CA name, e.g. ca01.example.com\Example CA`, http.StatusBadRequest)
			return
		}
	}
	if body.ADCSAgent != nil {
		if v := strings.TrimSpace(*body.ADCSAgent); v != "" {
			a := s.agentByID(ctx, v)
			if a == nil || a.OS != "windows" {
				http.Error(w, "the AD CS submitting endpoint must be a Windows endpoint in the domain", http.StatusBadRequest)
				return
			}
		}
		_ = s.store.SetSetting(ctx, settingADCSAgent, strings.TrimSpace(*body.ADCSAgent), who)
	}
	if body.ADCSConfig != nil {
		_ = s.store.SetSetting(ctx, settingADCSConfig, strings.TrimSpace(*body.ADCSConfig), who)
	}
	if body.ADCSTmpl != nil {
		_ = s.store.SetSetting(ctx, settingADCSTemplate, strings.TrimSpace(*body.ADCSTmpl), who)
	}
	if body.ACMEEmail != nil {
		_ = s.store.SetSetting(ctx, settingACMEEmail, strings.TrimSpace(*body.ACMEEmail), who)
	}
	if body.ACMEStaging != nil {
		_ = s.store.SetSetting(ctx, settingACMEStaging, map[bool]string{true: "true", false: ""}[*body.ACMEStaging], who)
	}
	if body.CFToken != nil {
		sealed, err := s.sealSetting(settingCFToken, strings.TrimSpace(*body.CFToken))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = s.store.SetSetting(ctx, settingCFToken, sealed, who)
	}
	s.audit(ctx, auditEvent{Action: "settings.cert_authorities", Actor: who, Target: "certificates", Severity: "notice",
		Detail: map[string]any{"token_changed": body.CFToken != nil, "adcs_agent": body.ADCSAgent, "adcs_config": body.ADCSConfig, "adcs_template": body.ADCSTmpl}})
	s.handleListManagedCerts(w, r)
}

// renewViaTailscale has the endpoint fetch its own tailnet certificate: the
// key is made by tailscaled there and nothing is signed here.
func (s *Server) renewViaTailscale(ctx context.Context, mc store.ManagedCert, by string, fail func(string) error) error {
	_ = s.store.SetManagedCertState(ctx, mc.ID, "renewing", "Asking Tailscale on the endpoint for its certificate", false, nil)
	res, err := s.agentCertCommand(ctx, mc.AgentID, "cert_tailscale", proto.CertJob{
		Names: mc.Names, CertPath: mc.CertPath, KeyPath: mc.KeyPath, ReloadCmd: mc.ReloadCmd, VerifyPort: mc.VerifyPort,
	}, 4*time.Minute)
	if err != nil || !res.OK {
		return fail("Tailscale certificate: " + firstNonEmpty(res.Error, errString(err)) + " (agent 0.57.24 or newer; HTTPS certificates enabled for the tailnet)\n" + res.Output)
	}
	var expires *time.Time
	if first, _, _ := strings.Cut(res.Output, "\n"); strings.HasPrefix(first, "expires ") {
		if t, err := time.Parse(time.RFC3339, strings.TrimPrefix(first, "expires ")); err == nil {
			expires = &t
		}
	}
	until := "unknown"
	if expires != nil {
		until = expires.UTC().Format("2006-01-02")
	}
	_ = s.store.SetManagedCertState(ctx, mc.ID, "idle", "Renewed by Tailscale (Let's Encrypt); valid until "+until+".\n"+res.Output, true, expires)
	s.audit(ctx, auditEvent{Action: "certs.renew", Actor: by, Target: mc.Name, AgentID: mc.AgentID, Severity: "notice",
		Detail: map[string]any{"ca": mc.CA, "path": mc.CertPath, "expires": expires}})
	s.emitCompleted("certificate", "Certificate renewed: "+mc.Name, "succeeded", "info",
		"Valid until "+until+".", mc.Name, "/certificates", map[string]any{"expires": expires})
	return nil
}
