package server

// Certificate lifecycle: the record of what Mustra issued, revocation, and
// the private CA's revocation list.
//
// Every successful issuance (a first install or a renewal) is recorded with
// its public certificate, serial and fingerprint; the issuance before it is
// marked superseded. That record is the Certificates → Inventory list, and
// it is what revocation works from: each CA revokes differently, and most
// need the serial or the certificate itself.
//
// Revoking, by CA:
//   - private: recorded here and published in the CA's CRL at
//     /pki/mustra-ca.crl, which every certificate it signs now points to.
//   - acme: revoked with Let's Encrypt using the account that ordered it.
//   - cloudflare_origin: the certificate is revoked through the Cloudflare
//     API, found by its serial among the zone's origin certificates.
//   - adcs: the submitting Windows endpoint runs certutil -revoke against
//     the enterprise CA and publishes a new CRL; its computer account needs
//     Issue and Manage Certificates on the CA (true when it is the CA).
//   - tailscale: not revocable from Mustra; Tailscale manages those.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// crlPath is where the private CA's revocation list is served, without
// login: anything checking a certificate must be able to fetch it.
const crlPath = "/pki/mustra-ca.crl"

// revokeReasons are the RFC 5280 reasons offered, by the code each carries.
var revokeReasons = map[string]int{
	"unspecified":            0,
	"key_compromise":         1,
	"superseded":             4,
	"cessation_of_operation": 5,
}

// recordIssuance notes a certificate just installed by a managed renewal.
func (s *Server) recordIssuance(ctx context.Context, mc store.ManagedCert, leaf *x509.Certificate, certPEM, by string) {
	sum := sha256.Sum256(leaf.Raw)
	nb, na := leaf.NotBefore, leaf.NotAfter
	err := s.store.RecordCertIssuance(ctx, store.CertIssuance{
		ID: idgen.New("ci-"), ManagedCertID: mc.ID, AgentID: mc.AgentID, Name: mc.Name, Names: mc.Names,
		CertPath: mc.CertPath, CA: mc.CA, Serial: leaf.SerialNumber.Text(16), Fingerprint: hex.EncodeToString(sum[:]),
		Issuer: leaf.Issuer.CommonName, NotBefore: &nb, NotAfter: &na, CertPEM: certPEM, Source: "issued", IssuedBy: by,
	})
	if err != nil {
		s.logger.Warn("recording certificate issuance failed", "name", mc.Name, "error", err)
	}
}

// adoptInstalledCerts records what each managed certificate's endpoint
// reports at its path when that certificate is not on record yet: one
// installed before the record existed, or one Tailscale renewed (Mustra
// never sees those). known holds the fingerprints on record per managed
// certificate; it reports whether anything was added.
func (s *Server) adoptInstalledCerts(ctx context.Context, managed []store.ManagedCert, known map[string]map[string]bool) bool {
	added := false
	for _, mc := range managed {
		rec, err := s.store.GetSensorData(ctx, mc.AgentID, string(proto.SensorCertificates))
		if err != nil || rec == nil {
			continue
		}
		// A scan from before the last renewal still shows the certificate
		// it replaced; adopting that would supersede the new one.
		if mc.LastRenewedAt != nil && !rec.CollectedAt.After(*mc.LastRenewedAt) {
			continue
		}
		var certs []proto.CertificateInfo
		if json.Unmarshal(rec.Data, &certs) != nil {
			continue
		}
		for _, c := range certs {
			if !managedCertAt(mc, c) || strings.HasPrefix(c.Path, "tls://") || c.Fingerprint == "" || known[mc.ID][c.Fingerprint] {
				continue
			}
			var nb, na *time.Time
			if t, err := time.Parse(time.RFC3339, c.NotBefore); err == nil {
				nb = &t
			}
			if t, err := time.Parse(time.RFC3339, c.NotAfter); err == nil {
				na = &t
			}
			// Tailscale's are Mustra's doing too: it asked for them.
			source, by := "discovered", "discovered"
			if mc.CA == "tailscale" && len(known[mc.ID]) > 0 {
				source, by = "issued", "Tailscale renewal"
			}
			if err := s.store.RecordCertIssuance(ctx, store.CertIssuance{
				ID: idgen.New("ci-"), ManagedCertID: mc.ID, AgentID: mc.AgentID, Name: mc.Name, Names: mc.Names,
				CertPath: mc.CertPath, CA: mc.CA, Serial: strings.ToLower(c.SerialNumber), Fingerprint: c.Fingerprint,
				Issuer: c.Issuer, NotBefore: nb, NotAfter: na, Source: source, IssuedBy: by,
			}); err == nil {
				added = true
			}
			break
		}
	}
	return added
}

// issuanceStatus is what an issuance is now: revoked, expired, superseded
// (replaced by a renewal) or active.
func issuanceStatus(c store.CertIssuance, now time.Time) string {
	switch {
	case c.RevokedAt != nil:
		return "revoked"
	case c.NotAfter != nil && c.NotAfter.Before(now):
		return "expired"
	case c.SupersededAt != nil:
		return "superseded"
	}
	return "active"
}

// revocableWhy says why an issuance cannot be revoked, or "" when it can.
func revocableWhy(c store.CertIssuance, now time.Time) string {
	switch {
	case c.RevokedAt != nil:
		return "already revoked"
	case c.NotAfter != nil && c.NotAfter.Before(now):
		return "expired: nothing trusts it any more"
	case c.CA == "tailscale":
		return "Tailscale certificates are managed by Tailscale"
	case c.CA == "upload":
		return "an uploaded certificate is revoked with the authority that issued it"
	case c.CA == "acme" && c.CertPEM == "":
		return "Let's Encrypt needs the certificate itself, which Mustra only has for ones it issued; renew it first"
	case c.Serial == "":
		return "no serial number on record"
	}
	return ""
}

type issuedView struct {
	store.CertIssuance
	Status    string `json:"status"`
	Revocable bool   `json:"revocable"`
	WhyNot    string `json:"why_not,omitempty"`
	CALabel   string `json:"ca_label"`
}

// listIssuedResponse is what GET /api/certificates/issued answers.
type listIssuedResponse struct {
	CRLURL  string         `json:"crl_url"`
	Issued  []issuedView   `json:"issued"`
	Reasons map[string]int `json:"reasons"`
}

// GET /api/certificates/issued: everything Mustra issued, newest first.
func (s *Server) handleListIssued(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := s.store.ListCertIssuances(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	known := map[string]map[string]bool{}
	for _, c := range list {
		if known[c.ManagedCertID] == nil {
			known[c.ManagedCertID] = map[string]bool{}
		}
		known[c.ManagedCertID][c.Fingerprint] = true
	}
	if managed, err := s.store.ListManagedCerts(ctx); err == nil && s.adoptInstalledCerts(ctx, managed, known) {
		if fresh, err := s.store.ListCertIssuances(ctx); err == nil {
			list = fresh
		}
	}
	now := time.Now()
	out := make([]issuedView, 0, len(list))
	for _, c := range list {
		why := revocableWhy(c, now)
		c.CertPEM = "" // the list does not need it; the revoke path reads it
		out = append(out, issuedView{CertIssuance: c, Status: issuanceStatus(c, now), Revocable: why == "", WhyNot: why, CALabel: certCAs[c.CA]})
	}
	writeJSONResponse(w, listIssuedResponse{Issued: out, CRLURL: crlPath, Reasons: revokeReasons})
}

type revokeRequest struct {
	Reason  string `json:"reason" api:"required"`
	Replace bool   `json:"replace"` // install a new certificate first
	Stop    bool   `json:"stop"`    // stop renewing the managed certificate
}

// revokeIssuedResponse is what POST /api/certificates/issued/{id}/revoke
// answers.
type revokeIssuedResponse struct {
	Detail string `json:"detail"`
	OK     bool   `json:"ok"`
}

// POST /api/certificates/issued/{id}/revoke
func (s *Server) handleRevokeIssued(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	code, ok := revokeReasons[req.Reason]
	if !ok {
		http.Error(w, "choose a reason", http.StatusBadRequest)
		return
	}
	c, err := s.store.GetCertIssuance(ctx, r.PathValue("id"))
	if err != nil || c == nil {
		http.Error(w, "no such certificate", http.StatusNotFound)
		return
	}
	if why := revocableWhy(*c, time.Now()); why != "" {
		http.Error(w, "cannot revoke: "+why, http.StatusUnprocessableEntity)
		return
	}
	var notes []string
	mc, _ := s.store.GetManagedCert(ctx, c.ManagedCertID)
	// Replacing first keeps the service up: the endpoint gets a new
	// certificate before the one it serves stops being trusted.
	if req.Replace {
		if mc == nil {
			http.Error(w, "this certificate is no longer managed, so there is nothing to install in its place; revoke without replacing", http.StatusUnprocessableEntity)
			return
		}
		if err := s.renewManagedCert(ctx, mc.ID, who); err != nil {
			http.Error(w, "the replacement failed, so nothing was revoked: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
		notes = append(notes, "A replacement certificate was installed first.")
	}
	detail, err := s.revokeWithCA(ctx, *c, code)
	if err != nil {
		s.audit(ctx, auditEvent{Action: "certs.revoke", Actor: who, Target: c.Name, AgentID: c.AgentID, Outcome: "failed", Severity: "warning",
			Detail: map[string]any{"ca": c.CA, "serial": c.Serial, "reason": req.Reason, "error": err.Error()}})
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	notes = append(notes, detail)
	if req.Stop && mc != nil {
		mc.Enabled = false
		if err := s.store.SaveManagedCert(ctx, *mc); err == nil {
			notes = append(notes, "Automatic renewal is turned off for it.")
		}
	}
	text := strings.Join(notes, " ")
	if _, err := s.store.MarkCertRevoked(ctx, c.ID, who, req.Reason, text); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "certs.revoke", Actor: who, Target: c.Name, AgentID: c.AgentID, Severity: "notice",
		Detail: map[string]any{"ca": c.CA, "serial": c.Serial, "reason": req.Reason, "replaced": req.Replace, "stopped": req.Stop}})
	s.notify(ctx, "notice", "Certificates", "Certificate revoked: "+c.Name, text, "/certificates#revoke")
	writeJSONResponse(w, revokeIssuedResponse{OK: true, Detail: text})
}

// revokeWithCA asks the issuing CA to revoke, and says what it did.
func (s *Server) revokeWithCA(ctx context.Context, c store.CertIssuance, code int) (string, error) {
	switch c.CA {
	case "private":
		return "Added to Mustra Private CA's revocation list (" + crlPath + ").", nil
	case "acme":
		block, _ := pem.Decode([]byte(c.CertPEM))
		if block == nil {
			return "", errors.New("the certificate on record is unreadable")
		}
		client, err := s.acmeClient(ctx)
		if err != nil {
			return "", err
		}
		if err := client.RevokeCert(ctx, nil, block.Bytes, acme.CRLReasonCode(code)); err != nil {
			return "", fmt.Errorf("Let's Encrypt refused the revocation: %w", err)
		}
		return "Revoked with Let's Encrypt.", nil
	case "cloudflare_origin":
		return s.revokeCloudflareOrigin(ctx, c)
	case "adcs":
		return s.revokeADCS(ctx, c, code)
	}
	return "", fmt.Errorf("%s certificates cannot be revoked from Mustra", firstNonEmpty(certCAs[c.CA], c.CA))
}

// acmeClient is the Let's Encrypt client on the account Mustra orders with.
func (s *Server) acmeClient(ctx context.Context) (*acme.Client, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}
	key, err := s.acmeAccountKey(ctx)
	if err != nil {
		return nil, err
	}
	dir := acme.LetsEncryptURL
	if settings[settingACMEStaging] == "true" {
		dir = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	return &acme.Client{Key: key, DirectoryURL: dir}, nil
}

// revokeCloudflareOrigin finds the origin certificate by serial in the
// zone of its first name and revokes it.
func (s *Server) revokeCloudflareOrigin(ctx context.Context, c store.CertIssuance) (string, error) {
	token, err := s.cloudflareToken(ctx)
	if err != nil {
		return "", err
	}
	if len(c.Names) == 0 {
		return "", errors.New("no names on record to find the zone by")
	}
	zone, err := cfZone(ctx, token, c.Names[0])
	if err != nil {
		return "", err
	}
	var list []struct {
		ID          string `json:"id"`
		Certificate string `json:"certificate"`
	}
	if err := cfCall(ctx, token, "GET", "/certificates?zone_id="+zone, nil, &list); err != nil {
		return "", fmt.Errorf("listing the zone's origin certificates: %w", err)
	}
	for _, oc := range list {
		block, _ := pem.Decode([]byte(oc.Certificate))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !strings.EqualFold(cert.SerialNumber.Text(16), c.Serial) {
			continue
		}
		if err := cfCall(ctx, token, "DELETE", "/certificates/"+oc.ID, nil, nil); err != nil {
			return "", fmt.Errorf("Cloudflare refused the revocation: %w", err)
		}
		return "Revoked with Cloudflare Origin CA.", nil
	}
	return "", errors.New("Cloudflare has no origin certificate with that serial in the zone (already revoked, or issued elsewhere)")
}

// revokeADCS has the AD CS submitting endpoint revoke the serial at the
// enterprise CA and publish a fresh CRL.
func (s *Server) revokeADCS(ctx context.Context, c store.CertIssuance, code int) (string, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return "", err
	}
	agentID, config := settings[settingADCSAgent], settings[settingADCSConfig]
	if agentID == "" || config == "" {
		return "", errors.New("AD CS is not set up (Certificates → Authorities)")
	}
	submitter := s.agentByID(ctx, agentID)
	if submitter == nil || !submitter.Online {
		return "", errors.New("the AD CS endpoint is offline")
	}
	res, err := s.agentCertCommand(ctx, agentID, "cert_adcs_revoke", proto.CertJob{
		RequestID: idgen.New("adcsr-"), CAConfig: config, Serial: c.Serial, Reason: code,
	}, 2*time.Minute)
	if err != nil || !res.OK {
		return "", fmt.Errorf("AD CS (%s) via %s: %s (agent 0.57.35 or newer; its computer account needs Issue and Manage Certificates)\n%s",
			config, submitter.Hostname, firstNonEmpty(res.Error, errString(err)), res.Output)
	}
	return "Revoked at " + config + " and a new CRL published.", nil
}

// GET /pki/mustra-ca.crl: Mustra Private CA's revocation list, signed by
// the CA, valid a week and regenerated on every request.
func (s *Server) handlePrivateCRL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil || settings[settingCACert] == "" {
		http.Error(w, "the private CA has not been created", http.StatusNotFound)
		return
	}
	caCert, caKey, _, err := s.privateCA(ctx)
	if err != nil {
		http.Error(w, "private CA unavailable", http.StatusInternalServerError)
		return
	}
	revoked, err := s.store.RevokedPrivateSerials(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var entries []x509.RevocationListEntry
	for _, c := range revoked {
		n, ok := new(big.Int).SetString(c.Serial, 16)
		if !ok || c.RevokedAt == nil {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: *c.RevokedAt, ReasonCode: revokeReasons[c.RevokeReason]})
	}
	now := time.Now()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(now.Unix()), ThisUpdate: now, NextUpdate: now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, caCert, caKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.Write(der)
}

// privateCRLURL is where certificates the private CA signs say to check
// for revocation, or "" when the console has no public URL configured.
func (s *Server) privateCRLURL(ctx context.Context) string {
	base, err := s.agentPublicURLOrEmpty(ctx)
	if err != nil || base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + crlPath
}

// issueNow starts the first issuance of a just-saved certificate in the
// background; the page follows its state.
func (s *Server) issueNow(ctx context.Context, id, by string) {
	_ = s.store.SetManagedCertState(ctx, id, "renewing", "Queued: issuing and installing", false, nil)
	go func() { _ = s.renewManagedCert(context.WithoutCancel(ctx), id, by) }()
}
