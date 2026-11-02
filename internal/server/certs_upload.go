package server

// Uploaded certificates (Cert Manager → New certificate → "Upload my own
// certificate"). A certificate bought from a public CA, or exported from
// another server, is installed the same way Mustra installs the ones it
// issues: files with a reload and a port check, or the Windows store bound
// to IIS or Remote Desktop, with the same rollback. It is accepted as a
// certificate file (PEM or DER, chain optional) with its key file, or as
// one PFX/PKCS#12 file with its password.
//
// The private key passes through the server to the endpoint and is not
// kept: Mustra cannot renew a certificate it did not issue, so there is
// nothing to keep it for. Expiry alerts remind you, and "Upload new
// version" installs the replacement.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
)

// uploadedCert is a certificate, its chain and its key, read and checked.
type uploadedCert struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
	Key   crypto.PrivateKey
}

// parseUpload reads what was uploaded: PEM or base64 DER for the
// certificate and key, or a base64 PFX with its password.
func parseUpload(certText, keyText, pfxB64, pfxPassword string) (*uploadedCert, error) {
	var u uploadedCert
	if strings.TrimSpace(pfxB64) != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pfxB64))
		if err != nil {
			return nil, errors.New("the PFX file could not be read")
		}
		key, leaf, chain, err := pkcs12.DecodeChain(raw, pfxPassword)
		if err != nil {
			return nil, fmt.Errorf("the PFX file could not be opened (is the password right?): %v", err)
		}
		u.Leaf, u.Chain, u.Key = leaf, chain, key
	} else {
		certs, err := readCertificates(certText)
		if err != nil {
			return nil, err
		}
		// The leaf is the one that is not a CA, else the first.
		for i, c := range certs {
			if !c.IsCA {
				u.Leaf = c
				certs = append(certs[:i:i], certs[i+1:]...)
				break
			}
		}
		if u.Leaf == nil {
			u.Leaf, certs = certs[0], certs[1:]
		}
		u.Chain = certs
		if u.Key, err = readPrivateKey(keyText); err != nil {
			return nil, err
		}
	}
	if err := keyMatches(u.Leaf, u.Key); err != nil {
		return nil, err
	}
	if time.Now().After(u.Leaf.NotAfter) {
		return nil, fmt.Errorf("that certificate expired on %s", u.Leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	return &u, nil
}

// readCertificates accepts PEM (one or more certificates) or one DER
// certificate, base64 encoded.
func readCertificates(text string) ([]*x509.Certificate, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("upload the certificate file")
	}
	var out []*x509.Certificate
	if strings.Contains(text, "-----BEGIN") {
		rest := []byte(text)
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("a certificate in the file cannot be read: %v", err)
			}
			out = append(out, c)
		}
	} else if der, err := base64.StdEncoding.DecodeString(text); err == nil {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("the certificate file is neither PEM nor DER")
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate found in the certificate file")
	}
	return out, nil
}

func readPrivateKey(text string) (crypto.PrivateKey, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("upload the key file (or a PFX that contains the key)")
	}
	var der []byte
	if strings.Contains(text, "-----BEGIN") {
		for rest := []byte(text); ; {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if strings.Contains(b.Type, "ENCRYPTED") {
				return nil, errors.New("the key file is password protected; remove the password (openssl pkey -in key.pem -out plain.pem) or upload a PFX")
			}
			if strings.Contains(b.Type, "PRIVATE KEY") {
				der = b.Bytes
				break
			}
		}
	} else if raw, err := base64.StdEncoding.DecodeString(text); err == nil {
		der = raw
	}
	if der == nil {
		return nil, errors.New("no private key found in the key file")
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("the key file holds a key that cannot be read (RSA, ECDSA and Ed25519 are supported)")
}

// keyMatches checks the key is the certificate's.
func keyMatches(cert *x509.Certificate, key crypto.PrivateKey) error {
	type publicKeyer interface{ Public() crypto.PublicKey }
	pk, ok := key.(publicKeyer)
	if !ok {
		return errors.New("unsupported key type")
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	eq, ok := pk.Public().(equaler)
	if !ok || !eq.Equal(cert.PublicKey) {
		return errors.New("the key does not belong to that certificate")
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return nil
	}
	return errors.New("unsupported key type")
}

func pemCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// installJob turns an upload into the agent's install job for this target.
func (u *uploadedCert) installJob(windowsStore bool) (proto.CertJob, error) {
	var chain strings.Builder
	for _, c := range u.Chain {
		chain.WriteString(pemCert(c))
	}
	job := proto.CertJob{CertPEM: pemCert(u.Leaf), ChainPEM: chain.String()}
	if windowsStore {
		password := randomSecret(32)
		pfx, err := pkcs12.Modern.Encode(u.Key, u.Leaf, u.Chain, password)
		if err != nil {
			return job, fmt.Errorf("packing it for the Windows store: %w", err)
		}
		job.PFXBase64, job.PFXPassword = base64.StdEncoding.EncodeToString(pfx), password
		return job, nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(u.Key)
	if err != nil {
		return job, err
	}
	job.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return job, nil
}

type uploadBody struct {
	Cert        string `json:"cert"`
	Key         string `json:"key" api:"writeonly"`
	PFX         string `json:"pfx" api:"writeonly"`
	PFXPassword string `json:"pfx_password" api:"writeonly"`
}

// POST /api/certificates/managed/{id}/upload: install an uploaded
// certificate (or its renewal) where the managed certificate says.
func (s *Server) handleUploadManagedCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	var b uploadBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&b); err != nil {
		http.Error(w, "invalid body (files up to 1 MB)", http.StatusBadRequest)
		return
	}
	mc, err := s.store.GetManagedCert(ctx, r.PathValue("id"))
	if err != nil || mc == nil {
		http.Error(w, "no such certificate", http.StatusNotFound)
		return
	}
	u, err := parseUpload(b.Cert, b.Key, b.PFX, b.PFXPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if a := s.agentByID(ctx, mc.AgentID); a == nil || !a.Online {
		http.Error(w, "the endpoint is offline; nothing was installed", http.StatusConflict)
		return
	}
	job, err := u.installJob(isWinStorePath(mc.CertPath))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	job.RequestID = idgen.New("upl-")
	job.Names, job.CertPath, job.KeyPath, job.ReloadCmd, job.VerifyPort = mc.Names, mc.CertPath, mc.KeyPath, mc.ReloadCmd, mc.VerifyPort
	job.WinBind, job.IISSite, job.FriendlyName = mc.WinBind, mc.IISSite, "Mustra: "+mc.Name
	_ = s.store.SetManagedCertState(ctx, mc.ID, "renewing", "Installing the uploaded certificate on the endpoint", false, nil)
	res, err := s.agentCertCommand(ctx, mc.AgentID, "cert_install", job, 3*time.Minute)
	if err != nil || !res.OK {
		why := "installing: " + firstNonEmpty(res.Error, errString(err)) + " (agent 0.57.39 or newer)\n" + res.Output
		_ = s.store.SetManagedCertState(ctx, mc.ID, "failed", why, false, nil)
		s.audit(ctx, auditEvent{Action: "certs.upload", Actor: who, Target: mc.Name, AgentID: mc.AgentID, Outcome: "failed", Severity: "warning",
			Detail: map[string]any{"path": mc.CertPath, "error": why}})
		http.Error(w, why, http.StatusUnprocessableEntity)
		return
	}
	expires := u.Leaf.NotAfter
	detail := fmt.Sprintf("Uploaded certificate from %s installed; valid until %s.\n%s", firstNonEmpty(u.Leaf.Issuer.CommonName, "its issuer"),
		expires.UTC().Format("2006-01-02"), res.Output)
	_ = s.store.SetManagedCertState(ctx, mc.ID, "idle", detail, true, &expires)
	s.recordIssuance(ctx, *mc, u.Leaf, pemCert(u.Leaf), who)
	s.audit(ctx, auditEvent{Action: "certs.upload", Actor: who, Target: mc.Name, AgentID: mc.AgentID, Severity: "notice",
		Detail: map[string]any{"path": mc.CertPath, "issuer": u.Leaf.Issuer.CommonName, "expires": expires, "serial": u.Leaf.SerialNumber.Text(16)}})
	m, _ := s.store.GetManagedCert(ctx, mc.ID)
	writeJSONResponse(w, m)
}

// previewUploadResponse is what POST /api/certificates/upload/preview
// answers.
type previewUploadResponse struct {
	Chain    int      `json:"chain"`
	DaysLeft int      `json:"days_left"`
	Issuer   string   `json:"issuer"`
	Names    []string `json:"names"`
	NotAfter string   `json:"not_after"`
	Subject  string   `json:"subject"`
}

// POST /api/certificates/upload/preview: read and check an upload before
// anything is installed, so the form can show what it is and fill in its
// names. Nothing is stored.
func (s *Server) handlePreviewUpload(w http.ResponseWriter, r *http.Request) {
	var b uploadBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&b); err != nil {
		http.Error(w, "invalid body (files up to 1 MB)", http.StatusBadRequest)
		return
	}
	u, err := parseUpload(b.Cert, b.Key, b.PFX, b.PFXPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	names := append([]string{}, u.Leaf.DNSNames...)
	for _, ip := range u.Leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 && u.Leaf.Subject.CommonName != "" {
		names = []string{u.Leaf.Subject.CommonName}
	}
	writeJSONResponse(w, previewUploadResponse{Subject: u.Leaf.Subject.CommonName, Issuer: u.Leaf.Issuer.CommonName,
		Names: names, NotAfter: u.Leaf.NotAfter.UTC().Format(time.RFC3339), Chain: len(u.Chain),
		DaysLeft: daysLeft(u.Leaf.NotAfter, time.Now())})
}
