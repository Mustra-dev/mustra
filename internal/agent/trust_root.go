package agent

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Trusted roots: Cert Manager pushes a CA's root certificate (Mustra's
// private CA, the domain's AD CS root) into each endpoint's system trust
// store, so certificates it signs are trusted there without a warning.
//
// macOS will not let even root mark a certificate trusted without a person
// at the keyboard; there the agent only checks, and the server installs a
// root-certificate profile through MDM instead (errMDMRequired).

// errMDMRequiredPrefix tells the server to fall back to MDM.
const errMDMRequiredPrefix = "mdm-required: "

type rootCert struct {
	cert *x509.Certificate
	pem  []byte
	file string // file name used in trust-store directories
	sha1 string // Windows thumbprint
}

func parseRoot(pemText string) (rootCert, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" {
		return rootCert{}, errors.New("no root certificate in the request")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return rootCert{}, err
	}
	if !c.IsCA {
		return rootCert{}, errors.New("that certificate is not a CA certificate")
	}
	sum := sha256.Sum256(c.Raw)
	thumb := sha1.Sum(c.Raw)
	return rootCert{
		cert: c,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}),
		file: "mustra-" + hex.EncodeToString(sum[:6]) + ".crt",
		sha1: strings.ToUpper(hex.EncodeToString(thumb[:])),
	}, nil
}

func trustRoot(ctx context.Context, job proto.CertJob) (string, error) {
	root, err := parseRoot(job.CertPEM)
	if err != nil {
		return "", err
	}
	if inHAOSAddon() {
		return "", errors.New("unsupported: Home Assistant OS manages its own trust store; the add-on cannot change it")
	}
	return trustRootOS(ctx, root, job.Remove)
}
