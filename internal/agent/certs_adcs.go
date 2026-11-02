package agent

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// AD CS submission, endpoint half. A Windows endpoint in the domain (the CA
// server itself, normally) submits a CSR made on another endpoint to the
// enterprise CA with certreq and returns the issued certificate followed by
// its CA certificate, as PEM. The key stays where it was made; this
// endpoint only relays the request under its own machine identity, which
// is what the template's Enroll permission has to allow.

var adcsConfigRe = regexp.MustCompile(`^[A-Za-z0-9.-]+\\[^"\r\n\\]+$`)
var adcsTemplateRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]+$`)

func checkADCSJob(csrPEM, config, template string) error {
	if !adcsConfigRe.MatchString(config) {
		return errors.New(`the CA config must be host\CA name, e.g. ca01.example.com\Example CA`)
	}
	if !adcsTemplateRe.MatchString(template) {
		return errors.New("the template must be its short name, e.g. WebServer")
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return errors.New("no certificate request to submit")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return errors.New("the certificate request is invalid")
	}
	return nil
}

// certreqPending recognises a request the CA accepted but holds for a CA
// manager's approval, and returns its request ID.
var certreqPendingRe = regexp.MustCompile(`(?i)RequestId:\s*"?(\d+)"?[\s\S]*?(pending|taken under submission)|(pending|taken under submission)[\s\S]*?RequestId:\s*"?(\d+)`)

func certreqPending(out string) (string, bool) {
	m := certreqPendingRe.FindStringSubmatch(out)
	if m == nil {
		return "", false
	}
	return m[1] + m[4], true
}

// pemCertificates normalises certificate files that certreq/certutil may
// write as PEM or as raw DER into PEM blocks.
func pemCertificates(data []byte) (string, error) {
	var out strings.Builder
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			out.Write(pem.EncodeToMemory(b))
		}
	}
	if out.Len() > 0 {
		return out.String(), nil
	}
	if _, err := x509.ParseCertificate(data); err != nil {
		return "", fmt.Errorf("not a certificate: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})), nil
}
