package server

// The identity providers App Credentials can renew at. Each is the
// smallest use of its API that discovers, rotates and retires credentials;
// see appcreds.go for what the modes do with them.
//
// What each can do:
//
//	                    discover  rotate  retire old
//	Entra client secret     ✓        ✓       ✓ (removePassword)
//	Entra client cert       ✓        ✓       ✓ (keyCredentials)
//	Entra SAML signing      ✓        ✓       left in place, inactive
//	Authentik OAuth secret  ✓        ✓       n/a: a new secret replaces the old at once
//	Authentik SAML signing  ✓        ✓       ✓ (unused key pair deleted)
//	Okta client secret      ✓        ✓       ✓ (deactivate, delete)
//	Okta SAML signing       ✓        ✓       left in place (Okta keys expire)
//	GCP service-account key ✓        ✓       ✓

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

var appCredHTTP = &http.Client{Timeout: 30 * time.Second}

// apiJSON makes one JSON request and decodes the answer; a non-2xx answer
// is an error carrying the provider's own message.
func apiJSON(ctx context.Context, method, rawURL string, header map[string]string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := appCredHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, redactURL(rawURL), resp.StatusCode, safeTruncate(apiErrorText(data), 300))
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// apiErrorText digs the message out of the error shapes these APIs use.
func apiErrorText(data []byte) string {
	var e struct {
		Error any `json:"error"`
		// Graph
		Message string `json:"message"`
		// Okta
		ErrorSummary string `json:"errorSummary"`
		// Authentik
		Detail string `json:"detail"`
	}
	if json.Unmarshal(data, &e) == nil {
		if m, ok := e.Error.(map[string]any); ok {
			if s, ok := m["message"].(string); ok {
				return s
			}
		}
		for _, s := range []string{e.ErrorSummary, e.Detail, e.Message} {
			if s != "" {
				return s
			}
		}
		if s, ok := e.Error.(string); ok {
			return s
		}
	}
	return strings.TrimSpace(string(data))
}

func redactURL(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}

func randomSecret(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	for i := range b {
		v, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, f := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700"} {
		if t, err := time.Parse(f, s); err == nil {
			return &t
		}
	}
	return nil
}

// newSelfSignedClientCert makes a key and a self-signed certificate for an
// app that authenticates with a certificate rather than a secret.
func newSelfSignedClientCert(name string, valid time.Duration) (certPEM, keyPEM string, der []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(valid),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), der, nil
}

func certPEMFromBase64(b64 string) string {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// --- Microsoft Entra ID (Microsoft Graph) ------------------------------------
//
// The connection is an app registration with the Application.ReadWrite.All
// application permission (admin consent), signing in with a client secret.

type entraProvider struct {
	tenant, clientID, secret string
	token                    string
	// Tests point these at a fake; empty means Microsoft's.
	loginBase, graphBase string
}

const graph = "https://graph.microsoft.com/v1.0"

func (p *entraProvider) graphURL() string { return firstNonEmpty(p.graphBase, graph) }

func (p *entraProvider) auth(ctx context.Context) (map[string]string, error) {
	if p.token == "" {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {p.clientID}, "client_secret": {p.secret},
			"scope": {"https://graph.microsoft.com/.default"}}
		req, _ := http.NewRequestWithContext(ctx, "POST", firstNonEmpty(p.loginBase, "https://login.microsoftonline.com")+"/"+url.PathEscape(p.tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := appCredHTTP.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var tok struct {
			AccessToken string `json:"access_token"`
			Desc        string `json:"error_description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&tok)
		if tok.AccessToken == "" {
			return nil, fmt.Errorf("Entra sign-in failed: %s", safeTruncate(firstNonEmpty(tok.Desc, resp.Status), 200))
		}
		p.token = tok.AccessToken
	}
	return map[string]string{"Authorization": "Bearer " + p.token}, nil
}

func (p *entraProvider) get(ctx context.Context, path string, out any) error {
	h, err := p.auth(ctx)
	if err != nil {
		return err
	}
	return apiJSON(ctx, "GET", p.graphURL()+path, h, nil, out)
}

func (p *entraProvider) send(ctx context.Context, method, path string, body, out any) error {
	h, err := p.auth(ctx)
	if err != nil {
		return err
	}
	return apiJSON(ctx, method, p.graphURL()+path, h, body, out)
}

func (p *entraProvider) Test(ctx context.Context) error {
	return p.get(ctx, "/applications?$top=1&$select=id", nil)
}

type graphKey struct {
	KeyID               string `json:"keyId"`
	DisplayName         string `json:"displayName"`
	EndDateTime         string `json:"endDateTime"`
	StartDateTime       string `json:"startDateTime,omitempty"`
	Type                string `json:"type,omitempty"`
	Usage               string `json:"usage,omitempty"`
	Key                 any    `json:"key,omitempty"`
	CustomKeyIdentifier any    `json:"customKeyIdentifier,omitempty"`
}

func (p *entraProvider) Discover(ctx context.Context) ([]store.AppCredential, error) {
	var out []store.AppCredential
	next := "/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999"
	for next != "" {
		var page struct {
			Value []struct {
				ID          string     `json:"id"`
				DisplayName string     `json:"displayName"`
				Passwords   []graphKey `json:"passwordCredentials"`
				Keys        []graphKey `json:"keyCredentials"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if err := p.get(ctx, next, &page); err != nil {
			return nil, err
		}
		for _, a := range page.Value {
			for _, k := range a.Passwords {
				out = append(out, store.AppCredential{AppID: a.ID, AppName: a.DisplayName, CredType: "client_secret",
					ExternalID: k.KeyID, DisplayName: firstNonEmpty(k.DisplayName, "client secret"), ExpiresAt: parseTime(k.EndDateTime)})
			}
			for _, k := range a.Keys {
				if k.Usage == "Verify" {
					out = append(out, store.AppCredential{AppID: a.ID, AppName: a.DisplayName, CredType: "client_certificate",
						ExternalID: k.KeyID, DisplayName: firstNonEmpty(k.DisplayName, "client certificate"), ExpiresAt: parseTime(k.EndDateTime)})
				}
			}
		}
		next = strings.TrimPrefix(page.Next, p.graphURL())
	}
	// SAML signing certificates belong to the enterprise application (the
	// service principal); only the one in use is tracked.
	var sps struct {
		Value []struct {
			ID          string     `json:"id"`
			DisplayName string     `json:"displayName"`
			Thumbprint  string     `json:"preferredTokenSigningKeyThumbprint"`
			Keys        []graphKey `json:"keyCredentials"`
		} `json:"value"`
	}
	if err := p.get(ctx, "/servicePrincipals?$filter=preferredSingleSignOnMode%20eq%20'saml'&$select=id,displayName,preferredTokenSigningKeyThumbprint,keyCredentials&$top=999", &sps); err != nil {
		return nil, err
	}
	for _, sp := range sps.Value {
		for _, k := range sp.Keys {
			ck, _ := k.CustomKeyIdentifier.(string)
			if k.Usage != "Sign" || (sp.Thumbprint != "" && !thumbMatches(ck, sp.Thumbprint)) {
				continue
			}
			out = append(out, store.AppCredential{AppID: "sp:" + sp.ID, AppName: sp.DisplayName, CredType: "saml_signing",
				ExternalID: k.KeyID, DisplayName: firstNonEmpty(k.DisplayName, "SAML signing"), ExpiresAt: parseTime(k.EndDateTime)})
		}
	}
	return out, nil
}

// thumbMatches compares Graph's customKeyIdentifier (base64 of the SHA-1
// thumbprint) with a hex thumbprint.
func thumbMatches(customKeyID, thumbHex string) bool {
	raw, err := base64.StdEncoding.DecodeString(customKeyID)
	if err != nil {
		return strings.EqualFold(customKeyID, thumbHex)
	}
	return strings.EqualFold(hex.EncodeToString(raw), thumbHex)
}

func (p *entraProvider) Rotate(ctx context.Context, c store.AppCredential) (credRotation, error) {
	lifetime := 180 * 24 * time.Hour
	switch c.CredType {
	case "client_secret":
		var res struct {
			KeyID       string `json:"keyId"`
			SecretText  string `json:"secretText"`
			EndDateTime string `json:"endDateTime"`
		}
		err := p.send(ctx, "POST", "/applications/"+url.PathEscape(c.AppID)+"/addPassword", map[string]any{"passwordCredential": map[string]any{
			"displayName": "Mustra " + time.Now().UTC().Format("2006-01-02"), "endDateTime": time.Now().Add(lifetime).UTC().Format(time.RFC3339)}}, &res)
		if err != nil {
			return credRotation{}, err
		}
		return credRotation{ExternalID: res.KeyID, ExpiresAt: parseTime(res.EndDateTime), Secret: res.SecretText}, nil
	case "client_certificate":
		certPEM, keyPEM, der, err := newSelfSignedClientCert(c.AppName, 365*24*time.Hour)
		if err != nil {
			return credRotation{}, err
		}
		keys, err := p.appKeys(ctx, c.AppID)
		if err != nil {
			return credRotation{}, err
		}
		end := time.Now().Add(365 * 24 * time.Hour).UTC()
		keys = append(keys, graphKey{Type: "AsymmetricX509Cert", Usage: "Verify", Key: base64.StdEncoding.EncodeToString(der),
			DisplayName: "CN=" + c.AppName + " (Mustra)", EndDateTime: end.Format(time.RFC3339)})
		if err := p.send(ctx, "PATCH", "/applications/"+url.PathEscape(c.AppID), map[string]any{"keyCredentials": keys}, nil); err != nil {
			return credRotation{}, err
		}
		after, err := p.appKeys(ctx, c.AppID)
		if err != nil {
			return credRotation{}, err
		}
		id := ""
		for _, k := range after {
			if s, _ := k.Key.(string); s == base64.StdEncoding.EncodeToString(der) {
				id = k.KeyID
			}
		}
		return credRotation{ExternalID: id, ExpiresAt: &end, CertPEM: certPEM, KeyPEM: keyPEM}, nil
	case "saml_signing":
		sp := strings.TrimPrefix(c.AppID, "sp:")
		var res struct {
			KeyID               string `json:"keyId"`
			Key                 string `json:"key"`
			EndDateTime         string `json:"endDateTime"`
			CustomKeyIdentifier string `json:"customKeyIdentifier"`
			Thumbprint          string `json:"thumbprint"`
		}
		err := p.send(ctx, "POST", "/servicePrincipals/"+url.PathEscape(sp)+"/addTokenSigningCertificate", map[string]any{
			"displayName": "CN=" + c.AppName + " SAML signing (Mustra)", "endDateTime": time.Now().Add(3 * 365 * 24 * time.Hour).UTC().Format(time.RFC3339)}, &res)
		if err != nil {
			return credRotation{}, err
		}
		thumb := res.Thumbprint
		if thumb == "" {
			thumb = res.CustomKeyIdentifier
		}
		// Make it the one Entra signs with; the app must trust it first,
		// which is what push (or the download) is for.
		if err := p.send(ctx, "PATCH", "/servicePrincipals/"+url.PathEscape(sp), map[string]any{"preferredTokenSigningKeyThumbprint": thumb}, nil); err != nil {
			return credRotation{}, fmt.Errorf("made the certificate but could not make it active: %w", err)
		}
		return credRotation{ExternalID: res.KeyID, ExpiresAt: parseTime(res.EndDateTime), CertPEM: certPEMFromBase64(res.Key),
			Note: "Entra now signs with the new certificate; the application must trust it."}, nil
	}
	return credRotation{}, fmt.Errorf("Entra cannot rotate a %s", c.CredType)
}

// appKeys reads an application's key credentials with their keys: a PATCH
// must send back every key it keeps.
func (p *entraProvider) appKeys(ctx context.Context, appID string) ([]graphKey, error) {
	var app struct {
		Keys []graphKey `json:"keyCredentials"`
	}
	if err := p.get(ctx, "/applications/"+url.PathEscape(appID)+"?$select=keyCredentials", &app); err != nil {
		return nil, err
	}
	for i, k := range app.Keys {
		if k.Key == nil {
			return nil, errors.New("Graph did not return the existing certificates, so they cannot be kept; nothing was changed")
		}
		app.Keys[i].CustomKeyIdentifier = nil
	}
	return app.Keys, nil
}

func (p *entraProvider) Retire(ctx context.Context, c store.AppCredential, externalID string) error {
	switch c.CredType {
	case "client_secret":
		return p.send(ctx, "POST", "/applications/"+url.PathEscape(c.AppID)+"/removePassword", map[string]any{"keyId": externalID}, nil)
	case "client_certificate":
		keys, err := p.appKeys(ctx, c.AppID)
		if err != nil {
			return err
		}
		kept := keys[:0]
		for _, k := range keys {
			if k.KeyID != externalID {
				kept = append(kept, k)
			}
		}
		return p.send(ctx, "PATCH", "/applications/"+url.PathEscape(c.AppID), map[string]any{"keyCredentials": kept}, nil)
	}
	return nil // SAML: the old certificate stays, inactive, until it expires
}

// --- Authentik --------------------------------------------------------------
//
// The connection is an API token (Directory → Tokens) of a user allowed to
// change providers and certificates.

type authentikProvider struct{ base, token string }

func (p *authentikProvider) call(ctx context.Context, method, path string, body, out any) error {
	return apiJSON(ctx, method, p.base+"/api/v3"+path, map[string]string{"Authorization": "Bearer " + p.token}, body, out)
}

func (p *authentikProvider) Test(ctx context.Context) error {
	return p.call(ctx, "GET", "/core/users/me/", nil, nil)
}

func (p *authentikProvider) Discover(ctx context.Context) ([]store.AppCredential, error) {
	var out []store.AppCredential
	var oauth struct {
		Results []struct {
			PK         int    `json:"pk"`
			Name       string `json:"name"`
			ClientType string `json:"client_type"`
		} `json:"results"`
	}
	if err := p.call(ctx, "GET", "/providers/oauth2/?page_size=500", nil, &oauth); err != nil {
		return nil, err
	}
	for _, o := range oauth.Results {
		if o.ClientType == "confidential" {
			out = append(out, store.AppCredential{AppID: fmt.Sprint(o.PK), AppName: o.Name, CredType: "client_secret",
				ExternalID: "current", DisplayName: "OAuth client secret"})
		}
	}
	var saml struct {
		Results []struct {
			PK        int    `json:"pk"`
			Name      string `json:"name"`
			SigningKP string `json:"signing_kp"`
		} `json:"results"`
	}
	if err := p.call(ctx, "GET", "/providers/saml/?page_size=500", nil, &saml); err != nil {
		return nil, err
	}
	for _, s := range saml.Results {
		if s.SigningKP == "" {
			continue
		}
		var kp struct {
			Name       string `json:"name"`
			CertExpiry string `json:"cert_expiry"`
		}
		_ = p.call(ctx, "GET", "/crypto/certificatekeypairs/"+url.PathEscape(s.SigningKP)+"/", nil, &kp)
		out = append(out, store.AppCredential{AppID: fmt.Sprint(s.PK), AppName: s.Name, CredType: "saml_signing",
			ExternalID: s.SigningKP, DisplayName: firstNonEmpty(kp.Name, "SAML signing"), ExpiresAt: parseTime(kp.CertExpiry)})
	}
	return out, nil
}

func (p *authentikProvider) Rotate(ctx context.Context, c store.AppCredential) (credRotation, error) {
	switch c.CredType {
	case "client_secret":
		secret := randomSecret(96)
		if err := p.call(ctx, "PATCH", "/providers/oauth2/"+url.PathEscape(c.AppID)+"/", map[string]any{"client_secret": secret}, nil); err != nil {
			return credRotation{}, err
		}
		return credRotation{ExternalID: "rotated-" + time.Now().UTC().Format("20060102T150405Z"), Secret: secret,
			Note: "Authentik replaces the secret at once: the application needs the new one now."}, nil
	case "saml_signing":
		var kp struct {
			PK string `json:"pk"`
		}
		if err := p.call(ctx, "POST", "/crypto/certificatekeypairs/generate/", map[string]any{
			"common_name": c.AppName + " SAML signing (Mustra " + time.Now().UTC().Format("2006-01-02") + ")", "validity_days": 730}, &kp); err != nil {
			return credRotation{}, err
		}
		var view struct {
			Data string `json:"data"`
		}
		_ = p.call(ctx, "GET", "/crypto/certificatekeypairs/"+url.PathEscape(kp.PK)+"/view_certificate/", nil, &view)
		if err := p.call(ctx, "PATCH", "/providers/saml/"+url.PathEscape(c.AppID)+"/", map[string]any{"signing_kp": kp.PK}, nil); err != nil {
			_ = p.call(ctx, "DELETE", "/crypto/certificatekeypairs/"+url.PathEscape(kp.PK)+"/", nil, nil)
			return credRotation{}, err
		}
		exp := time.Now().Add(730 * 24 * time.Hour)
		return credRotation{ExternalID: kp.PK, ExpiresAt: &exp, CertPEM: view.Data,
			Note: "Authentik now signs with the new certificate; the application must trust it."}, nil
	}
	return credRotation{}, fmt.Errorf("Authentik cannot rotate a %s", c.CredType)
}

func (p *authentikProvider) Retire(ctx context.Context, c store.AppCredential, externalID string) error {
	if c.CredType != "saml_signing" || externalID == "" {
		return nil
	}
	// Only a key pair no provider still uses.
	var saml struct {
		Results []struct {
			SigningKP string `json:"signing_kp"`
		} `json:"results"`
	}
	if err := p.call(ctx, "GET", "/providers/saml/?page_size=500", nil, &saml); err != nil {
		return err
	}
	for _, s := range saml.Results {
		if s.SigningKP == externalID {
			return nil
		}
	}
	return p.call(ctx, "DELETE", "/crypto/certificatekeypairs/"+url.PathEscape(externalID)+"/", nil, nil)
}

// --- Okta -------------------------------------------------------------------
//
// The connection is an API token (Security → API → Tokens) of an admin who
// may manage applications.

type oktaProvider struct{ base, token string }

func (p *oktaProvider) call(ctx context.Context, method, path string, body, out any) error {
	return apiJSON(ctx, method, p.base+"/api/v1"+path, map[string]string{"Authorization": "SSWS " + p.token}, body, out)
}

func (p *oktaProvider) Test(ctx context.Context) error {
	return p.call(ctx, "GET", "/apps?limit=1", nil, nil)
}

type oktaApp struct {
	ID          string         `json:"id"`
	Label       string         `json:"label"`
	SignOnMode  string         `json:"signOnMode"`
	Status      string         `json:"status"`
	Credentials map[string]any `json:"credentials"`
}

func (p *oktaProvider) Discover(ctx context.Context) ([]store.AppCredential, error) {
	var apps []oktaApp
	if err := p.call(ctx, "GET", "/apps?limit=200&filter=status%20eq%20%22ACTIVE%22", nil, &apps); err != nil {
		return nil, err
	}
	var out []store.AppCredential
	for _, a := range apps {
		switch a.SignOnMode {
		case "OPENID_CONNECT":
			var secrets []struct {
				ID      string `json:"id"`
				Status  string `json:"status"`
				Created string `json:"created"`
			}
			if err := p.call(ctx, "GET", "/apps/"+url.PathEscape(a.ID)+"/credentials/secrets", nil, &secrets); err != nil {
				continue // public clients have none
			}
			for _, s := range secrets {
				if s.Status == "ACTIVE" {
					out = append(out, store.AppCredential{AppID: a.ID, AppName: a.Label, CredType: "client_secret", ExternalID: s.ID,
						DisplayName: "client secret created " + strings.SplitN(s.Created, "T", 2)[0]})
				}
			}
		case "SAML_2_0":
			signing, _ := a.Credentials["signing"].(map[string]any)
			kid, _ := signing["kid"].(string)
			var keys []struct {
				Kid       string `json:"kid"`
				ExpiresAt string `json:"expiresAt"`
			}
			if err := p.call(ctx, "GET", "/apps/"+url.PathEscape(a.ID)+"/credentials/keys", nil, &keys); err != nil {
				continue
			}
			for _, k := range keys {
				if k.Kid == kid {
					out = append(out, store.AppCredential{AppID: a.ID, AppName: a.Label, CredType: "saml_signing", ExternalID: k.Kid,
						DisplayName: "SAML signing", ExpiresAt: parseTime(k.ExpiresAt)})
				}
			}
		}
	}
	return out, nil
}

func (p *oktaProvider) Rotate(ctx context.Context, c store.AppCredential) (credRotation, error) {
	switch c.CredType {
	case "client_secret":
		var res struct {
			ID           string `json:"id"`
			ClientSecret string `json:"client_secret"`
		}
		if err := p.call(ctx, "POST", "/apps/"+url.PathEscape(c.AppID)+"/credentials/secrets", map[string]any{}, &res); err != nil {
			return credRotation{}, err
		}
		return credRotation{ExternalID: res.ID, Secret: res.ClientSecret}, nil
	case "saml_signing":
		var key struct {
			Kid       string   `json:"kid"`
			ExpiresAt string   `json:"expiresAt"`
			X5c       []string `json:"x5c"`
		}
		if err := p.call(ctx, "POST", "/apps/"+url.PathEscape(c.AppID)+"/credentials/keys/generate?validityYears=2", nil, &key); err != nil {
			return credRotation{}, err
		}
		var app map[string]any
		if err := p.call(ctx, "GET", "/apps/"+url.PathEscape(c.AppID), nil, &app); err != nil {
			return credRotation{}, err
		}
		creds, _ := app["credentials"].(map[string]any)
		if creds == nil {
			creds = map[string]any{}
		}
		creds["signing"] = map[string]any{"kid": key.Kid}
		app["credentials"] = creds
		if err := p.call(ctx, "PUT", "/apps/"+url.PathEscape(c.AppID), app, nil); err != nil {
			return credRotation{}, fmt.Errorf("made the key but could not make it active: %w", err)
		}
		pemText := ""
		if len(key.X5c) > 0 {
			pemText = certPEMFromBase64(key.X5c[0])
		}
		return credRotation{ExternalID: key.Kid, ExpiresAt: parseTime(key.ExpiresAt), CertPEM: pemText,
			Note: "Okta now signs with the new certificate; the application must trust it."}, nil
	}
	return credRotation{}, fmt.Errorf("Okta cannot rotate a %s", c.CredType)
}

func (p *oktaProvider) Retire(ctx context.Context, c store.AppCredential, externalID string) error {
	if c.CredType != "client_secret" || externalID == "" {
		return nil
	}
	base := "/apps/" + url.PathEscape(c.AppID) + "/credentials/secrets/" + url.PathEscape(externalID)
	if err := p.call(ctx, "POST", base+"/lifecycle/deactivate", nil, nil); err != nil {
		return err
	}
	return p.call(ctx, "DELETE", base, nil, nil)
}

// --- Google Cloud (service-account keys) ------------------------------------
//
// The connection is a service-account key (JSON) for an account with the
// Service Account Key Admin role on the project.

type gcpProvider struct {
	project string
	email   string
	key     *rsa.PrivateKey
	token   string
}

func newGCPProvider(project, keyJSON string) (credProvider, *store.AppCredConnection, error) {
	var k struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		ProjectID   string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(keyJSON), &k); err != nil || k.PrivateKey == "" {
		return nil, nil, errors.New("the Google connection needs a service-account key file (JSON)")
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return nil, nil, errors.New("the service-account key has no private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	rk, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("the service-account key is not RSA")
	}
	if project == "" {
		project = k.ProjectID
	}
	return &gcpProvider{project: project, email: k.ClientEmail, key: rk}, nil, nil
}

func (p *gcpProvider) auth(ctx context.Context) (map[string]string, error) {
	if p.token == "" {
		now := time.Now()
		enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
		unsigned := enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + enc(map[string]any{
			"iss": p.email, "scope": "https://www.googleapis.com/auth/cloud-platform", "aud": "https://oauth2.googleapis.com/token",
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
		sum := sha256.Sum256([]byte(unsigned))
		sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
		if err != nil {
			return nil, err
		}
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)}}
		resp, err := appCredHTTP.PostForm("https://oauth2.googleapis.com/token", form)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var tok struct {
			AccessToken string `json:"access_token"`
			Desc        string `json:"error_description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&tok)
		if tok.AccessToken == "" {
			return nil, fmt.Errorf("Google sign-in failed: %s", firstNonEmpty(tok.Desc, resp.Status))
		}
		p.token = tok.AccessToken
	}
	return map[string]string{"Authorization": "Bearer " + p.token}, nil
}

func (p *gcpProvider) call(ctx context.Context, method, rawURL string, body, out any) error {
	h, err := p.auth(ctx)
	if err != nil {
		return err
	}
	return apiJSON(ctx, method, rawURL, h, body, out)
}

const iamAPI = "https://iam.googleapis.com/v1/"

func (p *gcpProvider) Test(ctx context.Context) error {
	return p.call(ctx, "GET", iamAPI+"projects/"+url.PathEscape(p.project)+"/serviceAccounts?pageSize=1", nil, nil)
}

func (p *gcpProvider) Discover(ctx context.Context) ([]store.AppCredential, error) {
	var sas struct {
		Accounts []struct {
			Email       string `json:"email"`
			DisplayName string `json:"displayName"`
		} `json:"accounts"`
	}
	if err := p.call(ctx, "GET", iamAPI+"projects/"+url.PathEscape(p.project)+"/serviceAccounts?pageSize=100", nil, &sas); err != nil {
		return nil, err
	}
	var out []store.AppCredential
	for _, sa := range sas.Accounts {
		var keys struct {
			Keys []struct {
				Name            string `json:"name"`
				ValidBeforeTime string `json:"validBeforeTime"`
			} `json:"keys"`
		}
		if err := p.call(ctx, "GET", iamAPI+"projects/-/serviceAccounts/"+url.PathEscape(sa.Email)+"/keys?keyTypes=USER_MANAGED", nil, &keys); err != nil {
			return nil, err
		}
		for _, k := range keys.Keys {
			exp := parseTime(k.ValidBeforeTime)
			if exp != nil && exp.Year() >= 9999 {
				exp = nil // "never expires"
			}
			out = append(out, store.AppCredential{AppID: sa.Email, AppName: firstNonEmpty(sa.DisplayName, sa.Email), CredType: "service_account_key",
				ExternalID: k.Name, DisplayName: k.Name[strings.LastIndex(k.Name, "/")+1:], ExpiresAt: exp})
		}
	}
	return out, nil
}

func (p *gcpProvider) Rotate(ctx context.Context, c store.AppCredential) (credRotation, error) {
	if c.CredType != "service_account_key" {
		return credRotation{}, fmt.Errorf("Google Cloud cannot rotate a %s", c.CredType)
	}
	var res struct {
		Name            string `json:"name"`
		PrivateKeyData  string `json:"privateKeyData"`
		ValidBeforeTime string `json:"validBeforeTime"`
	}
	if err := p.call(ctx, "POST", iamAPI+"projects/-/serviceAccounts/"+url.PathEscape(c.AppID)+"/keys", map[string]any{}, &res); err != nil {
		return credRotation{}, err
	}
	data, err := base64.StdEncoding.DecodeString(res.PrivateKeyData)
	if err != nil {
		return credRotation{}, errors.New("Google returned an unreadable key")
	}
	exp := parseTime(res.ValidBeforeTime)
	if exp != nil && exp.Year() >= 9999 {
		exp = nil
	}
	return credRotation{ExternalID: res.Name, ExpiresAt: exp, JSON: string(data)}, nil
}

func (p *gcpProvider) Retire(ctx context.Context, c store.AppCredential, externalID string) error {
	if externalID == "" {
		return nil
	}
	return p.call(ctx, "DELETE", iamAPI+externalID, nil, nil)
}
