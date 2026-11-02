package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestDueAtAndMaterial(t *testing.T) {
	exp := time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC)
	c := store.AppCredential{ExpiresAt: &exp, RenewDays: 30}
	if d := dueAt(c); d == nil || !d.Equal(exp.AddDate(0, 0, -30)) {
		t.Errorf("due 30 days before expiry, got %v", d)
	}
	rot := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	c = store.AppCredential{RotateDays: 90, LastRotatedAt: &rot}
	if d := dueAt(c); d == nil || !d.Equal(rot.AddDate(0, 0, 90)) {
		t.Errorf("no expiry: due rotate_days after the last rotation, got %v", d)
	}
	if dueAt(store.AppCredential{}) != nil {
		t.Error("no expiry and no rotation period: never due")
	}
	if m := (credRotation{Secret: "s", CertPEM: "c"}).material(); m != "s" {
		t.Errorf("a secret is the material: %q", m)
	}
	if m := (credRotation{KeyPEM: "K", CertPEM: "C"}).material(); m != "K\nC\n" {
		t.Errorf("key then certificate: %q", m)
	}
	if rotatable(store.AppCredential{Kind: "manual", CredType: "certificate"}) || !rotatable(store.AppCredential{Kind: "okta", ConnectionID: "x", CredType: "client_secret"}) {
		t.Error("only imported credentials rotate")
	}
}

// fakeAPI answers by "METHOD path" and records what was sent.
type fakeAPI struct {
	routes map[string]string
	seen   []string
	bodies map[string]string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	f.seen = append(f.seen, key)
	if f.bodies == nil {
		f.bodies = map[string]string{}
	}
	data, _ := io.ReadAll(r.Body)
	f.bodies[key] = string(data)
	if out, ok := f.routes[key]; ok {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(out))
		return
	}
	w.WriteHeader(404)
	_, _ = w.Write([]byte(`{"error":{"message":"no route ` + key + `"}}`))
}

func TestEntraProvider(t *testing.T) {
	f := &fakeAPI{routes: map[string]string{
		"POST /tenant/oauth2/v2.0/token":              `{"access_token":"tok"}`,
		"GET /v1.0/applications":                      `{"value":[{"id":"app1","displayName":"Grafana","passwordCredentials":[{"keyId":"k1","displayName":"prod","endDateTime":"2027-01-01T00:00:00Z"}],"keyCredentials":[]}]}`,
		"GET /v1.0/servicePrincipals":                 `{"value":[{"id":"sp1","displayName":"Jira","preferredTokenSigningKeyThumbprint":"0A0B","keyCredentials":[{"keyId":"s1","usage":"Sign","customKeyIdentifier":"Cgs=","endDateTime":"2028-01-01T00:00:00Z"},{"keyId":"s0","usage":"Sign","customKeyIdentifier":"AAA=","endDateTime":"2026-01-01T00:00:00Z"}]}]}`,
		"POST /v1.0/applications/app1/addPassword":    `{"keyId":"k2","secretText":"NEW","endDateTime":"2027-06-01T00:00:00Z"}`,
		"POST /v1.0/applications/app1/removePassword": ``,
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	p := &entraProvider{tenant: "tenant", clientID: "id", secret: "sec", loginBase: srv.URL, graphBase: srv.URL + "/v1.0"}
	ctx := context.Background()
	found, err := p.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].CredType != "client_secret" || found[1].CredType != "saml_signing" || found[1].ExternalID != "s1" {
		t.Fatalf("want the secret and only the SAML key in use, got %+v", found)
	}
	rot, err := p.Rotate(ctx, found[0])
	if err != nil || rot.Secret != "NEW" || rot.ExternalID != "k2" || rot.ExpiresAt == nil {
		t.Fatalf("rotate: %+v %v", rot, err)
	}
	if err := p.Retire(ctx, found[0], "k1"); err != nil || !strings.Contains(f.bodies["POST /v1.0/applications/app1/removePassword"], `"k1"`) {
		t.Fatalf("retire should remove k1: %v %q", err, f.bodies["POST /v1.0/applications/app1/removePassword"])
	}
}

func TestOktaProvider(t *testing.T) {
	f := &fakeAPI{routes: map[string]string{
		"GET /api/v1/apps":                                                   `[{"id":"a1","label":"Portal","signOnMode":"OPENID_CONNECT"},{"id":"a2","label":"Wiki","signOnMode":"SAML_2_0","credentials":{"signing":{"kid":"kid1"}}}]`,
		"GET /api/v1/apps/a1/credentials/secrets":                            `[{"id":"sec1","status":"ACTIVE","created":"2026-01-02T00:00:00Z"},{"id":"sec0","status":"INACTIVE"}]`,
		"GET /api/v1/apps/a2/credentials/keys":                               `[{"kid":"kid1","expiresAt":"2027-03-01T00:00:00Z"},{"kid":"kid0","expiresAt":"2025-01-01T00:00:00Z"}]`,
		"POST /api/v1/apps/a1/credentials/secrets":                           `{"id":"sec2","client_secret":"S2"}`,
		"POST /api/v1/apps/a2/credentials/keys/generate":                     `{"kid":"kid2","expiresAt":"2028-03-01T00:00:00Z","x5c":["MIIB"]}`,
		"GET /api/v1/apps/a2":                                                `{"id":"a2","label":"Wiki","credentials":{"signing":{"kid":"kid1"}}}`,
		"PUT /api/v1/apps/a2":                                                `{}`,
		"POST /api/v1/apps/a1/credentials/secrets/sec1/lifecycle/deactivate": `{}`,
		"DELETE /api/v1/apps/a1/credentials/secrets/sec1":                    ``,
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	p := &oktaProvider{base: srv.URL, token: "t"}
	ctx := context.Background()
	found, err := p.Discover(ctx)
	if err != nil || len(found) != 2 || found[0].ExternalID != "sec1" || found[1].ExternalID != "kid1" {
		t.Fatalf("discover: %+v %v", found, err)
	}
	if rot, err := p.Rotate(ctx, found[0]); err != nil || rot.Secret != "S2" {
		t.Fatalf("rotate secret: %+v %v", rot, err)
	}
	if _, err := p.Rotate(ctx, found[1]); err != nil {
		t.Fatalf("rotate SAML: %v", err)
	}
	var app map[string]any
	_ = json.Unmarshal([]byte(f.bodies["PUT /api/v1/apps/a2"]), &app)
	if app["credentials"].(map[string]any)["signing"].(map[string]any)["kid"] != "kid2" {
		t.Errorf("the app should now sign with kid2: %s", f.bodies["PUT /api/v1/apps/a2"])
	}
	if err := p.Retire(ctx, found[0], "sec1"); err != nil {
		t.Fatalf("retire: %v", err)
	}
}

func TestAuthentikProvider(t *testing.T) {
	f := &fakeAPI{routes: map[string]string{
		"GET /api/v3/providers/oauth2/":                                `{"results":[{"pk":3,"name":"Grafana","client_type":"confidential"},{"pk":4,"name":"SPA","client_type":"public"}]}`,
		"GET /api/v3/providers/saml/":                                  `{"results":[{"pk":7,"name":"Wiki","signing_kp":"kp1"}]}`,
		"GET /api/v3/crypto/certificatekeypairs/kp1/":                  `{"name":"wiki","cert_expiry":"2027-02-01T00:00:00Z"}`,
		"PATCH /api/v3/providers/oauth2/3/":                            `{}`,
		"POST /api/v3/crypto/certificatekeypairs/generate/":            `{"pk":"kp2"}`,
		"GET /api/v3/crypto/certificatekeypairs/kp2/view_certificate/": `{"data":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"}`,
		"PATCH /api/v3/providers/saml/7/":                              `{}`,
		"DELETE /api/v3/crypto/certificatekeypairs/kp1/":               ``,
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	p := &authentikProvider{base: srv.URL, token: "t"}
	ctx := context.Background()
	found, err := p.Discover(ctx)
	if err != nil || len(found) != 2 || found[0].AppID != "3" || found[1].ExternalID != "kp1" || found[1].ExpiresAt == nil {
		t.Fatalf("discover (confidential client and the SAML key pair only): %+v %v", found, err)
	}
	rot, err := p.Rotate(ctx, found[0])
	if err != nil || len(rot.Secret) != 96 || !strings.Contains(f.bodies["PATCH /api/v3/providers/oauth2/3/"], rot.Secret) {
		t.Fatalf("rotate secret: %v", err)
	}
	if rot, err := p.Rotate(ctx, found[1]); err != nil || rot.ExternalID != "kp2" || !strings.Contains(rot.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("rotate SAML: %+v %v", rot, err)
	}
	// kp1 is still listed as in use by the fake, so it must be kept.
	if err := p.Retire(ctx, found[1], "kp1"); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.seen {
		if s == "DELETE /api/v3/crypto/certificatekeypairs/kp1/" {
			t.Error("a key pair still in use must not be deleted")
		}
	}
}
