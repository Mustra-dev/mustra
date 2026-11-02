package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The certificate a TLS service presents is read without trusting it, so a
// self-signed one (Proxmox's default) is reported rather than refused.
func TestPresentedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	cert := presentedCertificate(context.Background(), strings.TrimPrefix(srv.URL, "https://"), "example.com")
	if cert == nil {
		t.Fatal("no certificate read from a TLS server")
	}
	if want := srv.Certificate().Raw; string(cert.Raw) != string(want) {
		t.Error("read a different certificate than the server presents")
	}
	info := certInfo(cert, "tls://"+strings.TrimPrefix(srv.URL, "https://"))
	if info.Fingerprint == "" || !strings.HasPrefix(info.Path, "tls://127.0.0.1:") {
		t.Errorf("got %+v", info)
	}
	if presentedCertificate(context.Background(), "127.0.0.1:1", "x") != nil {
		t.Error("a closed port yields no certificate")
	}
}
