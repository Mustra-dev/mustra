package server

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// The expected value comes from the Python reference that a real Guacamole
// 1.6 accepted (HMAC-SHA256, prepended, AES-128-CBC, zero IV, PKCS#7).
func TestGuacamoleSealMatchesReference(t *testing.T) {
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	got, err := guacamoleSeal(key, []byte(`{"username":"alex","expires":1,"connections":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "GJjvaQeFeIgYmIIT9zMazP/wmZ+3PRUKCxnmZobp78UaJJ+2ztWhA6DDzWtR2lQhxIk619BXMpcRsQp0izmxE0XGzYA54nCQEueyWuPpB8sLY39S4VHkfn7MWXmKdjH9"; got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}

func TestRemoteProtocolsAndAddress(t *testing.T) {
	win := store.AgentRecord{OS: "windows", IPs: []string{"fd81::1", "10.0.10.103"}}
	mac := store.AgentRecord{OS: "darwin", IPs: []string{"100.64.0.7", "10.0.10.143"}}
	ha := store.AgentRecord{OS: "linux", Platform: "haos", Hostname: "homeassistant"}
	if p := remoteProtocols(win); len(p) != 2 || p[0] != "rdp" || p[1] != "shadow" {
		t.Errorf("windows: %v", p)
	}
	if p := remoteProtocols(mac); len(p) != 2 || p[0] != "vnc" {
		t.Errorf("mac: %v", p)
	}
	if remoteProtocols(ha) != nil {
		t.Error("Home Assistant OS has nothing to connect to")
	}
	if a := remoteAddress(win); a != "10.0.10.103" {
		t.Errorf("windows address %s", a)
	}
	// A private LAN address beats the Tailscale CGNAT one.
	if a := remoteAddress(mac); a != "10.0.10.143" {
		t.Errorf("mac address %s", a)
	}
	if a := remoteAddress(ha); a != "homeassistant" {
		t.Errorf("fallback %s", a)
	}
	if got := fillRemoteTemplate("https://gw/x?h={ip}&p={protocol}:{port}&n={hostname}", store.AgentRecord{Hostname: "dc 01"}, "rdp", "10.0.0.5", "3389"); got != "https://gw/x?h=10.0.0.5&p=rdp:3389&n=dc+01" {
		t.Errorf("template %s", got)
	}
}

// Logging out is how a remote desktop ends with its Jump Gate window; a
// session Guacamole already dropped counts as ended, anything else retries.
func TestGuacamoleLogout(t *testing.T) {
	var gotPath, gotMethod string
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(status)
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL + "/guacamole")
	c := remoteConfig{GuacURL: srv.URL + "/guacamole", guacBaseURL: base}
	s := &Server{}
	if err := s.guacamoleLogout(context.Background(), c, "TOKEN/1"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/guacamole/api/tokens/TOKEN/1" {
		t.Fatalf("got %s %s", gotMethod, gotPath)
	}
	status = http.StatusNotFound
	if err := s.guacamoleLogout(context.Background(), c, "gone"); err != nil {
		t.Fatalf("an already-ended session must count as ended: %v", err)
	}
	status = http.StatusInternalServerError
	if err := s.guacamoleLogout(context.Background(), c, "x"); err == nil {
		t.Fatal("a failed logout must be reported so the sweep retries it")
	}
}
