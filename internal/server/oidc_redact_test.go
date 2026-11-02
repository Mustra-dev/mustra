package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

// The provider list is readable with settings.manage alone, so it must not
// carry the client secret; a scan found it returned in clear.
func TestOIDCProviderViewOmitsClientSecret(t *testing.T) {
	row := store.OIDCProviderRow{ID: "entra", Label: "Entra", IssuerURL: "https://login.example/v2.0",
		ClientID: "client-1", ClientSecret: "s3cr3t-value", RedirectURL: "https://console.example/auth/callback/entra"}
	b, err := json.Marshal(redactOIDCProvider(row))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "s3cr3t-value") {
		t.Fatalf("provider view leaks the client secret: %s", b)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["client_secret_set"] != true || got["client_id"] != "client-1" {
		t.Fatalf("view = %s, want client_secret_set true and the client id kept", b)
	}
	b, _ = json.Marshal(redactOIDCProvider(store.OIDCProviderRow{ID: "x"}))
	if !strings.Contains(string(b), `"client_secret_set":false`) {
		t.Fatalf("no secret stored should read as not set: %s", b)
	}
}
