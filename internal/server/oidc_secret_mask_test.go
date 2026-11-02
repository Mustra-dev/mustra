package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The provider list must never return the client secret, only whether one
// is stored (review/coordinator finding: it was returned in clear to any
// settings.manage holder).
func TestListOIDCProvidersMasksClientSecret(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const secret = "super-secret-value-123"
	if _, err := st.UpsertOIDCProvider(ctx, store.OIDCProviderRow{
		ID: "idptest", Label: "Test", Kind: "generic", IssuerURL: "https://issuer.example.com",
		ClientID: "cid", ClientSecret: secret, RedirectURL: "https://c/cb", Enabled: false, CreatedBy: "t",
	}); err != nil {
		t.Fatal(err)
	}
	a := auth.New(ctx, st, nil, false, slog.Default())
	s := &Server{logger: slog.Default(), store: st, auth: a}
	rec := httptest.NewRecorder()
	s.handleListOIDCProviders(rec, httptest.NewRequest("GET", "/api/admin/oidc-providers", nil))
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("client secret leaked in the provider list: %s", body)
	}
	var resp struct {
		Providers []map[string]any `json:"providers"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range resp.Providers {
		if p["id"] == "idptest" {
			found = true
			if _, ok := p["client_secret"]; ok {
				t.Error("response still carries a client_secret field")
			}
			if p["client_secret_set"] != true {
				t.Errorf("client_secret_set = %v, want true", p["client_secret_set"])
			}
		}
	}
	if !found {
		t.Fatal("test provider not in the list")
	}
}
