package server

// Secrets at rest: the directory bind password, the SCIM bearer token and
// SSO client secrets were stored as plain text in Postgres, where every
// database backup carried them. They are now sealed with the credential
// vault, bound to their record, like the Fleet and Cloudflare tokens.
//
// A stored value without a "vault:" or "plain:" prefix is a legacy plain
// value: it is still read as-is, and sealed once at startup.

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
)

// oidcSecretAAD binds a provider's sealed client secret to that provider.
func oidcSecretAAD(id string) string { return "oidc_provider/client_secret/" + id }

// sealWith seals value for storage, or marks it plain when there is no vault.
func sealWith(v *vault.Vault, aad, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if v == nil {
		return "plain:" + value, nil
	}
	ct, err := v.Seal(value, aad)
	if err != nil {
		return "", err
	}
	return "vault:" + base64.StdEncoding.EncodeToString(ct), nil
}

// openWith reads a stored secret: sealed, marked plain, or legacy plain.
func openWith(v *vault.Vault, aad, stored string) (string, error) {
	switch {
	case stored == "":
		return "", nil
	case strings.HasPrefix(stored, "plain:"):
		return strings.TrimPrefix(stored, "plain:"), nil
	case strings.HasPrefix(stored, "vault:"):
		if v == nil {
			return "", errors.New("this secret is encrypted but no credential encryption key is configured (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)")
		}
		ct, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, "vault:"))
		if err != nil {
			return "", err
		}
		plain, _, err := v.Open(ct, aad)
		return plain, err
	}
	return stored, nil // legacy: stored before secrets were sealed
}

// sealedAlready says whether a stored value needs the one-time sealing.
func sealedAlready(stored string) bool {
	return stored == "" || strings.HasPrefix(stored, "vault:") || strings.HasPrefix(stored, "plain:")
}

// secretSettings are settings holding a secret that older releases stored
// as plain text.
var secretSettings = []string{settingDirectoryBindPassword, settingSCIMToken, settingOIDCClientSecret}

// sealSecretsAtRest seals legacy plain secrets once. Without a vault there
// is nothing to seal with, and they stay as they are.
func sealSecretsAtRest(ctx context.Context, st *store.Store, v *vault.Vault, settings map[string]string) (int, error) {
	if v == nil {
		return 0, nil
	}
	n := 0
	for _, key := range secretSettings {
		stored := settings[key]
		if sealedAlready(stored) {
			continue
		}
		sealed, err := sealWith(v, vault.SettingAAD(key), stored)
		if err != nil {
			return n, err
		}
		if err := st.SetSetting(ctx, key, sealed, "mustra"); err != nil {
			return n, err
		}
		settings[key] = sealed
		n++
	}
	rows, err := st.ListOIDCProviders(ctx)
	if err != nil {
		return n, err
	}
	for _, r := range rows {
		if sealedAlready(r.ClientSecret) {
			continue
		}
		sealed, err := sealWith(v, oidcSecretAAD(r.ID), r.ClientSecret)
		if err != nil {
			return n, err
		}
		if err := st.SetOIDCProviderSecret(ctx, r.ID, sealed); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
