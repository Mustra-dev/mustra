package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Setting keys stored in Postgres (see schema.sql's settings table). Only
// this fixed set of runtime-editable knobs is exposed through the admin
// Settings tab — everything else (NATS/Postgres URLs, HTTP listen address,
// cookie security, the credential vault's encryption key) stays env-only:
// either structural (needs a restart to matter anyway) or unsafe to rotate
// without a migration (the encryption key would orphan every stored
// credential).
const (
	settingOIDCIssuerURL        = "oidc.issuer_url"
	settingOIDCClientID         = "oidc.client_id"
	settingOIDCClientSecret     = "oidc.client_secret"
	settingOIDCRedirectURL      = "oidc.redirect_url"
	settingBackdoorUsername     = "backdoor.username"
	settingBackdoorPasswordHash = "backdoor.password_hash"
	settingSCIMToken            = "scim.token"
	settingStaleAfterSeconds    = "agent.stale_after_seconds"
	settingOfflineExpirySeconds = "agent.offline_expiry_seconds"
	settingAgentNATSURL         = "agent.nats_url"
	settingBrandingLogoDataURL  = "branding.logo_data_url"
	// settingUninstallPasswordHash gates the uninstaller that ships with
	// every endpoint. Only the bcrypt hash is ever stored or sent: the
	// endpoints need to check a password offline, and a plaintext one
	// distributed to every managed machine would be a password nobody could
	// ever change safely.
	settingUninstallPasswordHash = "agent.uninstall_password_hash"
	// settingMacMDMEnrollURL is an MDM's enrollment page, offered to the
	// person at a Mac that lacks Full Disk Access and is not enrolled. Empty
	// means off. Apple honours a Full Disk Access grant only from an MDM the
	// Mac is enrolled in, so enrolling is the one step that makes the grant
	// automatic; the agent cannot enroll the Mac itself, only open the page.
	settingMacMDMEnrollURL = "agent.macos_mdm_enroll_url"
	// settingAgentConsoleURL is the console's public base URL as an endpoint
	// can reach it. There is no reliable way for the server to know this on
	// its own -- behind a tunnel or reverse proxy the address it binds is not
	// the address anyone uses -- so it is captured from a real browser
	// request the first time someone views an install script, which they must
	// have done for any agent to exist at all.
	settingAgentConsoleURL = "agent.console_url"
	settingUpdateRepo      = "update.repo"
	settingUpdateToken     = "update.token"
	// settingStreamRetentionHours is how long the JetStream buffer between
	// the agents and this server keeps messages every consumer has already
	// read — i.e. how long the control plane may be down before published
	// work is lost. See internal/nats/jetstream.go for why the default is
	// four hours rather than a day.
	settingStreamRetentionHours = "stream.retention_hours"
	// settingVaultLegacySealedOff records that every stored vault value has
	// been re-sealed bound to its record, after which unbound (v1)
	// ciphertexts are refused.
	settingVaultLegacySealedOff = "vault.legacy_sealed_off"
)

// liveConfig holds the subset of Config that's editable at runtime via the
// admin Settings API, guarded by a mutex since it's read from HTTP handlers
// and background loops concurrently with being written from a settings
// update. OIDC config lives inside auth.Auth itself (it already needed its
// own mutex to hot-swap the discovered provider) and the SCIM token inside
// scim.Server — this struct only holds the knobs that don't already have a
// natural owner.
type liveConfig struct {
	mu               sync.RWMutex
	staleAfter       time.Duration
	offlineExpiry    time.Duration
	agentNATSURL     string
	backdoorUsername string

	// The admin-uploaded console logo, held as the data URL it was
	// uploaded as. logoVersion changes on every edit so the browser's
	// cached copy of /branding/logo is bypassed the moment it's replaced
	// (the <img> src carries it as ?v=) — the same trick as the hashed
	// static asset URLs.
	logoDataURL string
	logoVersion uint64
}

func (l *liveConfig) snapshot() (staleAfter, offlineExpiry time.Duration, agentNATSURL, backdoorUsername string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.staleAfter, l.offlineExpiry, l.agentNATSURL, l.backdoorUsername
}

func (l *liveConfig) setAgent(staleAfter, offlineExpiry time.Duration, agentNATSURL string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.staleAfter = staleAfter
	l.offlineExpiry = offlineExpiry
	l.agentNATSURL = agentNATSURL
}

func (l *liveConfig) setBackdoorUsername(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.backdoorUsername = username
}

func (l *liveConfig) setLogo(dataURL string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logoDataURL = dataURL
	l.logoVersion++
}

func (l *liveConfig) logo() (dataURL string, version uint64) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.logoDataURL, l.logoVersion
}

func (s *Server) staleAfter() time.Duration {
	v, _, _, _ := s.live.snapshot()
	return v
}

func (s *Server) offlineExpiry() time.Duration {
	_, v, _, _ := s.live.snapshot()
	return v
}

// assetPurgeAfterSetting is how long a retired endpoint is kept before it
// is deleted outright. Empty or "0" means never, which is the default:
// keeping the record of a machine that is gone costs a row, and losing it
// costs the only answer to "what was on that box".
const assetPurgeAfterSetting = "assets.purge_after_days"

func (s *Server) purgeAfter() time.Duration {
	days, _ := s.purgeAfterDays(context.Background())
	return time.Duration(days) * 24 * time.Hour
}

// purgeAfterDays is the setting as a number of days, 0 for never: unset,
// "0" and a value that is not a positive number all mean never. An error
// is the store's: the setting could not be read.
func (s *Server) purgeAfterDays(ctx context.Context) (int, error) {
	v, err := s.store.GetSetting(ctx, assetPurgeAfterSetting)
	if err != nil {
		return 0, err
	}
	days, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || days <= 0 {
		return 0, nil
	}
	return days, nil
}

func (s *Server) agentNATSURL() string {
	_, _, v, _ := s.live.snapshot()
	return v
}

// streamRetention reads the configured buffer window. It goes to the store
// rather than a cached copy because it is read only when the settings page
// is rendered — the value that matters at runtime is the one already
// applied to the stream itself, and NATS is the authority on that.
func (s *Server) streamRetention(ctx context.Context) time.Duration {
	v, err := s.store.GetSetting(ctx, settingStreamRetentionHours)
	if err != nil || v == "" {
		return bnats.DefaultStreamRetention
	}
	hours, err := strconv.Atoi(v)
	if err != nil || hours <= 0 {
		return bnats.DefaultStreamRetention
	}
	return time.Duration(hours) * time.Hour
}

func (s *Server) backdoorUsername() string {
	_, _, _, v := s.live.snapshot()
	return v
}

// seedAndLoadSettings seeds the settings table from cfg (the env/flag-
// derived starting values) on a from-scratch deploy — SetSettingIfAbsent
// never overwrites a value already present, so this is a no-op after the
// very first boot — then returns the authoritative current values from
// Postgres, which win from then on. This is what lets the admin Settings
// page show real current values immediately even before anyone's ever
// opened it, while still making Postgres the source of truth once someone
// edits something.
func seedAndLoadSettings(ctx context.Context, st *store.Store, cfg Config) (map[string]string, error) {
	seed := map[string]string{
		settingOIDCIssuerURL:        cfg.OIDC.IssuerURL,
		settingOIDCClientID:         cfg.OIDC.ClientID,
		settingOIDCClientSecret:     cfg.OIDC.ClientSecret,
		settingOIDCRedirectURL:      cfg.OIDC.RedirectURL,
		settingBackdoorUsername:     cfg.BreakGlassUsername,
		settingSCIMToken:            cfg.SCIMToken,
		settingStaleAfterSeconds:    strconv.Itoa(int(cfg.StaleAfter.Seconds())),
		settingOfflineExpirySeconds: strconv.Itoa(int(cfg.OfflineExpiry.Seconds())),
		settingAgentNATSURL:         cfg.AgentNATSURL,
	}
	if cfg.BreakGlassPassword != "" {
		hash, err := auth.HashPassword(cfg.BreakGlassPassword)
		if err != nil {
			return nil, fmt.Errorf("hash initial backdoor password: %w", err)
		}
		seed[settingBackdoorPasswordHash] = hash
	}
	for k, v := range seed {
		if v == "" {
			continue // don't seed empty placeholders; GetAllSettings' zero-value default already means "unset"
		}
		if err := st.SetSettingIfAbsent(ctx, k, v, "startup-seed"); err != nil {
			return nil, err
		}
	}
	return st.GetAllSettings(ctx)
}

func durationFromSettingHours(settings map[string]string, key string, def time.Duration) time.Duration {
	v, ok := settings[key]
	if !ok || v == "" {
		return def
	}
	hours, err := strconv.Atoi(v)
	if err != nil || hours <= 0 {
		return def
	}
	return time.Duration(hours) * time.Hour
}

func durationFromSettingSeconds(settings map[string]string, key string, def time.Duration) time.Duration {
	v, ok := settings[key]
	if !ok || v == "" {
		return def
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return def
	}
	return time.Duration(secs) * time.Second
}
