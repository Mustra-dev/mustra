// Package servercmd is the control plane's command line: flags, environment
// and startup checks, shared by cmd/server (the deployed entrypoint) and
// cmd/console. The two used to carry separate copies, and the console's had
// drifted — no placeholder-secret check, no NATS credentials — so a
// deployment started through it ran with weaker defaults than one started
// through the server. One copy cannot drift.
package servercmd

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/server"
	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Main parses flags and the environment, refuses unsafe configuration,
// and runs the server until SIGINT/SIGTERM. name labels the exit message.
func Main(name string) {
	fs := flag.CommandLine
	var deprecated []string
	var (
		scriptToolsURL    = fs.String("script-tools-url", envOr("MUSTRA_SCRIPT_TOOLS_URL", "http://127.0.0.1:8091"), "isolated script analysis/completion service URL")
		natsURL           = fs.String("nats-url", envOr("MUSTRA_NATS_URL", "nats://127.0.0.1:4222"), "NATS server URL")
		natsCA            = fs.String("nats-ca", envOr("MUSTRA_NATS_CA", ""), "CA certificate that signed the NATS server certificate")
		natsUser          = fs.String("nats-user", envOr("MUSTRA_NATS_USER", ""), "NATS username for the server")
		natsPass          = fs.String("nats-password", envSecret("MUSTRA_NATS_PASSWORD"), "NATS password for the server (prefer MUSTRA_NATS_PASSWORD or MUSTRA_NATS_PASSWORD_FILE: flags are visible in ps)")
		natsSysPass       = fs.String("nats-sys-password", envSecret("MUSTRA_NATS_SYS_PASSWORD"), "password of the broker's system-account user mustra-sys, used to disconnect a revoked agent at once (prefer the environment)")
		agentNatsUser     = fs.String("agent-nats-user", envOr("MUSTRA_AGENT_NATS_USER", ""), "NATS username the install script gives agents")
		agentNatsPass     = fs.String("agent-nats-password", envSecret("MUSTRA_AGENT_NATS_PASSWORD"), "NATS password the install script gives agents (prefer the environment or a _FILE variable)")
		agentNatsURL      = fs.String("agent-nats-url", envOr("MUSTRA_AGENT_NATS_URL", ""), "LAN-reachable NATS URL the install scripts tell new agents to use (e.g. nats://10.0.0.5:4222)")
		agentBuilds       = fs.String("agent-builds-dir", envOr("MUSTRA_AGENT_BUILDS_DIR", ""), "directory of pre-built agent binaries served at /downloads/ (default: the container image's path)")
		allowPlaceholders = fs.Bool("allow-placeholder-secrets", envBoolOr("MUSTRA_ALLOW_PLACEHOLDER_SECRETS", false), "start even if a secret still has its example value (local development only)")
		postgresDS        = fs.String("postgres-dsn", envSecretOr("MUSTRA_POSTGRES_DSN", "postgres://mustra:mustra@127.0.0.1:5432/mustra?sslmode=disable"), "Postgres connection string")
		httpAddr          = fs.String("http-addr", envOr("MUSTRA_HTTP_ADDR", ":8080"), "HTTP listen address for the API/console")
		staleAfter        = fs.Duration("stale-after", envDurationOr("MUSTRA_STALE_AFTER", 30*time.Second), "time since last heartbeat before an agent is considered offline")
		offlineExpiry     = fs.Duration("offline-expiry", envDurationOr("MUSTRA_OFFLINE_EXPIRY", 1*time.Hour), "time an agent may stay offline before it's dropped from inventory entirely")
		logLevel          = fs.String("log-level", envOr("MUSTRA_LOG_LEVEL", "info"), "log level: debug, info, warn, error")

		cookieSecure = fs.Bool("cookie-secure", envBoolOr("MUSTRA_COOKIE_SECURE", true), "mark the session cookie Secure (disable only for plain-HTTP local dev)")
		sessionMax   = fs.Duration("session-max-age", envDurationOr("MUSTRA_SESSION_MAX_AGE", 0), "absolute lifetime of a console session (default 12h)")
		sessionIdle  = fs.Duration("session-idle-timeout", envDurationOr("MUSTRA_SESSION_IDLE_TIMEOUT", 0), "server-side idle timeout of a console session (default 1h)")

		oidcIssuer   = fs.String("oidc-issuer-url", envOr("MUSTRA_OIDC_ISSUER_URL", ""), "OIDC issuer URL (empty disables SSO)")
		oidcClient   = fs.String("oidc-client-id", envOr("MUSTRA_OIDC_CLIENT_ID", ""), "OIDC client ID")
		oidcSecret   = fs.String("oidc-client-secret", envSecret("MUSTRA_OIDC_CLIENT_SECRET"), "OIDC client secret")
		oidcRedirect = fs.String("oidc-redirect-url", envOr("MUSTRA_OIDC_REDIRECT_URL", ""), "OIDC redirect URL, e.g. https://mustra.example.com/auth/callback")
		oidcDomains  = fs.String("oidc-allowed-domains", envOr("MUSTRA_OIDC_ALLOWED_DOMAINS", ""), "comma-separated email domains allowed to sign in through SSO (verified email required)")
		oidcEmails   = fs.String("oidc-allowed-emails", envOr("MUSTRA_OIDC_ALLOWED_EMAILS", ""), "comma-separated email addresses allowed to sign in through SSO")
		oidcGroups   = fs.String("oidc-allowed-groups", envOr("MUSTRA_OIDC_ALLOWED_GROUPS", ""), "comma-separated IdP groups allowed to sign in through SSO")
		oidcGroupsCl = fs.String("oidc-groups-claim", envOr("MUSTRA_OIDC_GROUPS_CLAIM", "groups"), "ID-token claim carrying group membership")

		bgUser = fs.String("breakglass-username", envRenamed("MUSTRA_BREAKGLASS_USERNAME", "MUSTRA_BACKDOOR_USERNAME", &deprecated), "break-glass local administrator username")
		bgPass = fs.String("breakglass-password", envRenamedSecret("MUSTRA_BREAKGLASS_PASSWORD", "MUSTRA_BACKDOOR_PASSWORD", &deprecated), "break-glass local administrator password (prefer MUSTRA_BREAKGLASS_PASSWORD or _FILE)")
		// Deprecated spellings, kept so existing unit files keep working.
		oldUser = fs.String("backdoor-username", "", "deprecated: use --breakglass-username")
		oldPass = fs.String("backdoor-password", "", "deprecated: use --breakglass-password")

		scimToken = fs.String("scim-token", envSecret("MUSTRA_SCIM_TOKEN"), "bearer token SCIM clients must present (empty disables SCIM)")

		credKeyHex = fs.String("credential-encryption-key", envSecret("MUSTRA_CREDENTIAL_ENCRYPTION_KEY"), "hex-encoded 32-byte AES-256 key encrypting the deploy-page SSH credential vault (empty disables it)")
	)
	flag.Parse()

	// A LevelVar rather than a fixed level: slog reads it on every call, so
	// the admin UI can raise the level to debug and see the effect
	// immediately, without a restart that destroys whatever state was
	// being diagnosed.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: server.LogLevelVar()}))
	server.SetLogLevel(*logLevel)
	slog.SetDefault(logger)

	if *oldUser != "" {
		deprecated = append(deprecated, "--backdoor-username")
		if *bgUser == "" {
			*bgUser = *oldUser
		}
	}
	if *oldPass != "" {
		deprecated = append(deprecated, "--backdoor-password")
		if *bgPass == "" {
			*bgPass = *oldPass
		}
	}
	for _, d := range deprecated {
		logger.Warn("deprecated configuration name; rename it", "name", d,
			"use", strings.NewReplacer("BACKDOOR", "BREAKGLASS", "backdoor", "breakglass").Replace(d))
	}

	var credKey []byte
	if *credKeyHex != "" {
		k, err := hex.DecodeString(*credKeyHex)
		if err != nil {
			logger.Error("MUSTRA_CREDENTIAL_ENCRYPTION_KEY is not valid hex", "error", err)
			os.Exit(1)
		}
		credKey = k
	}

	cfg := server.Config{
		ScriptToolsURL:     *scriptToolsURL,
		NATSURL:            *natsURL,
		NATSCreds:          bnats.Creds{CAFile: *natsCA, User: *natsUser, Password: *natsPass},
		NATSSysCreds:       bnats.Creds{CAFile: *natsCA, User: "mustra-sys", Password: *natsSysPass},
		AgentNATSUser:      *agentNatsUser,
		AgentNATSPassword:  *agentNatsPass,
		AgentNATSURL:       *agentNatsURL,
		AgentBuildsDir:     *agentBuilds,
		PostgresDSN:        *postgresDS,
		HTTPAddr:           *httpAddr,
		StaleAfter:         *staleAfter,
		OfflineExpiry:      *offlineExpiry,
		CookieSecure:       *cookieSecure,
		SessionMaxAge:      *sessionMax,
		SessionIdleTimeout: *sessionIdle,
		OIDCAllowedDomains: auth.SplitList(*oidcDomains),
		OIDCAllowedEmails:  auth.SplitList(*oidcEmails),
		OIDCAllowedGroups:  auth.SplitList(*oidcGroups),
		OIDCGroupsClaim:    *oidcGroupsCl,
		OIDC: auth.OIDCConfig{
			IssuerURL:    *oidcIssuer,
			ClientID:     *oidcClient,
			ClientSecret: *oidcSecret,
			RedirectURL:  *oidcRedirect,
		},
		BreakGlassUsername:      *bgUser,
		BreakGlassPassword:      *bgPass,
		SCIMToken:               *scimToken,
		CredentialEncryptionKey: credKey,
		Logger:                  logger,
	}

	if err := server.CheckPlaceholderSecrets(cfg); err != nil {
		if !*allowPlaceholders {
			logger.Error(err.Error())
			os.Exit(1)
		}
		logger.Warn("starting with unsafe secrets because MUSTRA_ALLOW_PLACEHOLDER_SECRETS is set; never do this outside local development", "problem", err.Error())
	}
	if !*cookieSecure {
		logger.Warn("session cookies are not marked Secure (MUSTRA_COOKIE_SECURE=false); sign-in sessions can travel over plain HTTP. Use this only for local development on loopback")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, cfg); err != nil {
		logger.Error(name+" exited with error", "error", err)
		os.Exit(1)
	}
}

// envOr reads MUSTRA_<KEY> first and falls back to the pre-rename
// BEACON_<KEY>, so a deployment whose .env predates the rename keeps
// working untouched. Keys are passed in as "MUSTRA_...".
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if legacy, ok := strings.CutPrefix(key, "MUSTRA_"); ok {
		if v := os.Getenv("BEACON_" + legacy); v != "" {
			return v
		}
	}
	return def
}

// envSecretOr is envOr, plus <KEY>_FILE: a path whose contents are the
// value (Docker/Kubernetes secrets), so a secret need not sit in the
// environment or on the command line.
func envSecretOr(key, def string) string {
	if v := envOr(key, ""); v != "" {
		return v
	}
	if path := envOr(key+"_FILE", ""); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s_FILE: %v\n", key, err)
			os.Exit(1)
		}
		return strings.TrimRight(string(b), "\r\n")
	}
	return def
}

func envSecret(key string) string { return envSecretOr(key, "") }

// envRenamed reads the current name, falling back to the deprecated one
// (recording that it was used, for a warning once logging is up).
func envRenamed(key, old string, used *[]string) string {
	if v := envOr(key, ""); v != "" {
		return v
	}
	if v := envOr(old, ""); v != "" {
		*used = append(*used, old)
		return v
	}
	return ""
}

func envRenamedSecret(key, old string, used *[]string) string {
	if v := envSecret(key); v != "" {
		return v
	}
	if v := envSecret(old); v != "" {
		*used = append(*used, old)
		return v
	}
	return ""
}

func envDurationOr(key string, def time.Duration) time.Duration {
	v := envOr(key, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envBoolOr(key string, def bool) bool {
	v := envOr(key, "")
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes"
}
