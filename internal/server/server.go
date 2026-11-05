// Package server implements the mustra control plane: it consumes agent
// registrations, heartbeats, and facts off NATS, persists current state to
// Postgres, dispatches live queries to the fleet and collects results, and
// exposes an HTTP+SSE API for the console.
//
// cmd/server and cmd/console both call Run — for Slice 1 the console is
// merged into the same process as the API server (see docs/ROADMAP.md for
// the planned split once the console needs an independent scaling profile).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	gonats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/debsec"
	"github.com/mustra-dev/mustra/internal/server/scim"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

// Config controls server behavior.
type Config struct {
	NATSURL     string
	PostgresDSN string
	// NATSCreds authenticate the server to the control plane. The server
	// holds a different credential from the agents, with the privilege to
	// publish commands — which agents deliberately lack, because that
	// privilege is what turns access to the bus into root on the fleet.
	NATSCreds bnats.Creds
	// NATSSysCreds reach the broker's system account, the one that may
	// disconnect a client: how a revoked agent credential is cut off at
	// once rather than when its JWT expires. Empty password: revocation
	// waits for the expiry, as before.
	NATSSysCreds bnats.Creds
	// AgentNATSCreds are what the install script hands to a new endpoint.
	// Served over the console's HTTPS, never over the bus itself.
	AgentNATSUser     string
	AgentNATSPassword string
	// AgentBuildsDir holds the pre-built agent binaries served at
	// /downloads/. The container image populates it; a developer running
	// `go run ./cmd/server` points it at wherever `make agents` wrote to.
	// Empty means the container's path.
	AgentBuildsDir string
	HTTPAddr       string
	// ScriptToolsURL points to the isolated analysis and completion service.
	ScriptToolsURL string
	// StaleAfter is how long since the last heartbeat before an agent is
	// considered offline. Should be a small multiple of the agent's
	// heartbeat interval to tolerate a couple of missed beats without
	// flapping.
	StaleAfter time.Duration
	// OfflineExpiry is how long an agent may stay offline (no heartbeat)
	// before it's deleted from inventory entirely, not just marked
	// offline. Defaults to 1 hour.
	OfflineExpiry time.Duration

	// OIDC configures SSO against an external IdP (Authentik or any other
	// standards-compliant provider). Leave zero-valued to disable SSO —
	// the local backdoor account still works.
	OIDC auth.OIDCConfig
	// CookieSecure marks the session cookie Secure (HTTPS-only). Should be
	// true whenever the console is reached over HTTPS — which, behind a
	// Cloudflare Tunnel, it always is from the browser's point of view even
	// though the tunnel-to-container hop is plain HTTP.
	CookieSecure bool

	// SessionMaxAge and SessionIdleTimeout bound every console session on
	// the server, whatever the browser does. Zero means the auth package's
	// defaults (7 days absolute, 12 hours idle).
	SessionMaxAge      time.Duration
	SessionIdleTimeout time.Duration

	// OIDCAllowed* are SSO allowlist rules from the environment, added to
	// the ones kept in Settings. With none in either place every SSO
	// sign-in is refused.
	OIDCAllowedDomains []string
	OIDCAllowedEmails  []string
	OIDCAllowedGroups  []string
	OIDCGroupsClaim    string

	// BreakGlassUsername/BreakGlassPassword define the break-glass local
	// administrator, re-synced to Postgres on every startup so it always
	// matches current configuration (MUSTRA_BREAKGLASS_*; the old
	// MUSTRA_BACKDOOR_* names still work, with a warning). The server logs
	// a warning and the account is unusable if either is empty.
	BreakGlassUsername string
	BreakGlassPassword string

	// SCIMToken is the static bearer token an IdP's SCIM provider must
	// present at /scim/v2/*. Empty disables SCIM (every request 401s).
	SCIMToken string

	// AgentNATSURL is the LAN-reachable NATS address the install
	// scripts/deploy page tell new agents to connect to — distinct from
	// NATSURL, which is what the server itself uses (the in-compose-network
	// address, not reachable from outside the stack).
	AgentNATSURL string

	// CredentialEncryptionKey is the 32-byte AES-256 key (raw bytes, not
	// hex) encrypting the SSH credential vault at rest. Required for the
	// deploy page's network-scan-and-push flow; that flow is disabled
	// without it.
	CredentialEncryptionKey []byte

	Logger *slog.Logger
}

// Server is one running instance of the mustra control plane.
type Server struct {
	integ integrationBus // event streaming to integrations (integrations.go)
	// tunnels: open Guacamole tunnels per remote session (remote_jit.go).
	tunnels remoteTunnels
	// trustKick wakes the trusted-roots push (trust_roots.go) after a change.
	trustKick chan struct{}
	// entraOverride replaces the Graph client in tests (entra.go).
	entraOverride func(tenant, client, secret string) *graphClient
	// updateSent: agent ID → when it was last asked to update (agent_update_api.go).
	updateSent sync.Map
	// revealWatches holds the rules with a finished-scan announcement pending.
	revealWatches sync.Map
	// vulnKick asks vulnScanLoop for a scan soon; remediated holds the
	// agents a patch or software run just changed (vulnscan_after.go).
	vulnKick   chan struct{}
	remediated sync.Map
	// telemetry holds endpoint metrics on their way to Prometheus
	// (telemetry.go).
	telemetry *telemetryHub
	// osLifecycle holds OS release support dates (oslifecycle.go).
	osLifecycle *osLifecycleCache
	cfg         Config
	logger      *slog.Logger
	store       *store.Store
	nc          *gonats.Conn
	js          jetstream.JetStream
	agentHub    *hub
	queryMgr    *queryManager
	auth        *auth.Auth
	scim        *scim.Server
	vault       *vault.Vault // nil if CredentialEncryptionKey wasn't configured — deploy-push routes 503 in that case
	httpSrv     *http.Server
	live        *liveConfig // the subset of Config editable at runtime via the admin Settings API
	impact      impactCache // the last lateral-movement analysis; see impact_api.go
	windows     windowGate  // maintenance-window membership cache; see maintenance_api.go
	sigs        signalCache // compiled Signals; see signals.go
	// agentHubKick requests a coalesced agent-list broadcast; see
	// refreshAgentHub. nil outside Run.
	agentHubKick chan struct{}
	// resultsNC carries live-query answers only (see Run); nil means nc.
	resultsNC *gonats.Conn
	// Software Inventory & Usage view cache, by window; see swinventory_api.go.
	swinvMu       sync.Mutex
	swinvCache    map[int]*swInventory
	swinvRolledAt time.Time
	// Compiled integrity labels; see integrity_monitor.go.
	labelsMu sync.Mutex
	labels   []compiledLabel
	labelsAt time.Time
	// Effective watch sets by agent, for baselining new roots in the diff.
	watchRootsMu sync.Mutex
	watchRoots   map[string]*effectiveWatch
	watchRootsAt time.Time
	// Group membership and action groups, for management rights and the
	// per-module ceiling; see access.go.
	access accessCache
	// routeLog is the protected route table as registered, for the route
	// audit test; see routetable.go.
	routeLog *routeTable
	// openAPI and openAPIYAML are /api/openapi.json and /api/openapi.yaml;
	// see openAPIDocument.
	openAPIOnce sync.Once
	openAPI     []byte
	openAPIYAML []byte
	// gatedRoutes are the endpoint-action routes, by pattern; see
	// action_authz.go. Approvals replay through them.
	gatedRoutes map[string]*actionGate
	// setupToken is the one-time first-run token (a string); see setup.go.
	setupToken atomic.Value
	// One run at a time per policy and per playbook — a schedule and a
	// person can otherwise start the same one twice, concurrently. See
	// inflight.go.
	runs *inflight
	// debsec holds Debian's own verdict on each (package, CVE, release),
	// which is what separates a live finding from a CVE the distribution
	// already backported a fix for. Refreshed daily in the background.
	debsec *debsec.Index
	// syslog streams audit events to a collector as they happen — distinct
	// from a Connect export, which is a scheduled batch. A SIEM wants the
	// live tap; an alert that arrives an hour later in a CSV is not an
	// alert.
	syslog *syslogSink
	// dlTokens gates package-file downloads. The agent authenticates to
	// NATS, not HTTP, so it cannot present a session to fetch a payload —
	// the token is minted per dispatch and sent over the command channel.
	dlTokens *downloadTokens
	// startedAt backs the About page's uptime — the process start, not the
	// container's, so a crash-restart is visible.
	startedAt time.Time
	// trust is agent identity, enrollment and update signing; see
	// natsauth_config.go.
	trust *agentTrust
}

// warnGate rate-limits a repeated log line: mark records now, active
// reports whether it was marked within the window. Zero value is ready.
type warnGate struct {
	mu sync.Mutex
	at time.Time
}

func (g *warnGate) active(window time.Duration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.at.IsZero() && time.Since(g.at) < window
}

func (g *warnGate) mark() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.at = time.Now()
}

// Run wires up and runs the full control plane, blocking until ctx is
// cancelled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = 30 * time.Second
	}
	if cfg.OfflineExpiry <= 0 {
		cfg.OfflineExpiry = 1 * time.Hour
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":8080"
	}
	logger := cfg.Logger
	logger.Info("mustra server starting", "build", version.Current().String())

	st, err := store.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("open postgres store: %w", err)
	}
	defer st.Close()

	// With the broker's auth callout in use, the server's replies inbox
	// moves out of the shared _INBOX namespace (see bnats.ServerInboxPrefix).
	if trustEnv("MUSTRA_NATS_CALLOUT_SEED") != "" {
		cfg.NATSCreds.InboxPrefix = bnats.ServerInboxPrefix
	}
	nc, err := bnats.ConnectWithCreds(cfg.NATSURL, "server", cfg.NATSCreds, logger)
	if err != nil {
		return fmt.Errorf("connect to nats: %w", err)
	}
	defer nc.Close()

	// Live-query answers get a connection of their own. Every endpoint
	// answers a fleet-wide query within the same second, and the broker
	// disconnects a client whose unread data passes its max_pending (64 MB):
	// 5,000 endpoints answering a processes query (~28 KB each) did exactly
	// that to the one connection everything shared, dropping 92% of the
	// answers and, for three seconds, every auth callout, registration and
	// command reply with them. On their own connection a burst can cost at
	// most the query it belongs to.
	resultsNC, err := bnats.ConnectWithCreds(cfg.NATSURL, "server-results", cfg.NATSCreds, logger)
	if err != nil {
		return fmt.Errorf("connect to nats (query results): %w", err)
	}
	defer resultsNC.Close()

	js, err := bnats.JetStream(nc)
	if err != nil {
		return fmt.Errorf("init jetstream: %w", err)
	}

	// Settings seeded from env/flags on a from-scratch deploy, Postgres
	// authoritative from then on — see settings.go. This is what backs the
	// admin Settings tab's SSO/backdoor/SCIM/staleness config: editable at
	// runtime, no restart, and correct on the very first boot too.
	settings, err := seedAndLoadSettings(ctx, st, cfg)
	if err != nil {
		return fmt.Errorf("load settings: %w", err)
	}

	// After settings, because the buffer's retention is one of them. On a
	// first boot the seed has already run, so this is the configured value
	// rather than the default even on the very first pass.
	streamRetention := durationFromSettingHours(settings, settingStreamRetentionHours, bnats.DefaultStreamRetention)
	if _, err := bnats.EnsureAgentStream(ctx, nc, streamRetention); err != nil {
		return fmt.Errorf("ensure agent stream: %w", err)
	}
	logger.Info("agent stream ready", "retention", streamRetention)
	if err := st.SeedBuiltinRoles(ctx, auth.AllPermissions); err != nil {
		return fmt.Errorf("seed builtin roles: %w", err)
	}
	if ran, err := st.GrandfatherAllUsersAdminOnce(ctx); err != nil {
		return fmt.Errorf("grandfather existing users: %w", err)
	} else if ran {
		logger.Info("RBAC introduced: existing users granted admin (matching their prior unrestricted access) — adjust via the Admin tab")
	}

	backdoorUsername := settings[settingBackdoorUsername]
	backdoorHash := settings[settingBackdoorPasswordHash]
	if backdoorUsername == "" || backdoorHash == "" {
		logger.Warn("no break-glass account configured (set MUSTRA_BREAKGLASS_USERNAME/PASSWORD, or complete first-run setup) — if SSO is ever unreachable, nobody can log in")
	} else {
		if _, err := st.UpsertLocalAdmin(ctx, backdoorUsername, backdoorHash); err != nil {
			return fmt.Errorf("sync backdoor account: %w", err)
		}
		logger.Info("break-glass account synced", "username", backdoorUsername)
	}
	if settings[settingSCIMToken] == "" {
		logger.Warn("no SCIM token configured (MUSTRA_SCIM_TOKEN, or the admin Settings tab) — SCIM provisioning is disabled")
	}

	var v *vault.Vault
	if len(cfg.CredentialEncryptionKey) == 0 {
		logger.Warn("no credential encryption key configured (MUSTRA_CREDENTIAL_ENCRYPTION_KEY) — the deploy page's credential vault and SSH push are disabled")
	} else {
		v, err = vault.New(st, cfg.CredentialEncryptionKey)
		if err != nil {
			return fmt.Errorf("init credential vault: %w", err)
		}
		// Values encrypted before they were bound to their record are
		// re-sealed once; afterwards this finds nothing to do. Once a run
		// completes cleanly, unbound (version-1) ciphertexts are refused
		// for good: a value cannot be downgraded and relocated between
		// records. The decision is sticky in a setting, so a later start
		// enforces it even though it then finds nothing to migrate.
		alreadySealedOff, _ := st.GetSetting(ctx, settingVaultLegacySealedOff)
		migrated, failed, merr := v.MigrateLegacy(ctx)
		if merr != nil {
			logger.Warn("re-sealing stored vault values failed; they still decrypt and will be retried at the next start", "error", merr)
		} else {
			if migrated > 0 || failed > 0 {
				logger.Info("re-sealed stored vault values bound to their records", "migrated", migrated, "undecryptable", failed)
			}
			if alreadySealedOff != "true" {
				if err := st.SetSetting(ctx, settingVaultLegacySealedOff, "true", "system"); err != nil {
					logger.Warn("could not record that vault re-sealing completed", "error", err)
				}
			}
		}
		if alreadySealedOff == "true" || merr == nil {
			v.RefuseLegacy(true)
		}
	}
	if n, err := sealSecretsAtRest(ctx, st, v, settings); err != nil {
		logger.Warn("sealing stored secrets failed; they are still read as they are and will be retried at the next start", "error", err)
	} else if n > 0 {
		logger.Info("sealed secrets that were stored as plain text", "count", n)
	}
	scimToken, err := openWith(v, vault.SettingAAD(settingSCIMToken), settings[settingSCIMToken])
	if err != nil {
		logger.Warn("the stored SCIM token could not be decrypted — SCIM provisioning is disabled until it is set again", "error", err)
		scimToken = ""
	}

	s := &Server{
		cfg:       cfg,
		logger:    logger,
		store:     st,
		nc:        nc,
		js:        js,
		agentHub:  newHub(),
		queryMgr:  newQueryManager(nc, logger),
		auth:      auth.New(ctx, st, nil, cfg.CookieSecure, logger),
		vault:     v,
		scim:      scim.New(st, scimToken, logger),
		live:      &liveConfig{},
		runs:      newInflight(),
		debsec:    debsec.NewIndex(),
		syslog:    &syslogSink{},
		startedAt: time.Now(),
		dlTokens:  newDownloadTokens(),
		// Buffered by one: a pending request is all the loop needs to know.
		agentHubKick: make(chan struct{}, 1),
		vulnKick:     make(chan struct{}, 1),
		telemetry:    newTelemetryHub(),
		osLifecycle:  newOSLifecycleCache(),
		resultsNC:    resultsNC,
	}
	// Audit forwarding reaches an internal collector only if an
	// administrator allowlisted it (see guardedDial).
	s.syslog.dial = func(network, addr string) (net.Conn, error) {
		ctx := context.Background()
		return guardedDial(ctx, network, addr, s.webhookAllowedHosts(ctx), 5*time.Second)
	}
	s.live.setAgent(
		durationFromSettingSeconds(settings, settingStaleAfterSeconds, cfg.StaleAfter),
		durationFromSettingSeconds(settings, settingOfflineExpirySeconds, cfg.OfflineExpiry),
		settings[settingAgentNATSURL],
	)
	s.auth.SetSessionLimits(cfg.SessionMaxAge, cfg.SessionIdleTimeout)
	s.wireMFA()
	s.auth.SetOIDCPolicySource(s.oidcPolicy)
	s.live.setBackdoorUsername(backdoorUsername)
	s.live.setLogo(settings[settingBrandingLogoDataURL])

	// SSO providers live in their own table now; a deployment that predates
	// that is migrated across on this first boot, then loaded like any
	// other (which is what kicks off discovery for each).
	if err := s.migrateLegacyOIDCConfig(ctx, settings); err != nil {
		return fmt.Errorf("migrate legacy OIDC config: %w", err)
	}
	if err := s.loadOIDCProviders(ctx); err != nil {
		return fmt.Errorf("load OIDC providers: %w", err)
	}

	go s.sessionPruneLoop(ctx)

	// Agent identity, enrollment and update signing; see natsauth_config.go.
	stopTrust, err := s.startAgentTrust(ctx)
	if err != nil {
		return fmt.Errorf("agent trust: %w", err)
	}
	defer stopTrust()

	regSub, err := s.subscribeRegister(ctx)
	if err != nil {
		return fmt.Errorf("subscribe register: %w", err)
	}
	defer regSub.Unsubscribe()

	patchListSub, err := s.subscribePatchListQueries(ctx)
	if err != nil {
		return fmt.Errorf("subscribe patch list queries: %w", err)
	}
	defer patchListSub.Unsubscribe()

	selfServiceSub, err := s.subscribeSelfService(ctx)
	if err != nil {
		return fmt.Errorf("subscribe self service: %w", err)
	}
	defer selfServiceSub.Unsubscribe()

	customSensorSub, err := s.subscribeCustomSensorQueries(ctx)
	if err != nil {
		return fmt.Errorf("subscribe custom sensor queries: %w", err)
	}
	defer customSensorSub.Unsubscribe()

	hbConsume, err := s.consumeHeartbeats(ctx)
	if err != nil {
		return fmt.Errorf("start heartbeat consumer: %w", err)
	}
	defer hbConsume.Stop()

	factsConsume, err := s.consumeFacts(ctx)
	if err != nil {
		return fmt.Errorf("start facts consumer: %w", err)
	}
	defer factsConsume.Stop()

	sensorsConsume, err := s.consumeSensors(ctx)
	if err != nil {
		return fmt.Errorf("start sensors consumer: %w", err)
	}
	defer sensorsConsume.Stop()

	actionResultsConsume, err := s.consumeActionResults(ctx)
	if err != nil {
		return fmt.Errorf("start action results consumer: %w", err)
	}
	defer actionResultsConsume.Stop()

	fileEventsConsume, err := s.consumeFileEvents(ctx)
	if err != nil {
		return fmt.Errorf("start file events consumer: %w", err)
	}
	defer fileEventsConsume.Stop()

	procEventsConsume, err := s.consumeProcessEvents(ctx)
	if err != nil {
		return fmt.Errorf("start process events consumer: %w", err)
	}
	defer procEventsConsume.Stop()

	recEventsConsume, err := s.consumeRecorderEvents(ctx)
	if err != nil {
		return fmt.Errorf("start recorder events consumer: %w", err)
	}
	defer recEventsConsume.Stop()

	resultSub, err := s.subscribeResults(ctx)
	if err != nil {
		return fmt.Errorf("subscribe results: %w", err)
	}
	defer resultSub.Unsubscribe()

	telemetrySub, err := s.consumeTelemetryMetrics(ctx)
	if err != nil {
		return fmt.Errorf("subscribe telemetry metrics: %w", err)
	}
	defer telemetrySub.Unsubscribe()
	go s.telemetrySendLoop(ctx)

	go s.agentHubLoop(ctx)
	go s.stalenessSweepLoop(ctx)
	go s.offlineExpiryLoop(ctx)
	go s.patchSchedulerLoop(ctx)
	go s.scheduledActionLoop(ctx)
	go s.deployDispatchLoop(ctx)
	go s.huntLoop(ctx)
	go s.enforceLoop(ctx)
	go s.osLifecycleLoop(ctx)
	go s.playbookSchedulerLoop(ctx)
	go s.reportSchedulerLoop(ctx)
	go s.backupSchedulerLoop(ctx)
	s.prepareSetupToken(ctx)
	go s.fileEventPruneLoop(ctx)
	go s.processEventPruneLoop(ctx)
	go s.exportSchedulerLoop(ctx)
	s.allowlistExistingInternalDestinations(ctx)
	s.loadLoggingSettings(ctx)
	go s.debsecRefreshLoop(ctx)
	go s.vulnScanLoop(ctx)
	go s.softwareFollowLoop(ctx)
	go s.directorySyncLoop(ctx)
	go s.revealSchedulerLoop(ctx)
	go s.guideLoop(ctx)
	go s.patchWaitLoop(ctx)
	go s.macOSMDMWatchLoop(ctx)
	go s.certRenewLoop(ctx)
	go s.appCredLoop(ctx)
	go s.expiryAlertLoop(ctx)
	s.trustKick = make(chan struct{}, 1)
	go s.trustRootLoop(ctx)
	go s.discoverLoop(ctx)
	go s.backupAlertLoop(ctx)
	go s.backupSourceLoop(ctx)
	go s.threatLoop(ctx)
	go s.entraLoop(ctx)
	go s.complianceScanLoop(ctx)
	go s.warrantyLoop(ctx)
	go s.integrationLoop(ctx)
	go s.completionSweepLoop(ctx)
	go s.recorderEventPruneLoop(ctx)
	go s.exploitIntelRefreshLoop(ctx)
	go s.clientProfileLoop(ctx)
	go s.swinventoryLoop(ctx)
	go s.dashboardSampleLoop(ctx)
	go s.watchApplyLoop(ctx)
	go s.approvalExpiryLoop(ctx)
	go s.jumpExpiryLoop(ctx)
	go s.healthSampleLoop(ctx)
	go s.playbookPauseExpiryLoop(ctx)

	s.httpSrv = &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: s.routes(),
		// Slow clients hold a connection each; these bound how long. Upload
		// routes and event streams adjust their own read deadline (see
		// applyBodyLimits). No WriteTimeout: event streams write for hours.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	serveErr := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", cfg.HTTPAddr)
		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("http shutdown error", "error", err)
		}
		return nil
	case err := <-serveErr:
		return err
	}
}

// agentHubInterval is the most often the live agent list is rebuilt for
// the console's SSE feed.
//
// Every heartbeat, facts message and registration asks for a rebuild, and a
// rebuild reads and encodes the whole agents table. Done once per request,
// that is O(fleet) work per message and O(fleet²) per heartbeat interval:
// at 2,000 endpoints, 200 heartbeats a second each re-reading 2,000 rows,
// on the consumer goroutine that is supposed to be recording them.
// Coalescing to one rebuild a second keeps the feed exactly as live as a
// person watching it can tell.
const agentHubInterval = time.Second

// refreshAgentHub asks for the agent list to be re-read and broadcast to
// every subscribed SSE client. Called after any write (registration,
// heartbeat, facts) and periodically by the staleness sweep so an agent
// going silent (no new event) still flips to offline for viewers.
//
// It does not wait: requests made while one is pending coalesce, and
// agentHubLoop rebuilds at most once per agentHubInterval, and only while
// somebody is subscribed (a new subscriber gets a fresh snapshot of its
// own on connect). A Server that was not started by Run — tests — has no
// loop and is refreshed synchronously, as before.
func (s *Server) refreshAgentHub(ctx context.Context) {
	if s.agentHubKick == nil {
		s.broadcastAgents(ctx)
		return
	}
	select {
	case s.agentHubKick <- struct{}{}:
	default: // a rebuild is already pending; it will see this change too
	}
}

func (s *Server) agentHubLoop(ctx context.Context) {
	coalesceLoop(ctx, s.agentHubKick, agentHubInterval, s.agentHub.HasSubscribers, s.broadcastAgents)
}

// coalesceLoop runs run once for each burst of signals on kick, at most once
// per interval, skipping it while active reports false. A signal that
// arrives during the pause stays in kick (buffered, capacity one), so the
// last change before a quiet spell is always acted on.
func coalesceLoop(ctx context.Context, kick <-chan struct{}, interval time.Duration, active func() bool, run func(context.Context)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
		}
		if active() {
			run(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// broadcastAgents re-reads the agent list and publishes it to the hub.
func (s *Server) broadcastAgents(ctx context.Context) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		s.logger.Warn("list agents for broadcast failed", "error", err)
		return
	}
	payload, err := encodeAgents(agents)
	if err != nil {
		s.logger.Warn("encode agents for broadcast failed", "error", err)
		return
	}
	s.agentHub.Publish(payload)
}

func (s *Server) stalenessSweepLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshAgentHub(ctx)
		}
	}
}

// offlineExpiryLoop retires endpoints that have been quiet for longer than
// cfg.OfflineExpiry. Retiring keeps the row and everything recorded about
// it and only sets managed = false: what a decommissioned machine was
// running is exactly the question somebody asks months later, and deleting
// it threw away the only record. An endpoint that registers or heartbeats
// again is un-retired automatically. A far slower purge, off by default,
// is the only thing that still removes inventory.
func (s *Server) offlineExpiryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			offlineFor := s.offlineExpiry()
			n, err := s.store.RetireOfflineAgents(ctx, offlineFor)
			if err != nil {
				s.logger.Warn("retire offline agents failed", "error", err)
				continue
			}
			if n > 0 {
				s.logger.Info("retired long-offline endpoints", "count", n, "offline_for", offlineFor)
				s.refreshAgentHub(ctx)
			}
			// Purging is a separate, much slower decision: forgetting an
			// endpoint is not the same as noticing it went away. Zero means
			// never, which is the default.
			if purge := s.purgeAfter(); purge > 0 {
				if p, err := s.store.PurgeRetiredAgents(ctx, purge); err != nil {
					s.logger.Warn("purge retired agents failed", "error", err)
				} else if p > 0 {
					s.logger.Info("purged retired endpoints", "count", p, "retired_for", purge)
					s.refreshAgentHub(ctx)
				}
			}
		}
	}
}

// sessionPruneLoop periodically deletes expired session rows. Sessions are
// already rejected once expired (GetSessionUser checks expires_at), so this
// is housekeeping, not correctness — it just keeps the table from growing
// forever.
func (s *Server) sessionPruneLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.store.PruneExpiredSessions(ctx); err != nil {
				s.logger.Warn("prune expired sessions failed", "error", err)
			}
		}
	}
}
