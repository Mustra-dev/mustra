// Package agent implements the mustra endpoint agent: it registers with the
// control plane, heartbeats, publishes host facts, and answers live queries
// — buffering to a local bbolt store whenever NATS is unreachable so no
// data is lost across control-plane outages.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// Config controls agent behavior. All fields have sane defaults applied by
// cmd/agent; nothing here is required to be set beyond NATSURL.
type Config struct {
	NATSURL string
	Site    string
	// DataDir is the bbolt identity/outbox FILE, not the directory holding
	// it: cmd/agent appends the filename before constructing this. The name
	// and the comment both said directory, and code that believed them
	// wrote into a path underneath a file. Take filepath.Dir for anything
	// that needs the directory, as the rest of this package does.
	DataDir      string
	AgentVersion string
	// LogLevel is the handler's level, shared with main so a configure
	// command can change verbosity without a restart.
	LogLevel          *slog.LevelVar
	HeartbeatInterval time.Duration
	FactsInterval     time.Duration
	// SensorInterval is how often the processes/services/installed-apps
	// sensors re-collect and publish on their own, independent of live
	// queries. Default: 15 minutes. Adjustable per-sensor at
	// runtime via a mustra.cmd.<id> "set_sensor_interval" command — see
	// internal/agent/sensor_loop.go.
	SensorInterval time.Duration
	// SelfServiceAddr is where the local Self Service window listens. It is
	// a loopback address on purpose — the window is for the person sitting
	// at this machine, and it holds no authorization of its own (the server
	// decides what may be installed). Empty disables the window entirely.
	SelfServiceAddr string
	// NATSCreds authenticate this agent to the control plane and verify the
	// server it is talking to. Empty means an unauthenticated plaintext
	// connection, which is what shipped first and is why anything on the
	// network could issue root commands to the fleet.
	NATSCreds bnats.Creds
	// EnrollToken is an enrollment token given directly (MUSTRA_ENROLL_TOKEN).
	// Usually it is not: the installer writes it to enroll.token beside the
	// identity database, and the agent deletes that file once it has
	// enrolled. See identity.go.
	EnrollToken string
	// UpdatePubKey is the update signing key to pin, when given directly
	// rather than in update-signing.pub.
	UpdatePubKey string
	Logger       *slog.Logger
}

// ErrRestart asks the caller to run the agent again in-process: it has
// just obtained its own credential and must reconnect as itself.
var ErrRestart = errors.New("agent restart requested")

// Agent is one running instance of the mustra endpoint agent.
type Agent struct {
	// noRemoteCode is inventory-and-patching mode; see noremotecode.go. Read
	// once at start, from a file only an administrator on the endpoint can
	// change.
	noRemoteCode bool

	deployMu     sync.Mutex
	jitMu        sync.Mutex
	softwareMu   sync.Mutex
	deployActive string
	deployCancel context.CancelFunc
	cfg          Config
	logger       *slog.Logger
	store        *Store
	settings     agentSettings // client profile settings; see settings.go
	nc           *gonats.Conn
	pub          *durablePublisher
	// watchRefresh nudges the file watcher after a "watch" command.
	watchRefresh chan struct{}
	// notification is the end-user message currently awaiting an answer.
	// One at a time: a stack of competing restart prompts is not something
	// a person can act on, and the newest is the one that matters.
	notification activeNotification
	survey       activeSurvey
	branding     selfServiceBranding
	// tray records when the tray helper last asked for the current
	// notification. Its poll is its heartbeat: nothing else needs to be
	// registered, and if it stops, this goes stale on its own.
	tray lastSeen
	// trayReported keeps a failure to start the helper to one log line
	// rather than one every thirty seconds.
	trayReported lastSeen
	agentID      string
	info         proto.AgentInfo
	// cred is this agent's own credential; nil while it still runs on the
	// legacy shared password (or none, in development).
	cred *agentCredential
	// running counts the goroutines this Run started that have not yet
	// returned; Run does not return until it is zero again.
	running atomic.Int64
	// restartForTest, when set, asks Run to return ErrRestart exactly as a
	// successful legacy self-enrolment does (agent_restart_test.go).
	restartForTest <-chan struct{}
}

// lastSeen is a timestamp several goroutines touch: the Self Service
// server writes it, the notification path reads it.
type lastSeen struct {
	mu sync.RWMutex
	at time.Time
}

func (l *lastSeen) mark() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.at = time.Now()
}

// reset forgets the last sighting: the tray was just replaced, so the old
// one's polls say nothing about whether a new one is running.
func (l *lastSeen) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.at = time.Time{}
}

// active reports whether it was seen within window.
func (l *lastSeen) active(window time.Duration) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return !l.at.IsZero() && time.Since(l.at) < window
}

// age is how long since it was last seen, or -1 when never. Reported when
// the supervisor decides to start a helper, because "it started another one"
// and "it thinks none is running" are different problems and the number is
// what separates them.
func (l *lastSeen) age() time.Duration {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.at.IsZero() {
		return -1
	}
	return time.Since(l.at)
}

// New constructs an Agent. It does not connect to NATS or open the store —
// call Run for that.
func New(cfg Config) *Agent {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 10 * time.Second
	}
	if cfg.FactsInterval <= 0 {
		cfg.FactsInterval = 60 * time.Second
	}
	if cfg.SensorInterval <= 0 {
		cfg.SensorInterval = 15 * time.Minute
	}
	a := &Agent{cfg: cfg, logger: cfg.Logger, noRemoteCode: detectNoRemoteCode()}
	if a.noRemoteCode {
		a.logger.Info("inventory-and-patching mode: this endpoint refuses code from the server")
		noRemoteCodeActive.Store(true)
	}
	return a
}

// Run blocks until ctx is cancelled, running the full agent lifecycle:
// open store → connect NATS → register → subscribe to queries → heartbeat
// and facts loops → outbox flush loop.
func (a *Agent) Run(ctx context.Context) error {
	// Everything this Run starts lives on runCtx, not the caller's ctx. Run
	// can return while ctx is still live — ErrRestart after a legacy agent
	// enrols, and the caller then runs a new Agent in-process — and
	// goroutines on ctx would outlive it: a second set of every loop, using
	// a closed store and connection, and an old Self Service listener
	// holding the port the new one needs.
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	var group sync.WaitGroup
	goRun := func(f func()) {
		group.Add(1)
		a.running.Add(1)
		go func() {
			defer group.Done()
			defer a.running.Add(-1)
			f()
		}()
	}
	info, err := localAgentInfo(a.cfg.Site, a.cfg.AgentVersion)
	if err != nil {
		return fmt.Errorf("determine local host info: %w", err)
	}
	a.info = info

	store, err := OpenStore(a.cfg.DataDir)
	if err != nil {
		return fmt.Errorf("open local store: %w", err)
	}
	a.store = store
	a.recordPID()
	a.loadSettings()
	a.watchRefresh = make(chan struct{}, 1)
	a.loadWatchConfig()
	a.loadBranding()
	defer store.Close()

	// Expired temporary accounts are removed from here, before connecting,
	// so an endpoint that cannot reach the control plane still cleans up.
	// Stopped before the store closes (defers run in reverse).
	jitCtx, stopJIT := context.WithCancel(ctx)
	jitDone := make(chan struct{})
	go func() { defer close(jitDone); a.runJITSweep(jitCtx) }()
	defer func() { stopJIT(); <-jitDone }()

	priorID, err := store.LoadAgentID()
	if err != nil {
		return fmt.Errorf("load persisted agent id: %w", err)
	}
	if priorID != "" {
		a.logger.Info("resuming prior identity", "agent_id", priorID)
	}

	// Resume the journal before connecting: a rebooted endpoint can validate
	// local state even when the control plane is temporarily unreachable.
	deployCtx, stopDeploy := context.WithCancel(ctx)
	deployDone := make(chan struct{})
	workerStarted := false
	startDeploy := func() {
		// Jobs accepted before this mode was turned on stay unstarted.
		if a.noRemoteCode {
			return
		}
		workerStarted = true
		go func() { defer close(deployDone); a.runDeployLoop(deployCtx) }()
	}
	defer func() {
		stopDeploy()
		if workerStarted {
			<-deployDone
		}
	}()
	a.agentID = priorID
	if priorID != "" {
		a.logger = a.logger.With("agent_id", priorID)
		startDeploy()
	}
	natsCreds, err := a.establishIdentity(ctx, priorID)
	if err != nil {
		return err
	}
	if a.cred != nil && priorID != "" && priorID != a.cred.AgentID {
		// The credential names the identity; a database left over from an
		// earlier install does not get to disagree with it.
		a.logger.Warn("the stored identity differs from the enrolled one; adopting the enrolled one",
			"stored", priorID, "enrolled", a.cred.AgentID)
	}
	// The recovery job's liveness beat, before the connect loop below can
	// spin for as long as the broker is unreachable (recovery.go).
	goRun(func() { a.beatWhileRunning(ctx) })
	var nc *gonats.Conn
	var lastDiagnosis time.Time
	for {
		nc, err = bnats.ConnectWithCreds(a.cfg.NATSURL, "agent:"+info.Hostname, natsCreds, a.logger, bnats.FleetReconnectBackoff())
		if err == nil {
			break
		}
		if priorID == "" && a.cred == nil {
			return fmt.Errorf("connect to nats: %w", err)
		}
		a.logger.Warn("could not connect to the control plane, retrying", "error", err)
		// A certificate the agent cannot verify gets the detail needed to
		// see why (which CA it trusts, what the server presented), at most
		// every ten minutes so a long outage does not fill the log.
		if isCertificateError(err) && time.Since(lastDiagnosis) > 10*time.Minute {
			lastDiagnosis = time.Now()
			a.logger.Warn("the control plane's certificate did not verify against the agent's CA", tlsDiagnosis(a.cfg.NATSURL, natsCreds.CAFile)...)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	a.deployMu.Lock()
	a.nc = nc
	a.deployMu.Unlock()
	defer nc.Close()
	agentID, err := a.register(ctx, priorID)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	if a.cred != nil && agentID != a.cred.AgentID {
		return fmt.Errorf("register: server answered for %s, but this agent is enrolled as %s", agentID, a.cred.AgentID)
	}
	// A self-update waiting to hear that this build started and reached
	// the control plane hears it now (selfupdate_apply.go).
	a.commitPendingUpdate()
	if agentID != priorID {
		if workerStarted {
			if err := store.SaveAgentID(agentID); err != nil {
				return err
			}
			return fmt.Errorf("server changed persisted identity while local deployments may be active; restart to re-enroll")
		}
		a.agentID = agentID
		if err := store.SaveAgentID(agentID); err != nil {
			return fmt.Errorf("persist agent id: %w", err)
		}
		a.logger = a.logger.With("agent_id", agentID)
	}
	if !workerStarted {
		startDeploy()
	}
	a.logger.Info("registered", "hostname", info.Hostname, "os", info.OS, "arch", info.Arch, "site", info.Site)

	js, err := bnats.JetStream(nc)
	if err != nil {
		return fmt.Errorf("init jetstream: %w", err)
	}
	a.pub = newDurablePublisher(nc, js, store, a.logger)

	unsub, err := a.subscribeQueries(ctx)
	if err != nil {
		return fmt.Errorf("subscribe to query subjects: %w", err)
	}
	defer unsub()

	intervalChans := map[proto.SensorKind]chan time.Duration{
		proto.SensorProcesses:       make(chan time.Duration),
		proto.SensorServices:        make(chan time.Duration),
		proto.SensorInstalledApps:   make(chan time.Duration),
		proto.SensorPatches:         make(chan time.Duration),
		proto.SensorDisks:           make(chan time.Duration),
		proto.SensorNetwork:         make(chan time.Duration),
		proto.SensorUsers:           make(chan time.Duration),
		proto.SensorHardware:        make(chan time.Duration),
		proto.SensorPrivileges:      make(chan time.Duration),
		proto.SensorNeighbors:       make(chan time.Duration),
		proto.SensorCertificates:    make(chan time.Duration),
		proto.SensorPerformance:     make(chan time.Duration),
		proto.SensorIntegrity:       make(chan time.Duration),
		proto.SensorLocalAdmins:     make(chan time.Duration),
		proto.SensorDirectory:       make(chan time.Duration),
		proto.SensorBackups:         make(chan time.Duration),
		proto.SensorSecurityPosture: make(chan time.Duration),
	}
	cmdSub, err := a.subscribeCommands(ctx, intervalChans)
	if err != nil {
		return fmt.Errorf("subscribe to command subject: %w", err)
	}
	defer cmdSub.Unsubscribe()

	// Registered after the store and connection defers, so it runs before
	// them: every goroutine below is stopped and waited for while the
	// store and connection they use are still open.
	defer func() {
		cancelRun()
		group.Wait()
	}()

	restartCh := make(chan struct{})
	var restartOnce sync.Once
	goRun(func() { a.legacyEnrollRetryLoop(ctx, agentID, func() { restartOnce.Do(func() { close(restartCh) }) }) })

	goRun(func() { a.pub.runFlushLoop(ctx, 5*time.Second) })
	goRun(func() { a.heartbeatLoop(ctx) })
	goRun(func() { a.telemetryLoop(ctx) })
	goRun(func() { a.factsLoop(ctx) })
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorProcesses, a.cfg.SensorInterval, intervalChans[proto.SensorProcesses], func(ctx context.Context) (any, error) {
			return collectProcesses(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorServices, a.cfg.SensorInterval, intervalChans[proto.SensorServices], func(ctx context.Context) (any, error) {
			return collectServices(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorInstalledApps, a.cfg.SensorInterval, intervalChans[proto.SensorInstalledApps], func(ctx context.Context) (any, error) {
			return collectInstalledApps(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorPatches, a.cfg.SensorInterval, intervalChans[proto.SensorPatches], func(ctx context.Context) (any, error) {
			return a.collectPatchesReported(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorDisks, a.cfg.SensorInterval, intervalChans[proto.SensorDisks], func(ctx context.Context) (any, error) {
			return collectDisks(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorNetwork, a.cfg.SensorInterval, intervalChans[proto.SensorNetwork], func(ctx context.Context) (any, error) {
			return collectNetworkInterfaces(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorUsers, a.cfg.SensorInterval, intervalChans[proto.SensorUsers], func(ctx context.Context) (any, error) {
			return collectLoggedInUsers(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorPrivileges, a.cfg.SensorInterval, intervalChans[proto.SensorPrivileges], func(ctx context.Context) (any, error) {
			// Wrapped in a slice because every sensor publishes an array, even
			// the ones with exactly one row. A lone object here read as
			// unparseable to the group/question engine and silently didn't
			// contribute — which is precisely the kind of quiet wrong answer
			// this codebase is meant not to produce.
			info, err := collectPrivileges(ctx)
			if err != nil {
				return nil, err
			}
			return []proto.PrivilegeInfo{info}, nil
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorNeighbors, a.cfg.SensorInterval, intervalChans[proto.SensorNeighbors], func(ctx context.Context) (any, error) {
			return collectNeighbors(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorCertificates, a.cfg.SensorInterval, intervalChans[proto.SensorCertificates], func(ctx context.Context) (any, error) {
			return collectCertificates(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorLocalAdmins, a.cfg.SensorInterval, intervalChans[proto.SensorLocalAdmins], func(ctx context.Context) (any, error) {
			return collectLocalAdmins(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorDirectory, a.cfg.SensorInterval, intervalChans[proto.SensorDirectory], func(ctx context.Context) (any, error) {
			return collectDirectory(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorBackups, a.cfg.SensorInterval, intervalChans[proto.SensorBackups], func(ctx context.Context) (any, error) {
			return collectBackups(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorSecurityPosture, a.cfg.SensorInterval, intervalChans[proto.SensorSecurityPosture], func(ctx context.Context) (any, error) {
			return collectSecurityPosture(ctx)
		})
	})
	shellSub, err := a.subscribeShell(ctx)
	if err != nil {
		return fmt.Errorf("subscribe to shell subject: %w", err)
	}
	defer shellSub.Unsubscribe()

	goRun(func() { a.runPerformanceSampler(ctx) })
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorPerformance, perfReportEvery, intervalChans[proto.SensorPerformance], func(ctx context.Context) (any, error) {
			return collectPerformance(ctx)
		})
	})
	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorIntegrity, a.cfg.SensorInterval, intervalChans[proto.SensorIntegrity], func(ctx context.Context) (any, error) {
			return collectIntegrity(ctx)
		})
	})
	// The real-time half of file integrity monitoring. It runs alongside the
	// hash sweep above rather than instead of it: the sweep cannot miss a
	// change made while the agent was down, and the watcher cannot wait
	// fifteen minutes to notice one made now.
	goRun(func() { a.runFileWatch(ctx) })
	// The process half of the same idea: the processes sensor is a snapshot
	// on a timer, so anything that runs and exits between two collections
	// never existed as far as the console is concerned — which describes
	// most of what an attacker runs.
	goRun(func() { a.runProcessWatch(ctx) })
	// The recorder: registry, network, DNS and logon events, the third
	// real-time feed. See recorder.go for what each platform can see.
	goRun(func() { a.runRecorder(ctx) })
	if a.cfg.SelfServiceAddr != "" {
		goRun(func() { a.runSelfService(ctx, a.cfg.SelfServiceAddr) })
	}
	// Keep a tray helper running for whoever is signed in. Starting it is
	// the agent's job because only a service holding SYSTEM can get a
	// process across session 0 into somebody's desktop -- and because the
	// agent restarts on every update, this is also what brings the helper
	// back afterwards.
	goRun(func() { a.superviseTray(ctx.Done()) })
	// Ask for Full Disk Access if macOS has not granted it. At startup, so
	// it lands right after an install or update -- the installer restarts
	// the agent as its last act -- and rate-limited to once a day, because
	// an agent can restart for reasons that are not a person's doing.
	// Not tracked: a one-shot that touches neither the store nor the
	// connection, and a slow macOS command in it must not hold up a stop.
	go a.promptFullDiskAccess()
	// Installed Apps on Windows shows the running build, not the version
	// the installer wrote before any self-update.
	syncInstallEntry(a.cfg.AgentVersion)
	// A heartbeat for the recovery job, and once this build has proved
	// itself, the last-known-good copy and the job (recovery.go).
	goRun(func() { a.keepRecoveryReady(ctx) })
	// Operator-authored sensors, pulled from the server rather than
	// configured here, so adding one is a change in a single place.
	goRun(func() { a.runCustomSensorLoop(ctx) })
	// Patch jobs that were waiting on the restart this start may follow.
	goRun(func() { a.verifyPatchesAfterRestart(ctx) })

	goRun(func() {
		a.runSensorLoop(ctx, proto.SensorHardware, a.cfg.SensorInterval, intervalChans[proto.SensorHardware], func(ctx context.Context) (any, error) {
			return collectHardware(ctx)
		})
	})

	select {
	case <-ctx.Done():
		a.logger.Info("shutting down")
		return nil
	case <-restartCh:
		return ErrRestart
	case <-a.restartForTest:
		return ErrRestart
	}
}

// register sends a RegisterRequest and retries with backoff until it
// succeeds or ctx is cancelled — the server or NATS may not be up yet when
// the agent starts (e.g. both booting together in the compose
// stack).
func (a *Agent) register(ctx context.Context, priorID string) (string, error) {
	subject := bnats.Register()
	if a.cred != nil {
		// Bound to this identity by the subject: the broker lets only this
		// agent publish here.
		priorID = a.cred.AgentID
		subject = bnats.RegisterAgent(priorID)
	}
	req := proto.RegisterRequest{AgentID: priorID, Info: a.info}
	payload, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal register request: %w", err)
	}

	backoff := time.Second
	const maxBackoff = 15 * time.Second
	for {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		msg, err := a.nc.RequestWithContext(rctx, subject, payload)
		cancel()
		if err == nil {
			var resp proto.RegisterResponse
			if err := json.Unmarshal(msg.Data, &resp); err != nil {
				return "", fmt.Errorf("decode register response: %w", err)
			}
			if resp.AgentID == "" {
				return "", fmt.Errorf("server returned empty agent id")
			}
			return resp.AgentID, nil
		}
		a.logger.Warn("registration attempt failed, retrying", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer ticker.Stop()
	a.sendHeartbeat(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat(ctx)
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	hb := proto.Heartbeat{AgentID: a.agentID, Timestamp: time.Now().UTC()}
	payload, err := json.Marshal(hb)
	if err != nil {
		a.logger.Error("marshal heartbeat failed", "error", err)
		return
	}
	if err := a.pub.PublishLatest(ctx, bnats.AgentHeartbeat(a.agentID), payload); err != nil {
		a.logger.Error("heartbeat publish/buffer failed", "error", err)
	}
}

func (a *Agent) factsLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.FactsInterval)
	defer ticker.Stop()
	a.sendFacts(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendFacts(ctx)
		}
	}
}

func (a *Agent) sendFacts(ctx context.Context) {
	facts, err := collectFacts(ctx, a.agentID, a.info, a.cfg.AgentVersion)
	if err != nil {
		a.logger.Error("collect facts failed", "error", err)
		return
	}
	facts.Settings = a.currentSettings()
	facts.WatchRevision = currentWatch().Revision
	payload, err := json.Marshal(facts)
	if err != nil {
		a.logger.Error("marshal facts failed", "error", err)
		return
	}
	if err := a.pub.PublishLatest(ctx, bnats.AgentFacts(a.agentID), payload); err != nil {
		a.logger.Error("facts publish/buffer failed", "error", err)
	}
}
