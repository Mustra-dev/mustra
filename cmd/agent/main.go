// Command agent is the mustra endpoint agent: it connects outbound to NATS,
// registers with the control plane, heartbeats, publishes host facts, and
// answers live queries.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mustra-dev/mustra/internal/agent"
	bnats "github.com/mustra-dev/mustra/internal/nats"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		natsURL         = flag.String("nats-url", envOr("MUSTRA_NATS_URL", "nats://127.0.0.1:4222"), "NATS server URL")
		site            = flag.String("site", envOr("MUSTRA_SITE", "default"), "site label for this agent")
		dataDir         = flag.String("data-dir", envOr("MUSTRA_DATA_DIR", "./mustra-agent-data"), "path to bbolt identity/outbox file")
		hbEvery         = flag.Duration("heartbeat-interval", 10*time.Second, "heartbeat interval")
		factsEvry       = flag.Duration("facts-interval", 60*time.Second, "facts publish interval")
		sensorEvry      = flag.Duration("sensor-interval", 15*time.Minute, "processes/services/installed-apps sensor publish interval (default: 15m)")
		ssAddr          = flag.String("self-service-addr", envOr("MUSTRA_SELF_SERVICE_ADDR", "127.0.0.1:8137"), "loopback address for the Self Service window; empty to disable")
		natsCA          = flag.String("nats-ca", envOr("MUSTRA_NATS_CA", ""), "CA certificate that signed the NATS server's certificate")
		natsUser        = flag.String("nats-user", envOr("MUSTRA_NATS_USER", ""), "legacy shared NATS username (enrolled agents use their own credential)")
		natsPass        = flag.String("nats-password", envOr("MUSTRA_NATS_PASSWORD", ""), "legacy shared NATS password; prefer agent.env or enrollment")
		enrollToken     = flag.String("enroll-token", envOr("MUSTRA_ENROLL_TOKEN", ""), "enrollment token (normally read from enroll.token in the data dir)")
		updatePubKey    = flag.String("update-pubkey", envOr("MUSTRA_UPDATE_PUBKEY", ""), "base64 ed25519 key agent updates must be signed with (normally pinned at enrollment)")
		applyUpdate     = flag.String("apply-update", "", "internal: apply a staged, verified update described by this state file, then exit")
		recoverDir      = flag.String("recover", "", "internal: the recovery job; restart the agent, or restore its last known good build, if it stopped running (this data dir), then exit")
		recoverExe      = flag.String("recover-exe", "", "internal: the installed agent binary the recovery job looks after")
		verifyUninstall = flag.String("verify-uninstall-password", "",
			"check a password from stdin against the bcrypt hash in this file, then exit; used by the endpoint uninstaller")
		logLevel = flag.String("log-level", envOr("MUSTRA_LOG_LEVEL", "info"), "log level: debug, info, warn, error")
	)
	flag.Parse()

	// Checking the uninstall password, which the endpoint's own uninstaller
	// calls. bcrypt is not something a shell script or PowerShell can
	// verify on its own, and this binary is already on the machine.
	//
	// It runs before anything else is set up: no data directory, no log, no
	// bus. The uninstaller is about to remove all of it.
	if *verifyUninstall != "" {
		if err := agent.VerifyUninstallPassword(*verifyUninstall, os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		return
	}

	if *recoverDir != "" {
		// The recovery job (internal/agent/recovery.go), run by the OS
		// scheduler from the last-known-good copy of the agent.
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		if *recoverExe == "" {
			fmt.Fprintln(os.Stderr, "--recover needs --recover-exe")
			os.Exit(2)
		}
		if err := agent.Recover(*recoverDir, *recoverExe, logger); err != nil {
			os.Exit(1)
		}
		return
	}

	if *applyUpdate != "" {
		// The detached updater helper (internal/agent/selfupdate_apply.go).
		logger := slog.New(slog.NewTextHandler(updateLog(*applyUpdate), nil))
		if err := agent.ApplyUpdate(*applyUpdate, logger); err != nil {
			os.Exit(1)
		}
		return
	}

	// The shared password from an older install lives in agent.env beside
	// the binary (Linux, macOS and, after migration, Windows). Read here,
	// by the agent, rather than through the service's environment, which
	// every command the agent runs would inherit.
	//
	// The CA path is taken on its own, password or not: enrolling deletes
	// the password from agent.env but leaves the CA, and an install whose
	// agent URL is nats:// (not tls://) has no --nats-ca on its command
	// line. Tying the CA to the password made every such agent's first
	// restart after enrolling verify the bus against the system roots and
	// fail with "certificate signed by unknown authority".
	applyAgentEnvFile(natsUser, natsPass, natsCA)(readAgentEnvFile())
	// And nothing secret stays in this process's environment from here on,
	// so nothing the agent runs — package commands, custom sensors, shell
	// sessions — can read it.
	agent.ScrubSecretEnv()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "create data dir %s failed: %v\n", *dataDir, err)
		os.Exit(1)
	}

	// A Windows service has no console, so stdout is discarded. Keep the
	// log beside the identity database instead — without it, a service
	// that fails to start leaves nothing at all to diagnose.
	logOut := io.Writer(os.Stdout)
	if isService() {
		if f, err := openServiceLog(filepath.Join(*dataDir, "agent.log")); err == nil {
			logOut = f
		}
	}
	levelVar := new(slog.LevelVar)
	levelVar.Set(parseLevel(*logLevel))
	logger := slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: levelVar}))
	slog.SetDefault(logger)

	cfg := agent.Config{
		NATSURL:           *natsURL,
		Site:              *site,
		DataDir:           *dataDir + "/mustra-agent.db",
		AgentVersion:      version,
		HeartbeatInterval: *hbEvery,
		FactsInterval:     *factsEvry,
		SensorInterval:    *sensorEvry,
		SelfServiceAddr:   *ssAddr,
		NATSCreds:         bnats.Creds{CAFile: *natsCA, User: *natsUser, Password: *natsPass},
		EnrollToken:       *enrollToken,
		UpdatePubKey:      *updatePubKey,
		Logger:            logger,
		LogLevel:          levelVar,
	}

	run := func(ctx context.Context) error {
		for {
			err := agent.New(cfg).Run(ctx)
			// Having just enrolled, the agent reconnects as itself.
			if errors.Is(err, agent.ErrRestart) {
				logger.Info("restarting the agent in-process")
				continue
			}
			return err
		}
	}

	// Under the Windows SCM this blocks until the service is told to stop.
	// Everywhere else it returns immediately and we run in the foreground.
	if handled, err := runService(run, logger); handled {
		if err != nil {
			logger.Error("service exited with error", "error", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		logger.Error("agent exited with error", "error", err)
		os.Exit(1)
	}
}

// openServiceLog opens the agent's log file, rotating it once if it has
// grown past 10MB. A service runs unattended for months; an unbounded log
// on the system drive is its own outage.
func openServiceLog(path string) (*os.File, error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 10<<20 {
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

// envOr reads MUSTRA_<KEY> first and falls back to the pre-rename
// BEACON_<KEY>, so a deployment whose .env predates the rename keeps
// working untouched. Keys are passed in as "MUSTRA_..." by the flag
// definitions above. envDurationOr/envBoolOr use the same rule.
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

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// applyAgentEnvFile fills in what agent.env holds and the command line
// did not say: the legacy credential only as a pair, the CA on its own.
func applyAgentEnvFile(user, pass, ca *string) func(fileUser, filePass, fileCA string) {
	return func(fileUser, filePass, fileCA string) {
		if *user == "" && *pass == "" && filePass != "" {
			*user, *pass = fileUser, filePass
		}
		if *ca == "" {
			*ca = fileCA
		}
	}
}

// readAgentEnvFile reads the legacy credential an older installer left in
// agent.env beside the binary. Only the three keys it ever held are read;
// anything else in the file is ignored. A file readable by anyone but its
// owner is tightened before it is trusted.
func readAgentEnvFile() (user, pass, ca string) {
	exe, err := os.Executable()
	if err != nil {
		return "", "", ""
	}
	path := filepath.Join(filepath.Dir(exe), "agent.env")
	if fi, err := os.Stat(path); err != nil {
		return "", "", ""
	} else if fi.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(path, 0o600)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "MUSTRA_NATS_USER", "BEACON_NATS_USER":
			user = value
		case "MUSTRA_NATS_PASSWORD", "BEACON_NATS_PASSWORD":
			pass = value
		case "MUSTRA_NATS_CA", "BEACON_NATS_CA":
			ca = value
		}
	}
	return user, pass, ca
}

// updateLog is where the detached updater writes: beside its state file,
// since it runs outside the service and its output goes nowhere else.
func updateLog(statePath string) io.Writer {
	f, err := os.OpenFile(filepath.Join(filepath.Dir(statePath), "update.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return os.Stderr
	}
	return io.MultiWriter(f, os.Stderr)
}
