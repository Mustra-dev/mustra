package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	gonats "github.com/nats-io/nats.go"

	"github.com/mustra-dev/mustra/internal/proto"
)

// natsServerForTest starts a nats-server with JetStream and returns its
// URL. It needs $MUSTRA_TEST_NATS_SERVER or nats-server on PATH.
func natsServerForTest(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("MUSTRA_TEST_NATS_SERVER")
	if bin == "" {
		p, err := exec.LookPath("nats-server")
		if err != nil {
			t.Skip("no nats-server (set MUSTRA_TEST_NATS_SERVER to run the in-process restart test)")
		}
		bin = p
	}
	port := freeTCPPort(t)
	cmd := exec.Command(bin, "-a", "127.0.0.1", "-p", fmt.Sprint(port), "-js", "-sd", filepath.Join(t.TempDir(), "js"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	for i := 0; i < 100; i++ {
		if nc, err := gonats.Connect(url); err == nil {
			nc.Close()
			return url
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("test nats-server did not come up")
	return ""
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitListening(t *testing.T, addr string, want bool, within time.Duration, runDone ...chan error) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, d := range runDone {
			select {
			case err := <-d:
				t.Fatalf("Run returned early: %v", err)
			default:
			}
		}
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if c != nil {
			c.Close()
		}
		if (err == nil) == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s listening=%v not reached within %s", addr, want, within)
}

// After a legacy agent enrols, Run returns ErrRestart and cmd/agent runs a
// new Agent in the same process. Everything the first Run started must be
// gone by then: before the fix every loop was on the caller's context, so
// the restart left a second set of loops on a closed store and connection,
// and the old Self Service listener kept the port the new one needed.
func TestRunRestartLeavesNothingRunning(t *testing.T) {
	url := natsServerForTest(t)
	const agentID = "agt-0123456789abcdef0123456789abcdef"

	// Stands in for the control plane: answers registration, nothing else.
	harness, err := gonats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer harness.Close()
	if _, err := harness.Subscribe("beacon.register", func(m *gonats.Msg) {
		b, _ := json.Marshal(proto.RegisterResponse{AgentID: agentID})
		_ = m.Respond(b)
	}); err != nil {
		t.Fatal(err)
	}
	_ = harness.Flush()

	ssAddr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	dir := t.TempDir()
	cfg := Config{
		NATSURL:           url,
		Site:              "default", // what cmd/agent defaults to
		DataDir:           filepath.Join(dir, "mustra-agent.db"),
		SelfServiceAddr:   ssAddr,
		HeartbeatInterval: time.Hour,
		FactsInterval:     time.Hour,
		SensorInterval:    time.Hour,
		Logger:            slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: testLogLevel()})),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	baseline := runtime.NumGoroutine()

	first := New(cfg)
	restart := make(chan struct{})
	first.restartForTest = restart
	done := make(chan error, 1)
	go func() { done <- first.Run(ctx) }()
	waitListening(t, ssAddr, true, 60*time.Second, done)

	close(restart)
	select {
	case err := <-done:
		if !errors.Is(err, ErrRestart) {
			t.Fatalf("first Run returned %v, want ErrRestart", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("first Run did not return after a restart was requested")
	}
	if n := first.running.Load(); n != 0 {
		t.Fatalf("%d goroutine(s) of the first Run still running after it returned", n)
	}
	// The listener is closed by the time Run returns, so the port is free.
	if c, err := net.DialTimeout("tcp", ssAddr, 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("the first Run's Self Service listener still holds the port")
	}
	// No leftover loops. A little slack for runtime and client goroutines
	// winding down; a leaked runtime is dozens.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+5 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+5 {
		t.Fatalf("%d goroutines after the restart, baseline %d: the first runtime leaked", n, baseline)
	}

	// The in-process restart: a new Agent on the same configuration binds
	// the same Self Service port.
	second := New(cfg)
	done2 := make(chan error, 1)
	go func() { done2 <- second.Run(ctx) }()
	waitListening(t, ssAddr, true, 60*time.Second, done2)
	cancel()
	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("second Run returned %v on shutdown", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("second Run did not stop on cancellation")
	}
	if n := second.running.Load(); n != 0 {
		t.Fatalf("%d goroutine(s) of the second Run still running after it returned", n)
	}
	waitListening(t, ssAddr, false, 5*time.Second)
}

func testLogLevel() slog.Level {
	if os.Getenv("MUSTRA_TEST_AGENT_DEBUG") != "" {
		return slog.LevelDebug
	}
	return slog.LevelWarn
}
