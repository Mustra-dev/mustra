package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	bnats "github.com/mustra-dev/mustra/internal/nats"
)

const (
	replyTestAgentA = "agt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	replyTestAgentB = "agt-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	replyTestNonce  = "0123456789abcdef0123456789abcdef"
)

// An agent picks the reply subject of its own request; the server publishes
// there with its own rights. Only the requester's inbox is acceptable.
func TestAgentReplyAllowedOnlyIntoTheRequestersInbox(t *testing.T) {
	ctx := context.Background()
	notEnforced := &Server{logger: slog.Default()}
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	// Enforced, with no legacy password configured: legacy is refused
	// without the store being consulted.
	enforcedNoLegacy := &Server{logger: slog.Default(), trust: &agentTrust{calloutKey: kp}}

	cases := []struct {
		name  string
		s     *Server
		kind  replyKind
		id    string
		reply string
		want  bool
	}{
		{"own inbox", enforcedNoLegacy, replyAgent, replyTestAgentA, "_INBOX_" + replyTestAgentA + ".x.1", true},
		{"no reply", enforcedNoLegacy, replyAgent, replyTestAgentA, "", false},
		{"bare own prefix", enforcedNoLegacy, replyAgent, replyTestAgentA, "_INBOX_" + replyTestAgentA + ".", false},
		{"another agent's inbox", enforcedNoLegacy, replyAgent, replyTestAgentA, "_INBOX_" + replyTestAgentB + ".x", false},
		{"prefix of a longer id", enforcedNoLegacy, replyAgent, "agt-aaaa", "_INBOX_agt-aaaa.x", false},
		{"another agent's facts", enforcedNoLegacy, replyAgent, replyTestAgentA, "beacon.agent." + replyTestAgentB + ".facts", false},
		{"another agent's heartbeat", notEnforced, replyAgent, replyTestAgentA, "beacon.agent." + replyTestAgentB + ".heartbeat", false},
		{"jetstream api", notEnforced, replyAgent, replyTestAgentA, "$JS.API.STREAM.DELETE.AGENTS", false},
		{"command subject", notEnforced, replyAgent, replyTestAgentA, "beacon.cmd." + replyTestAgentB, false},
		{"server inbox", notEnforced, replyAgent, replyTestAgentA, bnats.ServerInboxPrefix + ".abc", false},
		{"wildcard", enforcedNoLegacy, replyAgent, replyTestAgentA, "_INBOX_" + replyTestAgentA + ".>", false},
		{"star", enforcedNoLegacy, replyAgent, replyTestAgentA, "_INBOX_" + replyTestAgentA + ".*", false},
		{"empty token", enforcedNoLegacy, replyAgent, replyTestAgentA, "_INBOX_" + replyTestAgentA + "..x", false},
		{"legacy inbox, identity not enforced", notEnforced, replyAgent, replyTestAgentA, "_INBOX.abc.1", true},
		{"legacy inbox, legacy refused", enforcedNoLegacy, replyAgent, replyTestAgentA, "_INBOX.abc.1", false},
		{"legacy subject, legacy inbox", notEnforced, replyLegacy, "", "_INBOX.abc", true},
		{"legacy subject, legacy refused", enforcedNoLegacy, replyLegacy, "", "_INBOX.abc", false},
		{"legacy subject, agent inbox", notEnforced, replyLegacy, replyTestAgentA, "_INBOX_" + replyTestAgentA + ".x", false},
		{"legacy subject, facts", notEnforced, replyLegacy, "", "beacon.agent." + replyTestAgentB + ".facts", false},
		{"enrol inbox", enforcedNoLegacy, replyEnroll, "", bnats.EnrollInboxPrefix(replyTestNonce) + ".x", true},
		{"enrol inbox, bad nonce", enforcedNoLegacy, replyEnroll, "", "_INBOX_ENROLL_xyz.x", false},
		{"enrol, bare prefix", enforcedNoLegacy, replyEnroll, "", bnats.EnrollInboxPrefix(replyTestNonce) + ".", false},
		{"enrol, facts", enforcedNoLegacy, replyEnroll, "", "beacon.agent." + replyTestAgentB + ".facts", false},
		{"enrol, legacy inbox", notEnforced, replyEnroll, "", "_INBOX.abc", false},
	}
	for _, c := range cases {
		msg := &nats.Msg{Subject: "beacon.selfservice." + c.id, Reply: c.reply}
		if got := c.s.agentReplyAllowed(ctx, msg, c.kind, c.id); got != c.want {
			t.Errorf("%s: agentReplyAllowed(%q) = %v, want %v", c.name, c.reply, got, c.want)
		}
	}
}

// natsServerBinary finds a nats-server to run the broker-level test
// against: $MUSTRA_TEST_NATS_SERVER, else nats-server on PATH.
func natsServerBinary(t *testing.T) string {
	if p := os.Getenv("MUSTRA_TEST_NATS_SERVER"); p != "" {
		return p
	}
	p, err := exec.LookPath("nats-server")
	if err != nil {
		t.Skip("no nats-server (set MUSTRA_TEST_NATS_SERVER to run the broker-level reply test)")
	}
	return p
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// The reflection itself, against a real broker: agent A, allowed to publish
// only beacon.selfservice.A, sends a request whose reply subject is agent
// B's facts subject (and the JetStream API). Before the fix the server's
// answer was stored in the AGENTS stream as B's facts.
func TestSelfServiceReplyReflectionAgainstBroker(t *testing.T) {
	bin := natsServerBinary(t)
	dir := t.TempDir()
	port := freePort(t)
	conf := fmt.Sprintf(`port: %d
jetstream { store_dir: %q }
authorization {
  users: [
    { user: srv, password: s }
    { user: agtA, password: a, permissions: {
        publish: { allow: ["beacon.selfservice.%s"] },
        subscribe: { allow: ["_INBOX_%s.>"] } } }
  ]
}
`, port, filepath.Join(dir, "js"), replyTestAgentA, replyTestAgentA)
	confPath := filepath.Join(dir, "nats.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-c", confPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)

	var srv *nats.Conn
	var err error
	for i := 0; i < 50; i++ {
		if srv, err = nats.Connect(url, nats.UserInfo("srv", "s")); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect to test broker: %v", err)
	}
	defer srv.Close()
	js, err := jetstream.New(srv)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "AGENTS", Subjects: []string{"beacon.agent.*.>"}})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{logger: slog.Default(), nc: srv}
	sub, err := s.subscribeSelfService(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := srv.Flush(); err != nil {
		t.Fatal(err)
	}

	agent, err := nats.Connect(url, nats.UserInfo("agtA", "a"), nats.CustomInboxPrefix(bnats.AgentInboxPrefix(replyTestAgentA)))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	for _, reply := range []string{
		"beacon.agent." + replyTestAgentB + ".facts",
		"beacon.agent." + replyTestAgentB + ".heartbeat",
		"$JS.API.STREAM.DELETE.AGENTS",
	} {
		if err := agent.PublishMsg(&nats.Msg{Subject: bnats.SelfService(replyTestAgentA), Reply: reply,
			Data: []byte(`{"action":"nope"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	// The agent's own, legitimate request is still answered.
	resp, err := agent.Request(bnats.SelfService(replyTestAgentA), []byte(`{"action":"nope"}`), 5*time.Second)
	if err != nil {
		t.Fatalf("legitimate self-service request went unanswered: %v", err)
	}
	if !strings.Contains(string(resp.Data), "unknown action") {
		t.Fatalf("unexpected reply %s", resp.Data)
	}
	_ = srv.Flush()
	time.Sleep(300 * time.Millisecond)

	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("AGENTS stream gone (reflected into the JetStream API?): %v", err)
	}
	if info.State.Msgs != 0 {
		t.Fatalf("the server's reply was reflected into the AGENTS stream: %d message(s) stored", info.State.Msgs)
	}
}
