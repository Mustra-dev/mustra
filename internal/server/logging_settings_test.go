package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// collector is a local TCP syslog collector: it accepts connections and
// hands back each line it reads, so a test can see where audit events
// are actually delivered.
type collector struct {
	ln       net.Listener
	accepted chan struct{} // one per connection accepted
	closed   chan struct{} // one per connection the server closed
	lines    chan string
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{ln: ln, accepted: make(chan struct{}, 16), closed: make(chan struct{}, 16), lines: make(chan string, 64)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.accepted <- struct{}{}
			go func() {
				defer conn.Close()
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					c.lines <- sc.Text()
				}
				c.closed <- struct{}{}
			}()
		}
	}()
	return c
}

func (c *collector) target() string { return "tcp://" + c.ln.Addr().String() }

// expect waits for the next line and checks it mentions want.
func (c *collector) expect(t *testing.T, want string) {
	t.Helper()
	select {
	case line := <-c.lines:
		if !strings.Contains(line, want) {
			t.Fatalf("collector got %q, want a line mentioning %q", line, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("collector received nothing; want a line mentioning %q", want)
	}
}

// quiet checks nothing arrives on ch for a moment.
func quiet(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("unexpected %s", what)
	case <-time.After(200 * time.Millisecond):
	}
}

func wait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// refusedTarget is a TCP address nothing listens on, so dialling it is
// refused at once.
func refusedTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}

// keepLevel restores the process-wide log level when the test ends.
func keepLevel(t *testing.T) {
	prev := levelVar.Level()
	t.Cleanup(func() { levelVar.Set(prev) })
}

func quietServer() *Server {
	return &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), syslog: &syslogSink{}}
}

func currentConn(s *Server) net.Conn {
	s.syslog.mu.RLock()
	defer s.syslog.mu.RUnlock()
	return s.syslog.conn
}

func postLogging(t *testing.T, s *Server, user, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/admin/logging", strings.NewReader(body))
	r = r.WithContext(auth.WithUser(r.Context(), &store.User{Username: user}))
	rec := httptest.NewRecorder()
	s.handleUpdateLogging(rec, r)
	return rec
}

func getLogging(t *testing.T, s *Server) loggingSettings {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleGetLogging(rec, httptest.NewRequest("GET", "/api/admin/logging", nil))
	var got loggingSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET /api/admin/logging: %v: %s", err, rec.Body)
	}
	return got
}

// A request refused with 400 changes nothing: not the level, not the
// forwarding the server is doing, not what GET reports. Before, the level
// was applied first and the working connection was closed before the new
// target was dialled, so a rejected target stopped forwarding until the
// next successful save or a restart. No store is needed: a refused
// request must not reach it.
func TestUpdateLoggingRefusedRequestChangesNothing(t *testing.T) {
	keepLevel(t)
	levelVar.Set(slog.LevelInfo)
	cases := map[string]string{
		"unreachable TCP target":   `{"log_level":"debug","forward_enabled":true,"forward_target":"` + refusedTarget(t) + `","forward_format":"json"}`,
		"undiallable UDP target":   `{"log_level":"debug","forward_enabled":true,"forward_target":"udp://127.0.0.1:notaport"}`,
		"unknown format":           `{"log_level":"debug","forward_format":"xml"}`,
		"enabled without a target": `{"log_level":"debug","forward_enabled":true,"forward_target":""}`,
		"bad level":                `{"log_level":"loud","forward_enabled":false}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			s := quietServer()
			old := newCollector(t)
			startForwarding(t, s, old.target())
			wait(t, old.accepted, "the first connection")
			conn := currentConn(s)

			rec := postLogging(t, s, "tester", body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d (%s), want 400", rec.Code, rec.Body)
			}
			if got := levelName(levelVar.Level()); got != "info" {
				t.Errorf("level is %s after a refused request, want info", got)
			}
			got := getLogging(t, s)
			want := loggingSettings{LogLevel: "info", Enabled: true, Target: old.target(), Format: "rfc5424"}
			if got != want {
				t.Errorf("GET after a refused request = %+v, want %+v", got, want)
			}
			if currentConn(s) != conn {
				t.Error("the working connection was replaced by a refused request")
			}
			quiet(t, old.closed, "close of the working connection")
			s.audit(context.Background(), auditEvent{Action: "test.still-forwarding"})
			old.expect(t, "test.still-forwarding")
		})
	}
}

// A new target is dialled while the old connection carries on: events
// audited during the dial still reach the old collector, and the old
// connection is closed only once the new one is in place.
func TestUpdateLoggingSwapsConnectionAfterDialling(t *testing.T) {
	s := quietServer()
	old, next := newCollector(t), newCollector(t)
	startForwarding(t, s, old.target())
	wait(t, old.accepted, "the first connection")

	s.syslog.dial = func(network, addr string) (net.Conn, error) {
		s.audit(context.Background(), auditEvent{Action: "test.during-dial"})
		old.expect(t, "test.during-dial")
		return dialSyslog(network, addr)
	}
	ch, err := s.syslog.prepare(syslogConfig{Enabled: true, Target: next.target(), Format: "json"})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, next.accepted, "the new connection")
	quiet(t, old.closed, "close of the old connection before the swap")
	s.syslog.apply(ch)
	wait(t, old.closed, "close of the old connection after the swap")

	s.audit(context.Background(), auditEvent{Action: "test.after-swap"})
	next.expect(t, `"action":"test.after-swap"`)
}

// Events forwarded from several goroutines while the target is swapped
// back and forth: run with -race. A write that fails because a swap
// closed its connection goes to the replacement instead of redialling
// over it, so the sink ends on the last target applied.
func TestSyslogReconfigureWhileForwarding(t *testing.T) {
	s := quietServer()
	a, b := newCollector(t), newCollector(t)
	go func() {
		for range a.lines {
		}
	}()
	go func() {
		for range b.lines {
		}
	}()
	startForwarding(t, s, a.target())

	stop := make(chan struct{})
	var done sync.WaitGroup
	for range 4 {
		done.Add(1)
		go func() {
			defer done.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.audit(context.Background(), auditEvent{Action: "test.concurrent"})
				}
			}
		}()
	}
	for i := range 20 {
		target := a.target()
		if i%2 == 0 {
			target = b.target()
		}
		s.syslog.edit.Lock()
		ch, err := s.syslog.prepare(syslogConfig{Enabled: true, Target: target, Format: "json"})
		if err != nil {
			s.syslog.edit.Unlock()
			t.Fatal(err)
		}
		s.syslog.apply(ch)
		s.syslog.edit.Unlock()
	}
	close(stop)
	done.Wait()

	s.syslog.mu.RLock()
	defer s.syslog.mu.RUnlock()
	if s.syslog.target != a.target() || s.syslog.conn == nil {
		t.Errorf("after the swaps: target %q, connected %v; want %q, connected", s.syslog.target, s.syslog.conn != nil, a.target())
	}
	if got := s.syslog.conn.RemoteAddr().String(); "tcp://"+got != a.target() {
		t.Errorf("connected to %s, want %s", got, a.target())
	}
}

// swappingConn fails its write after reconfiguring the sink, as if a save
// had swapped the connection while the write was in flight.
type swappingConn struct {
	net.Conn
	swap func()
}

func (c *swappingConn) Write([]byte) (int, error) {
	c.swap()
	return 0, net.ErrClosed
}

func (c *swappingConn) Close() error { return nil }

// An event whose write lost a race with a save goes to the new connection
// in the new format, not the one it was first rendered in.
func TestSyslogWriteRacingASwapUsesTheNewFormat(t *testing.T) {
	s := quietServer()
	next := newCollector(t)
	s.syslog.apply(syslogChange{
		cfg:     syslogConfig{Enabled: true, Target: "tcp://old.invalid:514", Format: "cef"},
		network: "tcp", addr: "old.invalid:514",
		conn: &swappingConn{swap: func() {
			ch, err := s.syslog.prepare(syslogConfig{Enabled: true, Target: next.target(), Format: "json"})
			if err != nil {
				t.Error(err)
				return
			}
			s.syslog.apply(ch)
		}},
	})
	s.audit(context.Background(), auditEvent{Action: "test.raced"})
	next.expect(t, `"action":"test.raced"`)
}

// The handler, end to end with the settings it persists. Opt-in: it needs
// a disposable Postgres database.
func TestUpdateLoggingAgainstStore(t *testing.T) {
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
	keepLevel(t)
	levelVar.Set(slog.LevelInfo)

	s := quietServer()
	s.store = st
	who := idgen.New("logging-test-")
	stored := func(key string) string {
		t.Helper()
		v, err := st.GetSetting(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	ok := func(body string) {
		t.Helper()
		if rec := postLogging(t, s, who, body); rec.Code != http.StatusOK {
			t.Fatalf("POST %s: status %d (%s)", body, rec.Code, rec.Body)
		}
	}

	first := newCollector(t)
	ok(`{"forward_enabled":true,"forward_target":"` + first.target() + `","forward_format":"rfc5424"}`)
	wait(t, first.accepted, "the first connection")
	first.expect(t, "logging.forwarding")
	conn := currentConn(s)

	t.Run("level only leaves forwarding alone", func(t *testing.T) {
		// Another save holds edit, as it would across a slow dial; a
		// level-only save does not wait for it.
		s.syslog.edit.Lock()
		codes := make(chan int, 1)
		go func() { codes <- postLogging(t, s, who, `{"log_level":"debug"}`).Code }()
		select {
		case code := <-codes:
			s.syslog.edit.Unlock()
			if code != http.StatusOK {
				t.Fatalf("level-only save: status %d", code)
			}
		case <-time.After(5 * time.Second):
			s.syslog.edit.Unlock()
			t.Fatal("a level-only save waited behind another save")
		}
		if got := levelName(levelVar.Level()); got != "debug" {
			t.Errorf("level is %s, want debug", got)
		}
		if got := getLogging(t, s); !got.Enabled || got.Target != first.target() || got.Format != "rfc5424" {
			t.Errorf("forwarding after a level-only request = %+v", got)
		}
		if currentConn(s) != conn {
			t.Error("a level-only request replaced the connection")
		}
		if v := stored("log_forward_enabled"); v != "true" {
			t.Errorf("stored log_forward_enabled = %q, want true", v)
		}
		if v := stored("log_forward_target"); v != first.target() {
			t.Errorf("stored log_forward_target = %q, want %q", v, first.target())
		}
		first.expect(t, "logging.level")
	})

	t.Run("refused target leaves level, store and connection", func(t *testing.T) {
		rec := postLogging(t, s, who, `{"log_level":"warn","forward_enabled":true,"forward_target":"`+refusedTarget(t)+`","forward_format":"json"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d (%s), want 400", rec.Code, rec.Body)
		}
		if got := levelName(levelVar.Level()); got != "debug" {
			t.Errorf("level is %s after a refused request, want debug", got)
		}
		for key, want := range map[string]string{
			"log_level": "debug", "log_forward_enabled": "true",
			"log_forward_target": first.target(), "log_forward_format": "rfc5424",
		} {
			if v := stored(key); v != want {
				t.Errorf("stored %s = %q after a refused request, want %q", key, v, want)
			}
		}
		if currentConn(s) != conn {
			t.Error("a refused request replaced the connection")
		}
		events, err := st.ListAuditEvents(ctx, "logging.", who, "", 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Target == "warn" || strings.Contains(e.Detail, "json") {
				t.Errorf("a refused request was audited as a change: %+v", e)
			}
		}
	})

	t.Run("new target replaces the connection", func(t *testing.T) {
		next := newCollector(t)
		ok(`{"forward_enabled":true,"forward_target":"` + next.target() + `","forward_format":"json"}`)
		wait(t, next.accepted, "the new connection")
		wait(t, first.closed, "close of the old connection")
		next.expect(t, `"action":"logging.forwarding"`)
		if v := stored("log_forward_target"); v != next.target() {
			t.Errorf("stored log_forward_target = %q, want %q", v, next.target())
		}

		// Saving the same target again keeps the connection it has.
		conn := currentConn(s)
		ok(`{"forward_enabled":true,"forward_target":"` + next.target() + `","forward_format":"cef"}`)
		quiet(t, next.accepted, "redial of an unchanged target")
		if currentConn(s) != conn {
			t.Error("an unchanged target was redialled")
		}
		next.expect(t, "CEF:0")
	})

	t.Run("turning forwarding off closes the connection", func(t *testing.T) {
		ok(`{"forward_enabled":false}`)
		if got := getLogging(t, s); got.Enabled {
			t.Errorf("forwarding still on: %+v", got)
		}
		if currentConn(s) != nil {
			t.Error("connection kept after forwarding was turned off")
		}
		if v := stored("log_forward_enabled"); v != "false" {
			t.Errorf("stored log_forward_enabled = %q, want false", v)
		}
	})
}

// On start the stored forwarding is restored; a target that cannot be
// reached is shown as off with the target it was meant to reach. Opt-in,
// like the test above.
func TestLoadLoggingSettingsRestoresForwarding(t *testing.T) {
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
	keepLevel(t)
	save := func(enabled, target, format string) {
		t.Helper()
		for k, v := range map[string]string{
			"log_forward_enabled": enabled, "log_forward_target": target, "log_forward_format": format,
		} {
			if err := st.SetSetting(ctx, k, v, "test"); err != nil {
				t.Fatal(err)
			}
		}
	}

	c := newCollector(t)
	save("true", c.target(), "cef")
	s := quietServer()
	s.store = st
	s.loadLoggingSettings(ctx)
	wait(t, c.accepted, "the restored connection")
	if got := getLogging(t, s); !got.Enabled || got.Target != c.target() || got.Format != "cef" {
		t.Errorf("restored forwarding = %+v", got)
	}

	refused := refusedTarget(t)
	save("true", refused, "json")
	s = quietServer()
	s.store = st
	s.loadLoggingSettings(ctx)
	if got := getLogging(t, s); got.Enabled || got.Target != refused || got.Format != "json" {
		t.Errorf("forwarding restored to an unreachable target = %+v, want off with that target", got)
	}
	if currentConn(s) != nil {
		t.Error("connected to an unreachable target")
	}
}

func startForwarding(t *testing.T, s *Server, target string) {
	t.Helper()
	ch, err := s.syslog.prepare(syslogConfig{Enabled: true, Target: target, Format: "rfc5424"})
	if err != nil {
		t.Fatal(err)
	}
	s.syslog.apply(ch)
}
