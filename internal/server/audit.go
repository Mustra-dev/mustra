package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// The audit log: one place that answers "what happened, who did it, and
// to what".
//
// mustra already recorded actions in six different tables — deployments,
// shell commands, question history, integrity changes, catalog requests,
// agent actions. Each is right for its own module and useless for the
// question people actually ask after something goes wrong, which spans all
// of them. This is the spine: every significant action writes one event
// here as well, so there is a single chronological record to read, export,
// and ship to a SIEM.
//
// Writing to the module's own table *and* here is deliberate duplication.
// The module tables carry structure this cannot (per-device patch results,
// command output); this carries uniformity they cannot. Collapsing either
// into the other would lose something.

type auditEvent struct {
	Action   string         // "software.deploy", "shell.exec", "settings.update"
	Actor    string         // who
	Target   string         // what it acted on, in human terms
	AgentID  string         // when it concerns one endpoint
	Outcome  string         // "ok" | "failed" | "denied"
	Severity string         // "info" | "notice" | "warning"
	Detail   map[string]any // action-specific, kept small
}

// audit records one event. It never returns an error and never blocks the
// caller on storage: an action must not fail because its audit row could
// not be written, but a dropped write is logged loudly rather than
// swallowed — a silently incomplete audit log is worse than none.
func (s *Server) audit(ctx context.Context, ev auditEvent) {
	if ev.Severity == "" {
		ev.Severity = "info"
	}
	if ev.Outcome == "" {
		ev.Outcome = "ok"
	}
	detail := ""
	if len(ev.Detail) > 0 {
		if b, err := json.Marshal(ev.Detail); err == nil {
			detail = string(b)
		}
	}

	if s.store == nil {
		s.logger.Error("AUDIT WRITE FAILED — no store", "action", ev.Action, "actor", ev.Actor)
	} else if err := s.store.RecordAuditEvent(ctx, store.AuditEvent{
		Action: ev.Action, Actor: ev.Actor, Target: ev.Target, AgentID: ev.AgentID,
		Outcome: ev.Outcome, Severity: ev.Severity, Detail: detail,
	}); err != nil {
		s.logger.Error("AUDIT WRITE FAILED — this action is not in the audit log",
			"action", ev.Action, "actor", ev.Actor, "error", err)
	}

	// Also to the process log, so `docker logs` and anything tailing it
	// see the same events without needing database access.
	s.logger.Info("audit", "action", ev.Action, "actor", ev.Actor,
		"target", ev.Target, "outcome", ev.Outcome)

	s.forwardSyslog(ev, detail)
	s.emitEvent(integrationEvent{Type: "audit", Action: ev.Action, Actor: ev.Actor, Target: ev.Target, AgentID: ev.AgentID,
		Severity: ev.Severity, Outcome: ev.Outcome, Detail: ev.Detail})
}

// auditStrict records an event and reports whether it reached the
// database. Privileged actions call it before doing anything: an action
// that leaves no audit row is refused rather than performed unrecorded.
func (s *Server) auditStrict(ctx context.Context, ev auditEvent) error {
	if s.store == nil {
		return fmt.Errorf("audit store unavailable")
	}
	if ev.Severity == "" {
		ev.Severity = "info"
	}
	if ev.Outcome == "" {
		ev.Outcome = "ok"
	}
	detail := ""
	if len(ev.Detail) > 0 {
		if b, err := json.Marshal(ev.Detail); err == nil {
			detail = string(b)
		}
	}
	if err := s.store.RecordAuditEvent(ctx, store.AuditEvent{
		Action: ev.Action, Actor: ev.Actor, Target: ev.Target, AgentID: ev.AgentID,
		Outcome: ev.Outcome, Severity: ev.Severity, Detail: detail,
	}); err != nil {
		s.logger.Error("AUDIT WRITE FAILED — privileged action refused",
			"action", ev.Action, "actor", ev.Actor, "error", err)
		return err
	}
	s.logger.Info("audit", "action", ev.Action, "actor", ev.Actor,
		"target", ev.Target, "outcome", ev.Outcome)
	s.forwardSyslog(ev, detail)
	s.emitEvent(integrationEvent{Type: "audit", Action: ev.Action, Actor: ev.Actor, Target: ev.Target, AgentID: ev.AgentID,
		Severity: ev.Severity, Outcome: ev.Outcome, Detail: ev.Detail})
	return nil
}

// ---- live log level ----

// levelVar backs the runtime-adjustable log level. slog reads it on every
// call, so changing it takes effect immediately across every goroutine
// without restarting anything or rebuilding the logger.
var levelVar = new(slog.LevelVar)

// LogLevelVar exposes the level to the process's logger construction, so
// there is one variable the whole program shares rather than a copy per
// handler that would drift the moment the level changed.
func LogLevelVar() *slog.LevelVar { return levelVar }

// SetLogLevel applies a level by name, for start-up configuration.
func SetLogLevel(name string) { levelVar.Set(parseLevel(name)) }

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func levelName(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug:
		return "debug"
	case l <= slog.LevelInfo:
		return "info"
	case l <= slog.LevelWarn:
		return "warn"
	default:
		return "error"
	}
}

// ---- syslog / SIEM forwarding ----

// syslogSink streams audit events to a syslog collector as they happen.
//
// Distinct from a Connect export on purpose: an export is a scheduled
// batch of answers, this is a live tap on the event stream. A SIEM wants
// the second — an alert that arrives an hour later in a CSV is not an
// alert.
type syslogSink struct {
	// edit serialises reconfiguration: reading the current settings,
	// dialling a new target and swapping it in happen as one step, so two
	// saves cannot interleave. A save holds edit, not mu, across its dial,
	// so events keep flowing to the old connection while a new one is
	// tried. (The forwarder's own one-shot reconnect after a failed write
	// does dial under mu, as it always has.)
	edit sync.Mutex

	mu      sync.RWMutex
	enabled bool
	target  string // as configured, scheme included: what is stored and shown
	network string // "udp" | "tcp"
	addr    string
	format  string // "rfc5424" | "cef" | "json"
	conn    net.Conn

	// dial connects to a collector; nil means dialSyslog. Tests replace it
	// to act while a dial is in progress.
	dial func(network, addr string) (net.Conn, error)
}

// syslogConfig is one complete forwarding configuration.
type syslogConfig struct {
	Enabled bool
	Target  string
	Format  string
}

// syslogChange is a checked syslogConfig, ready to apply. conn is the
// connection to swap in: freshly dialled, or nil to keep the current one
// when the target has not changed.
type syslogChange struct {
	cfg           syslogConfig
	network, addr string
	conn          net.Conn
}

var syslogFormats = []string{"rfc5424", "cef", "json"}

// parseSyslogTarget splits a target into the network and address to
// dial. A bare host:port is UDP, as syslog traditionally is.
func parseSyslogTarget(target string) (network, addr string) {
	if rest, ok := strings.CutPrefix(target, "tcp://"); ok {
		return "tcp", rest
	}
	if rest, ok := strings.CutPrefix(target, "udp://"); ok {
		return "udp", rest
	}
	return "udp", target
}

func dialSyslog(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, 5*time.Second)
}

func (k *syslogSink) dialer() func(network, addr string) (net.Conn, error) {
	if k.dial != nil {
		return k.dial
	}
	return dialSyslog
}

// settings reports the configuration the sink is running.
func (k *syslogSink) settings() syslogConfig {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return syslogConfig{Enabled: k.enabled, Target: k.target, Format: k.format}
}

// prepare checks cfg and, when it turns forwarding on to a target the
// sink is not already connected to, dials that target. It changes
// nothing: if it fails, the sink carries on exactly as before, so a
// mistyped address cannot stop forwarding that works. The caller holds
// edit from before it reads the settings until it has applied the change.
func (k *syslogSink) prepare(cfg syslogConfig) (syslogChange, error) {
	cfg.Target = strings.TrimSpace(cfg.Target)
	if cfg.Format == "" {
		cfg.Format = "rfc5424"
	}
	if !slices.Contains(syslogFormats, cfg.Format) {
		return syslogChange{}, fmt.Errorf("format must be rfc5424, cef or json")
	}
	ch := syslogChange{cfg: cfg}
	if cfg.Target != "" {
		ch.network, ch.addr = parseSyslogTarget(cfg.Target)
	}
	if !cfg.Enabled {
		return ch, nil
	}
	if cfg.Target == "" {
		return syslogChange{}, fmt.Errorf("forwarding needs a target")
	}

	k.mu.RLock()
	connected := k.conn != nil && k.network == ch.network && k.addr == ch.addr
	k.mu.RUnlock()
	if connected {
		return ch, nil
	}
	// Dial now so a bad address is reported to whoever is saving the
	// setting, rather than failing silently on every event afterwards.
	conn, err := k.dialer()(ch.network, ch.addr)
	if err != nil {
		return syslogChange{}, fmt.Errorf("could not reach %s over %s: %w", ch.addr, ch.network, err)
	}
	ch.conn = conn
	return ch, nil
}

// apply swaps a prepared change in, closing the connection it replaces.
func (k *syslogSink) apply(ch syslogChange) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !ch.cfg.Enabled || ch.conn != nil {
		if k.conn != nil {
			k.conn.Close()
		}
		k.conn = ch.conn
	}
	k.enabled, k.target, k.format = ch.cfg.Enabled, ch.cfg.Target, ch.cfg.Format
	k.network, k.addr = ch.network, ch.addr
}

func (s *Server) forwardSyslog(ev auditEvent, detail string) {
	s.syslog.mu.RLock()
	enabled, format, conn := s.syslog.enabled, s.syslog.format, s.syslog.conn
	s.syslog.mu.RUnlock()
	if !enabled || conn == nil {
		return
	}

	line := syslogLine(format, ev, detail)
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		s.syslog.mu.Lock()
		defer s.syslog.mu.Unlock()
		if s.syslog.conn != conn {
			// Reconfigured while this event was being written: the
			// connection that failed was closed on purpose (or already
			// redialled by another event). Send to whatever replaced it
			// rather than redialling over it, in the format it now
			// expects, which the change may have switched.
			if s.syslog.enabled && s.syslog.conn != nil {
				_, _ = s.syslog.conn.Write([]byte(syslogLine(s.syslog.format, ev, detail) + "\n"))
			}
			return
		}
		// One reconnect attempt: a TCP collector restarting shouldn't
		// permanently sever the stream.
		conn.Close()
		if c, derr := s.syslog.dialer()(s.syslog.network, s.syslog.addr); derr == nil {
			s.syslog.conn = c
			_, _ = c.Write([]byte(line + "\n"))
		} else {
			s.syslog.conn = nil
			s.logger.Warn("syslog forwarding is down", "target", s.syslog.target, "error", derr)
		}
	}
}

// syslogLine renders one audit event in a forwarding format.
func syslogLine(format string, ev auditEvent, detail string) string {
	host, _ := os.Hostname()
	var line string
	switch format {
	case "cef":
		// CEF severity is 0-10; audit events map to a narrow band because
		// they are records of intent, not detections.
		sev := map[string]int{"info": 3, "notice": 5, "warning": 7, "critical": 9}[ev.Severity]
		line = fmt.Sprintf("CEF:0|mustra|mustra|1.0|%s|%s|%d|suser=%s target=%s outcome=%s %s",
			cefEscape(ev.Action), cefEscape(ev.Action), sev,
			cefEscape(ev.Actor), cefEscape(ev.Target), cefEscape(ev.Outcome), cefEscape(detail))
	case "json":
		b, _ := json.Marshal(map[string]any{
			"ts": time.Now().UTC().Format(time.RFC3339), "host": host,
			"action": ev.Action, "actor": ev.Actor, "target": ev.Target,
			"agent_id": ev.AgentID, "outcome": ev.Outcome, "severity": ev.Severity,
			"detail": detail,
		})
		line = string(b)
	default: // rfc5424
		pri := 13 // user.notice
		if ev.Severity == "warning" {
			pri = 12
		} else if ev.Severity == "critical" {
			pri = 10 // user.crit: identity and permission changes
		}
		// The message body is a JSON object rather than key=value text.
		// A syslog collector still frames and routes it by the header,
		// while anything downstream — Loki's `| json`, Splunk, Elastic —
		// gets real fields instead of a string to regex apart. Structured
		// framing on the outside, structured content on the inside.
		body, err := json.Marshal(map[string]any{
			"action": ev.Action, "actor": ev.Actor, "target": ev.Target,
			"agent_id": ev.AgentID, "outcome": ev.Outcome,
			"severity": ev.Severity, "detail": ev.Detail,
		})
		if err != nil {
			body = []byte(`{"action":"` + ev.Action + `"}`)
		}
		line = fmt.Sprintf("<%d>1 %s %s mustra - %s - %s",
			pri, time.Now().UTC().Format(time.RFC3339), host, ev.Action, body)
	}
	return line
}

func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}
