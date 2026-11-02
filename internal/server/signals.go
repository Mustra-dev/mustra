package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/signals"
	"github.com/mustra-dev/mustra/internal/store"
)

// Signals: behavioural rules evaluated live against every process, file
// and recorder event. An indicator asks "is this exact hash/name/address
// here"; a signal asks "did something behave like this" — PowerShell with
// an encoded command, a Run key written by anything that is not an
// installer, a connection to a port nobody uses, forty failed logons from
// one address. The rules are compiled once and cached; a save reloads them.
//
// A finding is one signal on one endpoint with a count, not one row per
// hit: a rule that fires a thousand times overnight is one thing to look at.

type compiledSignal struct {
	store.Signal
	rule *signals.Rule
}

type signalCache struct {
	mu      sync.RWMutex
	at      time.Time
	byKind  map[string][]compiledSignal
	all     []compiledSignal
	version int
}

func (s *Server) loadSignals(ctx context.Context, force bool) {
	c := &s.sigs
	c.mu.RLock()
	fresh := !force && time.Since(c.at) < time.Minute
	c.mu.RUnlock()
	if fresh {
		return
	}
	list, err := s.store.ListSignals(ctx)
	if err != nil {
		s.logger.Warn("load signals", "error", err)
		return
	}
	byKind := map[string][]compiledSignal{}
	var all []compiledSignal
	for _, sg := range list {
		if !sg.Enabled {
			continue
		}
		rule, err := signals.Compile(sg.Expression)
		if err != nil {
			s.logger.Warn("signal does not compile; skipped", "signal", sg.Name, "error", err)
			continue
		}
		cs := compiledSignal{Signal: sg, rule: rule}
		all = append(all, cs)
		for _, obj := range rule.Objects() {
			byKind[obj] = append(byKind[obj], cs)
		}
	}
	c.mu.Lock()
	c.byKind, c.all, c.at = byKind, all, time.Now()
	c.version++
	c.mu.Unlock()
}

// matchSignals evaluates every enabled signal that reads this kind of
// event and records a finding for each that fires. It returns the id of
// the first signal that matched, for the event row. Notification is on the
// first hit per (signal, endpoint); later hits only raise the count.
func (s *Server) matchSignals(ctx context.Context, agentID, kind string, fields map[string]string, summary string, count int) string {
	s.loadSignals(ctx, false)
	s.sigs.mu.RLock()
	rules := s.sigs.byKind[kind]
	s.sigs.mu.RUnlock()
	if len(rules) == 0 {
		return ""
	}
	first := ""
	for _, cs := range rules {
		if !cs.rule.Eval(fields) {
			continue
		}
		if first == "" {
			first = cs.ID
		}
		isNew, err := s.store.RecordSignalFinding(ctx, store.SignalFinding{
			ID: idgen.New("sig-f-"), SignalID: cs.ID, AgentID: agentID, Kind: kind, Summary: safeTruncate(summary, 1000), Count: count,
		})
		if err != nil {
			s.logger.Warn("record signal finding", "signal", cs.Name, "error", err)
			continue
		}
		if isNew {
			hostname := s.hostnameFor(ctx, agentID)
			severity := cs.Severity
			if severity != "critical" && severity != "info" {
				severity = "warning"
			}
			s.logger.Warn("signal fired", "signal", cs.Name, "host", hostname, "kind", kind, "event", summary)
			s.notify(ctx, severity, "Threat Response", "Signal fired: "+cs.Name,
				fmt.Sprintf("%s on %s: %s", kind, hostname, safeTruncate(summary, 200)), "/hunt#signals")
		}
	}
	return first
}

// processFields and fileFields flatten the two older feeds the same way,
// so one rule language covers all six objects.
func processFields(ev proto.ProcessEvent) map[string]string {
	return map[string]string{
		"process.name": ev.Name, "process.command_line": ev.Cmdline, "process.user": ev.Username,
		"process.pid": strconv.Itoa(int(ev.PID)), "process.ppid": strconv.Itoa(int(ev.PPID)),
	}
}

func fileFields(ev proto.FileEvent) map[string]string {
	return map[string]string{"file.path": ev.Path, "file.op": ev.Op}
}

// --- HTTP ---

// listSignalsResponse is what GET /api/hunt/signals answers.
type listSignalsResponse struct {
	Examples []map[string]string `json:"examples"`
	Objects  map[string][]string `json:"objects"`
	Signals  []store.Signal      `json:"signals"`
}

func (s *Server) handleListSignals(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListSignals(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSONResponse(w, listSignalsResponse{Signals: list, Objects: signals.Objects, Examples: signalExamples})
}

// saveSignalResponse is what POST /api/hunt/signals and PUT
// /api/hunt/signals/{id} answer.
type saveSignalResponse struct {
	ID      string   `json:"id"`
	Objects []string `json:"objects"`
}

func (s *Server) handleSaveSignal(w http.ResponseWriter, r *http.Request) {
	var in store.Signal
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "invalid signal", 400)
		return
	}
	if id := r.PathValue("id"); id != "" {
		in.ID = id
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Expression = strings.TrimSpace(in.Expression)
	if in.Name == "" {
		http.Error(w, "a signal needs a name", 400)
		return
	}
	rule, err := signals.Compile(in.Expression)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	in.Objects = rule.Objects()
	switch in.Severity {
	case "info", "warning", "critical":
	default:
		in.Severity = "warning"
	}
	if in.ID == "" {
		in.ID = idgen.New("sig-")
		in.Enabled = true
	}
	in.CreatedBy = auth.CurrentUser(r.Context()).Username
	if err := s.store.UpsertSignal(r.Context(), in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.loadSignals(r.Context(), true)
	s.audit(r.Context(), auditEvent{Action: "hunt.signal.save", Actor: in.CreatedBy, Target: in.Name, Severity: "notice",
		Detail: map[string]any{"objects": in.Objects, "severity": in.Severity, "enabled": in.Enabled}})
	writeJSONResponse(w, saveSignalResponse{ID: in.ID, Objects: in.Objects})
}

func (s *Server) handleDeleteSignal(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSignal(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.loadSignals(r.Context(), true)
	w.WriteHeader(204)
}

// testSignalRequest is the body of POST /api/hunt/signals/test.
type testSignalRequest struct {
	Expression string `json:"expression" api:"required"`
}

// signalTestHit is an entry of what POST /api/hunt/signals/test answers.
type signalTestHit struct {
	Kind     string    `json:"kind"`
	Hostname string    `json:"hostname"`
	At       time.Time `json:"at"`
	Summary  string    `json:"summary"`
}

// testSignalResponse is what POST /api/hunt/signals/test answers.
type testSignalResponse struct {
	Hits    []signalTestHit `json:"hits"`
	Objects []string        `json:"objects"`
	Scanned int             `json:"scanned"`
}

// handleTestSignal compiles an expression and runs it over the last
// events of the kinds it reads, so an author sees what it would have
// caught before enabling it. No finding is recorded.
func (s *Server) handleTestSignal(w http.ResponseWriter, r *http.Request) {
	var req testSignalRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	rule, err := signals.Compile(req.Expression)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	hits := []signalTestHit{}
	scanned := 0
	for _, obj := range rule.Objects() {
		switch obj {
		case "process":
			evs, _ := s.store.ListProcessEvents(r.Context(), "", "", false, 1000)
			for _, e := range evs {
				if e.Kind != "start" {
					continue
				}
				scanned++
				if rule.Eval(processFields(proto.ProcessEvent{PID: e.PID, PPID: e.PPID, Name: e.Name, Cmdline: e.Cmdline, Username: e.Username})) {
					hits = append(hits, signalTestHit{"process", e.Hostname, e.At, e.Name + " " + e.Cmdline})
				}
			}
		case "file":
			evs, _ := s.store.ListFileEvents(r.Context(), "", false, 1000)
			for _, e := range evs {
				scanned++
				if rule.Eval(fileFields(proto.FileEvent{Path: e.Path, Op: e.Op})) {
					hits = append(hits, signalTestHit{"file", e.Hostname, e.At, e.Op + " " + e.Path})
				}
			}
		default:
			evs, _ := s.store.ListRecorderEvents(r.Context(), obj, "", "", false, 1000)
			for _, e := range evs {
				scanned++
				if rule.Eval(e.Fields) {
					hits = append(hits, signalTestHit{e.Kind, e.Hostname, e.At, e.Summary})
				}
			}
		}
	}
	if len(hits) > 200 {
		hits = hits[:200]
	}
	writeJSONResponse(w, testSignalResponse{Objects: rule.Objects(), Scanned: scanned, Hits: hits})
}

// listSignalFindingsResponse is what GET /api/hunt/signal-findings answers.
type listSignalFindingsResponse struct {
	Findings []store.SignalFinding `json:"findings"`
}

func (s *Server) handleListSignalFindings(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.store.ListSignalFindings(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSONResponse(w, listSignalFindingsResponse{Findings: list})
}

// ackSignalFindingRequest is the body of POST /api/hunt/signal-findings/{id}/ack.
type ackSignalFindingRequest struct {
	// Acknowledged is true when left out, or with no body at all: the
	// route acknowledges. False re-opens the finding. A body that is not
	// valid JSON is refused. The same as an indicator finding's ack.
	Acknowledged *bool `json:"acknowledged"`
}

func (s *Server) handleAckSignalFinding(w http.ResponseWriter, r *http.Request) {
	var req ackSignalFindingRequest
	// No body at all acknowledges; one that cannot be read is refused
	// rather than taken as the same.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ack := true
	if req.Acknowledged != nil {
		ack = *req.Acknowledged
	}
	if err := s.store.AcknowledgeSignalFinding(r.Context(), r.PathValue("id"), ack); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}

// signalExamples are starting points the editor offers. They are examples,
// not seeded rules: nothing fires that nobody wrote.
var signalExamples = []map[string]string{
	{"name": "PowerShell with an encoded command", "severity": "critical", "expression": "process.name contains 'powershell' AND (process.command_line contains '-enc' OR process.command_line contains '-EncodedCommand' OR process.command_line contains 'FromBase64String')"},
	{"name": "Download piped to a shell", "severity": "critical", "expression": "(process.command_line contains 'curl' OR process.command_line contains 'wget') AND (process.command_line contains '| sh' OR process.command_line contains '| bash' OR process.command_line contains '|sh' OR process.command_line contains '|bash')"},
	{"name": "New autorun written", "severity": "warning", "expression": "registry.key contains '\\CurrentVersion\\Run' AND registry.op != 'delete'"},
	{"name": "Defender exclusion added", "severity": "critical", "expression": "registry.key contains 'Windows Defender\\Exclusions' AND registry.op != 'delete'"},
	{"name": "LSA authentication package changed", "severity": "critical", "expression": "registry.key ends with '\\Control\\Lsa' AND (registry.value equals 'Security Packages' OR registry.value equals 'Authentication Packages' OR registry.value equals 'Notification Packages')"},
	{"name": "Connection to a common reverse-shell port", "severity": "critical", "expression": "network.direction equals 'connect' AND network.remote_port in [4444, 1337, 31337, 5555, 6666]"},
	{"name": "Office application connecting out", "severity": "warning", "expression": "network.direction equals 'connect' AND network.process in ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'] AND NOT network.remote_ip starts with '10.'"},
	{"name": "New listener on an unusual port", "severity": "warning", "expression": "network.direction equals 'listen' AND network.local_port > 1024 AND NOT network.process in ['sshd', 'node', 'docker-proxy', 'nats-server', 'postgres']"},
	{"name": "Suspiciously long DNS label", "severity": "warning", "expression": "dns.query matches '^[a-z0-9]{25,}\\.'"},
	{"name": "Tor or paste-site resolution", "severity": "warning", "expression": "dns.query ends with '.onion' OR dns.query contains 'pastebin' OR dns.query contains 'ngrok'"},
	{"name": "Failed logon for a disabled or unknown account", "severity": "warning", "expression": "logon.outcome equals 'failure' AND (logon.reason contains 'no such user' OR logon.reason contains 'disabled' OR logon.reason contains 'invalid user')"},
	{"name": "Remote interactive logon from outside the LAN", "severity": "critical", "expression": "logon.outcome equals 'success' AND logon.type in ['remote-interactive', 'ssh-password', 'ssh-publickey'] AND NOT logon.source starts with '10.' AND NOT logon.source equals 'local'"},
	{"name": "Cron or sudoers changed", "severity": "warning", "expression": "(file.path starts with '/etc/cron' OR file.path starts with '/etc/sudoers') AND file.op != 'remove'"},
}
