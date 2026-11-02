package server

// Remote desktop sign-in without typing a password, and the record of it.
//
// Temporary accounts (JIT): with the setting on, opening a Guacamole
// session asks the endpoint's agent for a local administrator made for
// this session alone — a minted name, a random password (RDP, VNC) or a
// key pair (SSH) — and puts it in the signed connection ticket, so
// Guacamole signs in by itself and nobody, the person connecting
// included, sees the secret. When the session ends the server asks the
// agent to remove the account and keeps asking until it confirms. The
// agent holds its own deadline too and removes the account by itself
// past it, so neither a lost server nor an endpoint that went offline
// leaves an administrator behind for longer than the session could last.
//
// The end of a session is seen, not guessed: this server proxies
// Guacamole's tunnel, so while a tunnel is open it refreshes the
// session's last_seen_at, and a session whose tunnel has been closed for
// remoteIdleGrace is ended (a reload or a network blip reconnects within
// it). Several servers behind one database agree, because the clock is
// in the row.
//
// Recording: guacd writes every session's screen (and an SSH session's
// text) to a volume this server reads; the session row names the file.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingRemoteJIT       = "remote.jit"       // "" (off) | offer | always
	settingRemoteRecording = "remote.recording" // "" (on) | off

	// remoteJITMaxSession bounds a temporary account when no Jump Gate
	// window does; remoteJITSlack is how much longer the agent's own
	// deadline is than the session's, so the server's removal comes first.
	remoteJITMaxSession = 8 * time.Hour
	remoteJITSlack      = 10 * time.Minute

	remoteIdleGrace     = 3 * time.Minute
	remoteTouchInterval = 30 * time.Second

	// remoteJITAlertAfter is how many failed removals raise a notification.
	remoteJITAlertAfter = 3

	// remoteRecordingsDir is where guacd writes, as this server sees it
	// (deploy/docker-compose.yml mounts the volume read-only there).
	remoteRecordingsDefault = "/remote-recordings/recordings"
	// guacdRecordingsDir is the same directory as guacd sees it.
	guacdRecordingsDir = "/home/guacd/recordings"
)

var remoteSessionIDPattern = regexp.MustCompile(`^rs[0-9a-f]{32}$`)

func remoteRecordingsDir() string {
	if d := os.Getenv("MUSTRA_REMOTE_RECORDINGS_DIR"); d != "" {
		return d
	}
	return remoteRecordingsDefault
}

// remoteCredentials is what a connection ticket signs in with.
type remoteCredentials struct {
	Username   string
	Password   string
	PrivateKey string // PEM, SSH only
}

// jitAlphabet leaves out quotes, backslashes and lookalikes: the password
// passes through JSON, dscl and RDP, and is never typed, but nothing gains
// from characters that need escaping.
const (
	jitLower   = "abcdefghijkmnopqrstuvwxyz"
	jitUpper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	jitDigits  = "23456789"
	jitSymbols = "!#%+-=?@^_~"
)

func randomFrom(alphabet string, n int) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		out[i] = alphabet[k.Int64()]
	}
	return string(out)
}

// newJITUsername mints the name the agent accepts: mustra- and eight of
// [a-z0-9], fifteen characters, inside Windows' twenty.
func newJITUsername() string {
	return "mustra-" + randomFrom("abcdefghijklmnopqrstuvwxyz0123456789", 8)
}

// newJITPassword is 24 characters with every class Windows' complexity
// rule asks for, shuffled so the classes are not in fixed places.
func newJITPassword() string {
	all := jitLower + jitUpper + jitDigits + jitSymbols
	p := []byte(randomFrom(jitLower, 1) + randomFrom(jitUpper, 1) + randomFrom(jitDigits, 1) + randomFrom(jitSymbols, 1) + randomFrom(all, 20))
	for i := len(p) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		p[i], p[j.Int64()] = p[j.Int64()], p[i]
	}
	return string(p)
}

// newJITKeyPair returns an RSA key in PKCS#1 PEM, the format every guacd
// build reads, and its authorized_keys line.
func newJITKeyPair() (privatePEM, authorized string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return "", "", err
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	authorized = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " mustra-jit"
	return privatePEM, authorized, nil
}

// errJITRefused is an endpoint's own "no" (as opposed to no answer): the
// agent undid whatever it had made, so there is nothing to remove.
var errJITRefused = errors.New("refused")

func remoteTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// useJIT says whether this opening signs in with a temporary account.
func useJIT(c remoteConfig, asked bool) bool {
	if c.Provider != "guacamole" {
		return false
	}
	switch c.JIT {
	case "always":
		return true
	case "offer":
		return asked
	}
	return false
}

// createJITAccount asks the endpoint for the session's account. The
// session row naming it is written first, by the caller, so an account
// the agent made but whose reply was lost is still removed.
func (s *Server) createJITAccount(ctx context.Context, target store.AgentRecord, protocol, sessionID, username string, deadline time.Time) (remoteCredentials, error) {
	creds := remoteCredentials{Username: username}
	job := proto.JITAccountJob{Username: username, ExpiresAt: deadline.Add(remoteJITSlack), SessionID: sessionID}
	if protocol == "ssh" {
		priv, pub, err := newJITKeyPair()
		if err != nil {
			return creds, err
		}
		creds.PrivateKey, job.AuthorizedKey = priv, pub
	} else {
		creds.Password = newJITPassword()
		job.Password = creds.Password
	}
	payload, err := json.Marshal(proto.AgentCommand{Cmd: "jit_create", JIT: &job})
	if err != nil {
		return creds, err
	}
	rctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(target.AgentID), payload)
	if err != nil {
		return creds, fmt.Errorf("the endpoint did not answer: %w", err)
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &res); err != nil {
		return creds, errors.New("malformed answer from the endpoint")
	}
	if !res.OK {
		if strings.HasPrefix(res.Error, "unknown command") {
			return creds, fmt.Errorf("this endpoint's agent is too old for temporary accounts (0.57.40 or newer): %w", errJITRefused)
		}
		return creds, fmt.Errorf("the endpoint could not create a temporary account: %s: %w", res.Error, errJITRefused)
	}
	if res.Output != "" {
		s.logger.Info("temporary account notes", "host", target.Hostname, "username", username, "notes", res.Output)
	}
	return creds, nil
}

// removeJITAccounts asks endpoints to remove the accounts of ended
// sessions, backing off per session while an endpoint is offline or
// refuses, and raising a notification once a removal keeps failing.
func (s *Server) removeJITAccounts(ctx context.Context) {
	due, err := s.store.RemoteJITToRemove(ctx)
	if err != nil {
		s.logger.Warn("listing temporary accounts to remove failed", "error", err)
		return
	}
	for _, rs := range due {
		out, err := s.requestJITRemove(ctx, rs.AgentID, rs.JITUsername)
		if err == nil {
			if err := s.store.RemoteJITRemoved(ctx, rs.ID); err != nil {
				s.logger.Warn("recording a temporary account's removal failed", "session", rs.ID, "error", err)
				continue
			}
			s.audit(ctx, auditEvent{Action: "remote.jit_removed", Actor: "system", Target: rs.Hostname, AgentID: rs.AgentID, Severity: "notice",
				Detail: map[string]any{"session_id": rs.ID, "account": rs.JITUsername, "user": rs.Username, "notes": out}})
			continue
		}
		retry := time.Duration(1<<min(rs.JITAttempts, 5)) * time.Minute // 1, 2, 4 … 32 minutes
		n, ferr := s.store.RemoteJITFailed(ctx, rs.ID, err.Error(), retry)
		if ferr != nil {
			s.logger.Warn("recording a failed removal failed", "session", rs.ID, "error", ferr)
			continue
		}
		s.logger.Warn("removing a temporary account failed; will retry", "host", rs.Hostname, "account", rs.JITUsername, "attempt", n, "error", err)
		if n == remoteJITAlertAfter {
			s.audit(ctx, auditEvent{Action: "remote.jit_remove_failed", Actor: "system", Target: rs.Hostname, AgentID: rs.AgentID, Severity: "warning",
				Detail: map[string]any{"session_id": rs.ID, "account": rs.JITUsername, "error": err.Error(), "attempts": n}})
			s.notify(ctx, "warning", "remote",
				"Temporary account not yet removed from "+rs.Hostname,
				fmt.Sprintf("%s is still on %s after %d attempts (%s). Mustra keeps trying, and the agent removes it by itself at its deadline.", rs.JITUsername, rs.Hostname, n, err),
				"/endpoint/"+rs.AgentID)
		}
	}
}

func (s *Server) requestJITRemove(ctx context.Context, agentID, username string) (string, error) {
	payload, err := json.Marshal(proto.AgentCommand{Cmd: "jit_remove", JIT: &proto.JITAccountJob{Username: username}})
	if err != nil {
		return "", err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(agentID), payload)
	if err != nil {
		return "", fmt.Errorf("the endpoint did not answer: %w", err)
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &res); err != nil {
		return "", errors.New("malformed answer from the endpoint")
	}
	if !res.OK {
		return res.Output, errors.New(res.Error)
	}
	return res.Output, nil
}

// remoteTunnels counts open tunnels per session in this process, so two
// tabs on one session refresh it once, and only the last to close stops.
type remoteTunnels struct {
	mu   sync.Mutex
	open map[string]*openTunnel
}

type openTunnel struct {
	n    int
	stop chan struct{}
}

// trackGuacamoleTunnel keeps a session's last_seen_at fresh for as long
// as the request (a WebSocket tunnel, which lasts the whole connection)
// is being served, and stamps it once more when it closes, so the idle
// grace counts from the moment the desktop went away. It returns the
// function to call when the request is done.
func (s *Server) trackGuacamoleTunnel(r *http.Request) func() {
	if !strings.HasSuffix(r.URL.Path, "/websocket-tunnel") {
		return func() {}
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		return func() {}
	}
	id, err := s.store.RemoteSessionByTokenHash(r.Context(), remoteTokenHash(token))
	if err != nil || id == "" {
		return func() {}
	}
	ctx := context.WithoutCancel(r.Context())
	_ = s.store.TouchRemoteSession(ctx, id)
	s.tunnels.mu.Lock()
	if s.tunnels.open == nil {
		s.tunnels.open = map[string]*openTunnel{}
	}
	t := s.tunnels.open[id]
	if t == nil {
		t = &openTunnel{stop: make(chan struct{})}
		s.tunnels.open[id] = t
		go func(stop <-chan struct{}) {
			tick := time.NewTicker(remoteTouchInterval)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					if err := s.store.TouchRemoteSession(ctx, id); err != nil {
						s.logger.Warn("refreshing a remote session failed", "session", id, "error", err)
					}
				}
			}
		}(t.stop)
	}
	t.n++
	s.tunnels.mu.Unlock()
	return func() {
		s.tunnels.mu.Lock()
		t.n--
		if t.n == 0 {
			close(t.stop)
			delete(s.tunnels.open, id)
		}
		s.tunnels.mu.Unlock()
		_ = s.store.TouchRemoteSession(ctx, id)
	}
}

// remoteSessionRow is an entry of what GET /api/remote/sessions answers.
type remoteSessionRow struct {
	store.RemoteSession
	HasScreen     bool `json:"has_screen"`
	HasTypescript bool `json:"has_typescript"`
}

// GET /api/remote/sessions: recent remote desktop sessions, with their
// temporary accounts and recordings.
func (s *Server) handleListRemoteSessions(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListRemoteSessions(r.Context(), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]remoteSessionRow, 0, len(list))
	for _, rs := range list {
		x := remoteSessionRow{RemoteSession: rs}
		if rs.Recording != "" {
			x.HasScreen = fileExists(filepath.Join(remoteRecordingsDir(), rs.Recording))
			x.HasTypescript = fileExists(filepath.Join(remoteRecordingsDir(), rs.Recording+".typescript"))
		}
		out = append(out, x)
	}
	writeJSONResponse(w, out)
}

// GET /api/remote/sessions/{id}/recording?kind=screen|typescript|timing
// downloads a session's recording. Viewing one is audited, as reading a
// shell transcript is.
func (s *Server) handleRemoteRecording(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !remoteSessionIDPattern.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	rs, err := s.store.GetRemoteSession(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rs == nil || rs.Recording == "" {
		http.NotFound(w, r)
		return
	}
	name := rs.Recording // the session ID, written by this server; never from the request
	ext, ctype := "", "application/octet-stream"
	switch kind := r.URL.Query().Get("kind"); kind {
	case "", "screen":
		ext = ".guac"
	case "typescript":
		name += ".typescript"
		ctype = "text/plain; charset=utf-8"
	case "timing":
		name += ".typescript.timing"
		ctype = "text/plain; charset=utf-8"
	default:
		http.Error(w, "kind must be screen, typescript or timing", http.StatusBadRequest)
		return
	}
	f, err := os.Open(filepath.Join(remoteRecordingsDir(), name))
	if err != nil {
		http.Error(w, "the recording is not available on this server (see docs/REMOTE-ACCESS.md, Recording)", http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "remote.recording_view", Actor: auth.CurrentUser(r.Context()).Username,
		Target: rs.Hostname, AgentID: rs.AgentID, Severity: "info", Detail: map[string]any{"session_id": rs.ID, "kind": r.URL.Query().Get("kind")}})
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", rs.Hostname+"-"+name+ext))
	http.ServeContent(w, r, "", fi.ModTime(), f)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// openGuacamole opens a Guacamole session: the session row, then the
// temporary account if one is wanted, then the signed ticket. The row
// comes first so that whatever happens after — an endpoint that made the
// account but whose answer was lost, a Guacamole that refused the ticket —
// the account is on record and removed. Fail closed: a session the server
// could not record is not opened.
func (s *Server) openGuacamole(ctx context.Context, c remoteConfig, target store.AgentRecord, protocol, addr, port, reason, grantID string,
	expires *time.Time, jit, localAccount bool) (sessionID, jitName, openURL string, err error) {
	sessionID = newID("rs")
	rec := store.RemoteSession{ID: sessionID, AgentID: target.AgentID, Hostname: target.Hostname, Username: auth.CurrentUser(ctx).Username,
		Protocol: protocol, Provider: "guacamole", GrantID: grantID, ExpiresAt: expires, Reason: reason}
	if c.Record {
		rec.Recording = sessionID
	}
	deadline := time.Now().Add(remoteJITMaxSession)
	if expires != nil && expires.Before(deadline) {
		deadline = *expires
	}
	if jit {
		jitName = newJITUsername()
		rec.JITUsername, rec.JITState = jitName, "active"
		// The account's lifetime bounds the session when no window does.
		rec.ExpiresAt = &deadline
	}
	if err := s.store.CreateRemoteSession(ctx, rec); err != nil {
		return "", "", "", fmt.Errorf("could not record the session: %w", err)
	}
	fail := func(why string, e error) (string, string, string, error) {
		if errors.Is(e, errJITRefused) {
			_ = s.store.RemoteJITNotCreated(ctx, sessionID)
		}
		if err := s.store.EndRemoteSession(ctx, sessionID, why); err != nil {
			s.logger.Warn("ending a session that failed to open failed", "session", sessionID, "error", err)
		}
		s.audit(ctx, auditEvent{Action: "remote.open_failed", Actor: rec.Username, Target: target.Hostname, AgentID: target.AgentID, Severity: "warning",
			Detail: map[string]any{"session_id": sessionID, "protocol": protocol, "account": jitName, "stage": why, "error": e.Error()}})
		return "", "", "", e
	}
	var creds remoteCredentials
	if jit {
		if creds, err = s.createJITAccount(ctx, target, protocol, sessionID, jitName, deadline); err != nil {
			return fail("temporary account failed", err)
		}
		s.audit(ctx, auditEvent{Action: "remote.jit_created", Actor: rec.Username, Target: target.Hostname, AgentID: target.AgentID, Severity: "notice",
			Detail: map[string]any{"session_id": sessionID, "account": jitName, "protocol": protocol, "expires_at": deadline}})
	}
	domain := ""
	if protocol == "rdp" && !localAccount && !jit {
		domain = s.signInDomain(ctx, target.AgentID)
	}
	openURL, token, err := s.guacamoleTicket(ctx, c, target, protocol, addr, port, domain, creds, rec.Recording)
	if err != nil {
		return fail("could not open", err)
	}
	sealed, err := s.sealSetting(remoteSessionTokenAAD, token)
	if err == nil {
		err = s.store.SetRemoteSessionToken(ctx, sessionID, sealed, remoteTokenHash(token))
	}
	if err != nil {
		_ = s.guacamoleLogout(ctx, c, token)
		return fail("could not record", fmt.Errorf("could not record the session: %w", err))
	}
	return sessionID, jitName, openURL, nil
}
