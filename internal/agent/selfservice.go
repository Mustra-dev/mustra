package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/selfservice"
)

// Self Service: a small window the person using this machine can open to
// see what mustra has done to it, check in on demand, and install approved
// software.
//
// It listens on loopback only, and that alone turned out not to be a
// security model: a web page can make the user's browser POST here. Every
// request now passes selfServiceGuard (selfservice_guard.go) — Host,
// Origin, a per-launch token and a JSON content type. The local UI is
// still never trusted with authorization: the server decides what may be
// installed and answers with the package name, so this window can't be
// used to install something arbitrary.

// runSelfService serves the local window until ctx is cancelled.
func (a *Agent) runSelfService(ctx context.Context, addr string) {
	mux := http.NewServeMux()
	token := newSelfServiceToken()
	page := withSelfServiceToken(selfservice.HTML(), token)

	// The token, for the tray and menu bar helpers, which are local
	// programs rather than the window. Readable by anything that can make
	// a same-origin request here, which a cross-origin page cannot.
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		writeLocalJSON(w, map[string]any{"token": token})
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		// A nonce per response: only the window's own scripts run, so
		// operator-supplied branding text that somehow reached the DOM as
		// markup could not execute.
		nonce := newSelfServiceToken()[:32]
		w.Header().Set("Content-Security-Policy", selfServiceCSP(nonce))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(withScriptNonce(page, nonce))
	})

	// Opening the window forces a check-in, so what it shows is current
	// rather than up to a sensor interval stale.
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		a.checkInNow(r.Context())
		reply := a.askServer(r.Context(), proto.SelfServiceRequest{
			Action: "state", BrandingVersion: a.brandingVersion(),
		})
		a.applyBranding(reply)
		// The images went into the cache above; the window gets them from
		// "branding", so there is no reason to send them twice.
		reply.Branding = nil
		writeLocalJSON(w, map[string]any{
			"branding":       a.brandingForWindow(),
			"connected":      a.nc != nil && a.nc.IsConnected(),
			"server":         a.cfg.NATSURL,
			"agent_id":       a.agentID,
			"agent_version":  a.info.Version,
			"latest_version": reply.LatestAgentVersion,
			"notification":   a.notificationForWindow(),
			"survey":         a.surveyForWindow(),
			"hostname":       a.info.Hostname,
			"os":             runtime.GOOS,
			"os_name":        osName(),
			"site":           a.info.Site,
			"user":           windowUser(),
			"no_remote_code": a.noRemoteCode,
			"reply":          reply,
		})
	})

	// The branding alone, answered from the cache without asking the
	// server, so the window can paint in the organisation's look straight
	// away instead of waiting on a state round-trip that may take seconds.
	mux.HandleFunc("GET /api/branding", func(w http.ResponseWriter, r *http.Request) {
		writeLocalJSON(w, map[string]any{"branding": a.brandingForWindow()})
	})

	// What the tray helper polls. Deliberately separate from /api/state:
	// that one checks in with the control plane on every call, which is the
	// right thing for a window somebody just opened and the wrong thing
	// entirely for a poll running every few seconds on every endpoint.
	// This answers from memory and touches nothing.
	mux.HandleFunc("GET /api/notification", func(w http.ResponseWriter, r *http.Request) {
		// Only the tray polls this. Recording it here means the agent knows
		// a better notifier is present without the tray having to announce
		// itself, and the knowledge expires on its own if the tray stops.
		a.tray.mark()
		writeLocalJSON(w, map[string]any{
			"notification":  a.notificationForWindow(),
			"survey":        a.surveyForWindow(),
			"agent_version": a.info.Version,
			"hostname":      a.info.Hostname,
			"connected":     a.nc != nil && a.nc.IsConnected(),
		})
	})

	mux.HandleFunc("POST /api/checkin", func(w http.ResponseWriter, r *http.Request) {
		a.checkInNow(r.Context())
		writeLocalJSON(w, map[string]any{"ok": true, "checked_in_at": time.Now().Format(time.RFC3339)})
	})

	mux.HandleFunc("POST /api/install", a.handleSelfServiceInstall)

	// Updating the agent is offered, never applied on its own: a fleet that
	// silently replaces its own agent binary is a fleet that can silently
	// break. The server decides the command; this only asks to be updated.
	// Answering an end-user notification. The answer is the whole point: a
	// restart prompt nobody can prove was postponed twice is
	// indistinguishable from one that was never shown.
	mux.HandleFunc("POST /api/notification-response", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Action          string `json:"action"`
			PostponeMinutes int    `json:"postpone_minutes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeLocalJSON(w, map[string]any{"ok": false, "error": "bad request"})
			return
		}
		if problem := a.answerNotification(context.WithoutCancel(r.Context()), body.Action, body.PostponeMinutes); problem != "" {
			writeLocalJSON(w, map[string]any{"ok": false, "error": problem})
			return
		}
		writeLocalJSON(w, map[string]any{"ok": true})
	})

	// Answering a survey. Declining is a first-class answer: it is the only
	// thing that distinguishes a question nobody wanted from one nobody was
	// asked, and without that difference a response rate means nothing.
	mux.HandleFunc("POST /api/survey-response", func(w http.ResponseWriter, r *http.Request) {
		var body proto.SurveyAnswers
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeLocalJSON(w, map[string]any{"ok": false, "error": "bad request"})
			return
		}
		body.User = localUser()
		if problem := a.answerSurvey(context.WithoutCancel(r.Context()), body); problem != "" {
			writeLocalJSON(w, map[string]any{"ok": false, "error": problem})
			return
		}
		writeLocalJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("POST /api/update-agent", func(w http.ResponseWriter, r *http.Request) {
		auth := a.askServer(r.Context(), proto.SelfServiceRequest{
			Action: "update_agent", User: localUser(),
		})
		if !auth.OK {
			writeLocalJSON(w, map[string]any{"ok": false,
				"error": firstNonEmpty(auth.Error, "the server did not authorize an update")})
			return
		}
		// The same verified path the console uses: the signed offer is
		// checked against the pinned key and applied by the agent's own
		// detached updater, never by a server-supplied command.
		out, err := a.startVerifiedUpdate(context.WithoutCancel(r.Context()), auth.Update)
		if err != nil {
			a.logger.Error("could not start the agent update", "error", err)
			writeLocalJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		a.logger.Info("agent self-update started", "detail", out, "user", localUser())
		writeLocalJSON(w, map[string]any{"ok": true,
			"message": out + " — this window will disconnect for a moment while the agent restarts"})
	})

	mux.HandleFunc("POST /api/request", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ItemID string `json:"item_id"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeLocalJSON(w, map[string]any{"ok": false, "error": "bad request"})
			return
		}
		reply := a.askServer(r.Context(), proto.SelfServiceRequest{
			Action: "request", ItemID: body.ItemID, Reason: body.Reason, User: localUser(),
		})
		writeLocalJSON(w, map[string]any{"ok": reply.OK, "message": reply.Message, "error": reply.Error})
	})

	srv := &http.Server{Addr: addr, Handler: newSelfServiceGuard(addr, token, mux), ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		a.logger.Warn("self service window unavailable", "addr", addr, "error", err)
		return
	}
	a.logger.Info("self service window listening", "url", "http://"+addr+"/")
	served := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
		case <-served:
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		a.logger.Warn("self service window stopped", "error", err)
	}
	close(served)
	// Serve returns as soon as Shutdown closes the listener, while handlers
	// may still be using the store and the connection. Return only once
	// they are done, so an in-process restart finds the port free and the
	// old runtime quiet.
	<-shutdownDone
}

// askServer does one Self Service request/reply over NATS.
func (a *Agent) askServer(ctx context.Context, req proto.SelfServiceRequest) proto.SelfServiceReply {
	if a.nc == nil || a.agentID == "" {
		return proto.SelfServiceReply{Error: "not connected to the mustra server yet"}
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return proto.SelfServiceReply{Error: err.Error()}
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	msg, err := a.nc.RequestWithContext(rctx, bnats.SelfService(a.agentID), payload)
	if err != nil {
		return proto.SelfServiceReply{Error: "the mustra server didn't answer: " + err.Error()}
	}
	var reply proto.SelfServiceReply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return proto.SelfServiceReply{Error: "malformed reply from the server"}
	}
	return reply
}

// checkInNow publishes a heartbeat, fresh facts and every sensor
// immediately, so opening the window brings this device up to date rather
// than waiting for the next interval.
func (a *Agent) checkInNow(ctx context.Context) {
	a.sendHeartbeat(ctx)
	a.sendFacts(ctx)
	for kind, collect := range map[proto.SensorKind]func(context.Context) (any, error){
		proto.SensorInstalledApps: func(ctx context.Context) (any, error) { return collectInstalledApps(ctx) },
		proto.SensorPatches:       func(ctx context.Context) (any, error) { return collectPatches(ctx, a.nc, a.agentID) },
		proto.SensorHardware:      func(ctx context.Context) (any, error) { return collectHardware(ctx) },
		proto.SensorDisks:         func(ctx context.Context) (any, error) { return collectDisks(ctx) },
	} {
		a.collectAndPublishSensor(ctx, kind, collect)
	}
}

// windowUser names the person the window greets: whoever is signed in at
// the computer, falling back to the agent's own account when nobody is
// (a server, or a login screen).
func windowUser() string {
	if u := interactiveUser(); u != "" {
		return u
	}
	return localUser()
}

func localUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	for _, key := range []string{"SUDO_USER", "USER", "USERNAME"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return "unknown"
}

func writeLocalJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// handleSelfServiceInstall installs an item the server authorizes. An endpoint
// in inventory-and-patching mode says no before asking: the server would record
// a run, and answer "queued" for a job that can never start here.
func (a *Agent) handleSelfServiceInstall(w http.ResponseWriter, r *http.Request) {
	if a.noRemoteCode {
		writeLocalJSON(w, map[string]any{"ok": false, "error": errNoRemoteCode.Error()})
		return
	}
	var body struct {
		ItemID string `json:"item_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeLocalJSON(w, map[string]any{"ok": false, "error": "bad request"})
		return
	}
	auth := a.askServer(r.Context(), proto.SelfServiceRequest{
		Action: "install", ItemID: body.ItemID, User: localUser(),
	})
	if auth.OK && auth.Deploy != nil {
		if err := a.store.acceptDeploy(*auth.Deploy); err != nil {
			writeLocalJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeLocalJSON(w, map[string]any{"ok": true, "output": "Deployment queued; progress appears in Activity", "run_id": auth.RunID})
		return
	}
	if !auth.OK || auth.Package == "" {
		writeLocalJSON(w, map[string]any{"ok": false, "error": firstNonEmpty(auth.Error, "install was not authorized")})
		return
	}

	a.softwareMu.Lock()
	defer a.softwareMu.Unlock()
	pending, err := a.store.deployStates()
	if err != nil || len(pending) > 0 {
		detail := "A software deployment is already pending; try again after it completes"
		a.askServer(r.Context(), proto.SelfServiceRequest{Action: "install_result", RunID: auth.RunID, OK: false, Detail: detail})
		writeLocalJSON(w, map[string]any{"ok": false, "error": detail})
		return
	}
	// Self Service installs use the agent's default budget: the server
	// hands back a package name to run, not the package's own timeout.
	out, err := runSoftwareCommand(r.Context(), auth.Package, 0)
	result := proto.SelfServiceRequest{
		Action: "install_result", RunID: auth.RunID, OK: err == nil, Detail: out,
	}
	if err != nil {
		result.Detail = err.Error() + "\n" + out
	}
	a.askServer(context.WithoutCancel(r.Context()), result)

	writeLocalJSON(w, map[string]any{"ok": err == nil, "output": out,
		"error": errString(err), "command": auth.Package})
}
