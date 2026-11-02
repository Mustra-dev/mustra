package server

// First-run setup.
//
// A fresh install has no credentials at all until somebody creates them.
// The alternatives were both worse: a generated password means copying a
// string out of a terminal or .env before you can log in, and a shipped
// default -- admin/password, changed on first login -- is a known
// credential that works on every deployment during the window between the
// first boot and the first login. Nobody has to be told to rotate a
// credential that never existed.
//
// The window this design does leave is the one where anyone who reaches the
// console before its owner does can claim it. That is the same trade every
// self-hosted first-run screen makes, and it is bounded: the page closes
// permanently the moment an account exists, the claim is a single atomic
// write so two people cannot both win it, and the account that was created
// is written to the audit log with the address it was created from.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// The setup token.
//
// Whoever reached /setup first used to own the deployment, and with the
// console published on the LAN or through a tunnel that is a real race. A
// fresh install now prints a one-time token to the server log at startup
// (or takes MUSTRA_SETUP_TOKEN), and /setup only opens for a browser that
// arrived through the URL carrying it: the owner has the log, the passer-by
// does not. The token lives in memory only and dies with setup.

const setupCookieName = "mustra_setup"

// prepareSetupToken runs at startup. On a deployment that is not pending
// it does nothing.
func (s *Server) prepareSetupToken(ctx context.Context) {
	if !s.setupPendingCtx(ctx) {
		return
	}
	tok := strings.TrimSpace(os.Getenv("MUSTRA_SETUP_TOKEN"))
	if len(tok) < 16 {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		tok = hex.EncodeToString(b)
	}
	s.setupToken.Store(tok)
	s.logger.Warn("FIRST-RUN SETUP: this deployment has no administrator yet. Open the console at "+
		"/setup?token=<token> to create one; nobody without this token can.",
		"token", tok, "path", "/setup?token="+tok)
}

// setupTokenOK reports whether the request carries the setup token, in the
// form field, the query string, or the cookie /setup?token= set.
func (s *Server) setupTokenOK(r *http.Request, bodyToken string) bool {
	want, _ := s.setupToken.Load().(string)
	if want == "" {
		return false
	}
	for _, cand := range []string{bodyToken, r.URL.Query().Get("token")} {
		if cand != "" && subtle.ConstantTimeCompare([]byte(cand), []byte(want)) == 1 {
			return true
		}
	}
	if c, err := r.Cookie(setupCookieName); err == nil && c.Value != "" {
		return subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
	}
	return false
}

const settingSetupCompleted = "setup.completed"

// minSetupPasswordLength is a floor, not a policy. Complexity rules push
// people towards predictable substitutions; length is what actually costs
// an attacker something, and anything more opinionated belongs to whatever
// identity provider the deployment ends up using.
const minSetupPasswordLength = 12

// setupPending reports whether this deployment has never been claimed.
//
// Three conditions, all of them: the flag is unset, no break-glass account
// is configured, and no user exists. An upgrade of a running deployment
// satisfies none of them, so the setup page cannot appear on a console that
// already has operators -- which would be a way in, not a convenience.
func (s *Server) setupPending(r *http.Request) bool { return s.setupPendingCtx(r.Context()) }

func (s *Server) setupPendingCtx(ctx context.Context) bool {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		s.logger.Error("could not read settings while checking for first-run setup", "error", err)
		return false // fail closed: no setup page rather than an open one
	}
	if settings[settingSetupCompleted] == "true" {
		return false
	}
	if settings[settingBackdoorUsername] != "" && settings[settingBackdoorPasswordHash] != "" {
		return false
	}
	n, err := s.store.CountUsers(ctx)
	if err != nil {
		s.logger.Error("could not count users while checking for first-run setup", "error", err)
		return false
	}
	return n == 0
}

// handleSetupPage serves the one-time account creation page. Once the
// deployment is claimed this is a redirect to the login it replaced, so a
// bookmarked /setup is a dead end rather than a second door.
func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if !s.setupPending(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !s.setupTokenOK(r, "") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("This deployment has not been set up yet.\n\nOpen the setup link printed in the server log " +
			"(\"FIRST-RUN SETUP\", e.g. docker compose logs server), which carries a one-time token.\n"))
		return
	}
	// Carry the token from the URL into a short-lived cookie so the form's
	// own POST (which knows nothing about it) is admitted.
	tok, _ := s.setupToken.Load().(string)
	http.SetCookie(w, &http.Cookie{Name: setupCookieName, Value: tok, Path: "/setup",
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: 3600})
	data, err := staticFS.ReadFile("static/setup.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeConsolePage(w, data)
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Confirm  string `json:"confirm"`
	// AcceptTerms is the box on the setup page: whoever claims a deployment
	// accepts the Terms of Use (TERMS.md) for it, and the audit row says so.
	AcceptTerms bool `json:"accept_terms"`
	// Token is the one-time setup token; it may instead arrive as the
	// cookie GET /setup?token= sets.
	Token string `json:"token"`
}

// handleSetupSubmit creates the first administrator.
//
// Order matters: the claim is taken before the account is created, so the
// loser of a race is told the deployment is already set up rather than
// quietly overwriting the winner's account.
func (s *Server) handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.setupPending(r) {
		writeSetupError(w, http.StatusConflict, "this deployment has already been set up; sign in instead")
		return
	}

	var req setupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeSetupError(w, http.StatusBadRequest, "could not read the form")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !s.setupTokenOK(r, req.Token) {
		s.logger.Warn("first-run setup attempted without the setup token", "from", clientIPOf(r))
		writeSetupError(w, http.StatusForbidden, "this setup needs the one-time token from the server log; open the setup link printed there")
		return
	}

	if req.Username == "" {
		writeSetupError(w, http.StatusBadRequest, "choose a username")
		return
	}
	if strings.ContainsAny(req.Username, " \t\r\n") {
		writeSetupError(w, http.StatusBadRequest, "a username cannot contain spaces")
		return
	}
	if utf8.RuneCountInString(req.Password) < minSetupPasswordLength {
		writeSetupError(w, http.StatusBadRequest,
			"use at least 12 characters — this account is the way back in when SSO is not available")
		return
	}
	if req.Password != req.Confirm {
		writeSetupError(w, http.StatusBadRequest, "the two passwords do not match")
		return
	}
	if !req.AcceptTerms {
		writeSetupError(w, http.StatusBadRequest, "accept the Terms of Use to continue")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("hashing the first administrator's password failed", "error", err)
		writeSetupError(w, http.StatusInternalServerError, "could not store that password")
		return
	}

	// One atomic write decides who owns this deployment.
	won, err := s.store.ClaimSetting(r.Context(), settingSetupCompleted, "true", req.Username)
	if err != nil {
		s.logger.Error("claiming first-run setup failed", "error", err)
		writeSetupError(w, http.StatusInternalServerError, "could not complete setup")
		return
	}
	if !won {
		writeSetupError(w, http.StatusConflict, "this deployment has already been set up; sign in instead")
		return
	}

	// From here the deployment is claimed, so a failure has to be loud: it
	// leaves a console nobody can sign in to, which is recoverable only by
	// clearing the flag.
	if err := s.store.SetSetting(r.Context(), settingBackdoorUsername, req.Username, req.Username); err != nil {
		s.logger.Error("storing the first administrator's username failed", "error", err)
		writeSetupError(w, http.StatusInternalServerError, "could not complete setup")
		return
	}
	if err := s.store.SetSetting(r.Context(), settingBackdoorPasswordHash, hash, req.Username); err != nil {
		s.logger.Error("storing the first administrator's password failed", "error", err)
		writeSetupError(w, http.StatusInternalServerError, "could not complete setup")
		return
	}
	user, err := s.store.UpsertLocalAdmin(r.Context(), req.Username, hash)
	if err != nil {
		s.logger.Error("creating the first administrator failed", "error", err)
		writeSetupError(w, http.StatusInternalServerError, "could not create the account")
		return
	}
	s.live.setBackdoorUsername(req.Username)
	s.setupToken.Store("")
	http.SetCookie(w, &http.Cookie{Name: setupCookieName, Value: "", Path: "/setup", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1})

	// Recorded with where it came from. On a deployment briefly reachable
	// before its owner got to it, this row is how you find out.
	s.audit(r.Context(), auditEvent{
		Action: "setup.complete", Actor: req.Username, Target: req.Username, Severity: "critical",
		Detail: map[string]any{"from": clientIPOf(r), "user_id": user.ID, "accepted_terms": true},
	})
	s.logger.Warn("first-run setup completed", "username", req.Username, "from", clientIPOf(r))

	writeJSONResponse(w, map[string]any{"ok": true, "username": req.Username})
}

func writeSetupError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
