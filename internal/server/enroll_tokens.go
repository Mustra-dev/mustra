package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Enrollment tokens: what an administrator hands to a new endpoint instead
// of the bus password. A token is shown once, stored as a hash, expires,
// and enrolls at most max_uses agents — one by default; more for a GPO or
// MDM rollout where one command line goes to many machines. A leaked
// token enrolls a bounded number of extra endpoints into the console,
// visibly; it gives no access to any existing agent's subjects.

const (
	tokenPrefix         = "mte_"
	maxTokenUses        = 1000
	maxTokenLifetime    = 30 * 24 * time.Hour
	defaultTokenTTL     = 24 * time.Hour
	pushTokenTTL        = 15 * time.Minute
	enrollTokenRandSize = 32
)

func newEnrollToken() string {
	b := make([]byte, enrollTokenRandSize)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// mintEnrollToken creates a token and returns it with its record.
func (s *Server) mintEnrollToken(ctx context.Context, label, site, actor string, maxUses int, ttl time.Duration) (string, store.EnrollmentToken, error) {
	token := newEnrollToken()
	t := store.EnrollmentToken{
		ID: newID("etk-"), Label: label, Site: site, MaxUses: maxUses, CreatedBy: actor,
		ExpiresAt: time.Now().Add(ttl).UTC(),
	}
	if err := s.store.CreateEnrollmentToken(ctx, t, hashToken(token)); err != nil {
		return "", store.EnrollmentToken{}, err
	}
	t.CreatedAt = time.Now().UTC()
	return token, t, nil
}

// enrollTokenRow is an entry of what GET /api/enrollment-tokens answers.
type enrollTokenRow struct {
	store.EnrollmentToken
	Usable bool `json:"usable"`
}

// listEnrollTokensResponse is what GET /api/enrollment-tokens answers.
type listEnrollTokensResponse struct {
	Tokens []enrollTokenRow `json:"tokens"`
}

func (s *Server) handleListEnrollTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.store.ListEnrollmentTokens(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]enrollTokenRow, 0, len(tokens))
	now := time.Now()
	for _, t := range tokens {
		out = append(out, enrollTokenRow{t, t.Usable(now)})
	}
	writeJSONResponse(w, listEnrollTokensResponse{Tokens: out})
}

// createEnrollTokenRequest is the body of POST /api/enrollment-tokens.
type createEnrollTokenRequest struct {
	Label        string  `json:"label"`
	Site         string  `json:"site"`
	MaxUses      int     `json:"max_uses"`
	ExpiresHours float64 `json:"expires_hours"`
	// NoRemoteCode installs in inventory-and-patching mode: the endpoint
	// refuses code from the server, and only an administrator on it can undo
	// that.
	NoRemoteCode bool `json:"no_remote_code"`
}

// createEnrollTokenResponse is what POST /api/enrollment-tokens answers:
// the install commands, or why they could not be built.
type createEnrollTokenResponse struct {
	Commands      map[string]string     `json:"commands,omitempty"`
	CommandsError string                `json:"commands_error,omitempty"`
	Record        store.EnrollmentToken `json:"record"`
	Token         string                `json:"token"`
}

func (s *Server) handleCreateEnrollToken(w http.ResponseWriter, r *http.Request) {
	var req createEnrollTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if len(req.Label) > 120 {
		http.Error(w, "label is too long", http.StatusBadRequest)
		return
	}
	if req.Site != "" && !validSite(req.Site) {
		http.Error(w, "site may contain only letters, digits, '-' and '_' (at most 64)", http.StatusBadRequest)
		return
	}
	if req.MaxUses == 0 {
		req.MaxUses = 1
	}
	if req.MaxUses < 1 || req.MaxUses > maxTokenUses {
		http.Error(w, "max_uses must be between 1 and 1000", http.StatusBadRequest)
		return
	}
	ttl := defaultTokenTTL
	if req.ExpiresHours != 0 {
		ttl = time.Duration(req.ExpiresHours * float64(time.Hour))
	}
	if ttl < time.Minute || ttl > maxTokenLifetime {
		http.Error(w, "expiry must be between one minute and 30 days", http.StatusBadRequest)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	token, t, err := s.mintEnrollToken(r.Context(), req.Label, req.Site, who, req.MaxUses, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{
		Action: "agent.enroll_token.create", Actor: who, Target: firstNonEmptyString(req.Label, t.ID), Severity: "notice",
		Detail: map[string]any{"id": t.ID, "max_uses": t.MaxUses, "expires_at": t.ExpiresAt, "site": t.Site, "no_remote_code": req.NoRemoteCode},
	})
	resp := createEnrollTokenResponse{Token: token, Record: t}
	// The one-liners are built here, from the configured public URL, so the
	// page never has to guess the console's address from its own location.
	if base, err := s.agentPublicURL(r.Context()); err == nil {
		if shSum, ps1Sum, err := s.installScriptHashes(r.Context(), t.Site, token, req.NoRemoteCode); err == nil {
			resp.Commands = installCommands(base, token, t.Site, req.NoRemoteCode, shSum, ps1Sum)
		} else {
			resp.CommandsError = err.Error()
		}
	} else {
		resp.CommandsError = err.Error()
	}
	writeJSONResponse(w, resp)
}

// installCommands renders the copy-paste one-liners. The token travels in a
// header rather than the URL, so it does not land in proxy and CDN access logs;
// the site, which is not secret, stays in the query.
//
// A command is the one thing an administrator carries from a console they signed
// in to, so it pins what it runs. It downloads the script to a file and checks
// its hash before running anything, and the script holds the hash of everything
// it downloads (installPins), so the whole install is verified whatever sits
// between the endpoint and the server. A pinned command stops working when the
// script would change: an upgrade, or a change to the uninstall password. It
// says so, and fails before touching anything. The "_plain" forms keep working,
// for automation that stores a command and accepts trusting the connection.
func installCommands(base, token, site string, noRemoteCode bool, shSum, ps1Sum string) map[string]string {
	var params []string
	if site != "" {
		params = append(params, "site="+site)
	}
	if noRemoteCode {
		params = append(params, "no_remote_code=1")
	}
	q := ""
	if len(params) > 0 {
		q = "?" + strings.Join(params, "&")
	}
	auth := "Authorization: Bearer " + token
	const stale = "mustra: this install command no longer matches the server: it may be out of date. Create a new enrollment token. Nothing was changed."
	shPinned := func(run string) string {
		return `f=$(mktemp) && curl -fsSL -H ` + shQuote(auth) + ` ` + shQuote(base+"/install.sh"+q) + ` -o "$f" && ` +
			`{ [ "$( (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f") | cut -d ' ' -f1)" = ` + shQuote(shSum) + ` ] || { echo ` + shQuote(stale) + ` >&2; false; }; } && ` +
			run + ` "$f"; s=$?; rm -f "$f"; (exit $s)`
	}
	irm := "irm -UseBasicParsing -Headers @{Authorization=" + psQuoteString("Bearer "+token) + "} " + psQuoteString(base+"/install.ps1"+q)
	return map[string]string{
		"unix": shPinned("sudo bash"),
		// Alpine has neither bash, curl nor sudo out of the box, and is
		// usually administered as root.
		"alpine": "apk add --no-cache bash curl && " + shPinned("bash"),
		"windows": `$f=Join-Path $env:TEMP ('mustra-'+[guid]::NewGuid()+'.ps1'); ` + irm + ` -OutFile $f; ` +
			`if((Get-FileHash $f -Algorithm SHA256).Hash -ne ` + psQuoteString(ps1Sum) + `){Remove-Item $f; throw ` + psQuoteString(stale) + `}; ` +
			`$s=[IO.File]::ReadAllText($f); Remove-Item $f; iex $s`,
		"unix_plain":    "curl -fsSL -H " + shQuote(auth) + " " + shQuote(base+"/install.sh"+q) + " | sudo bash",
		"alpine_plain":  "apk add --no-cache bash curl && curl -fsSL -H " + shQuote(auth) + " " + shQuote(base+"/install.sh"+q) + " | bash",
		"windows_plain": irm + " | iex",
	}
}

// revokeEnrollTokenResponse is what DELETE /api/enrollment-tokens/{id}
// answers.
type revokeEnrollTokenResponse struct {
	OK bool `json:"ok"`
}

func (s *Server) handleRevokeEnrollToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ok, err := s.store.RevokeEnrollmentToken(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "no such active token", http.StatusNotFound)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "agent.enroll_token.revoke", Actor: auth.CurrentUser(r.Context()).Username,
		Target: id, Severity: "notice"})
	writeJSONResponse(w, revokeEnrollTokenResponse{OK: true})
}

// listAgentIdentitiesResponse is what GET /api/agent-identities answers.
type listAgentIdentitiesResponse struct {
	Agents           []store.AgentIdentity `json:"agents"`
	IdentityEnforced bool                  `json:"identity_enforced"`
	LegacyAllowed    bool                  `json:"legacy_allowed"`
}

func (s *Server) handleListAgentIdentities(w http.ResponseWriter, r *http.Request) {
	ids, err := s.store.ListAgentIdentities(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listAgentIdentitiesResponse{Agents: ids, IdentityEnforced: s.identityEnforced(),
		LegacyAllowed: s.legacyAllowed(r.Context())})
}

// revokeAgentCredentialResponse is what POST
// /api/agents/{id}/revoke-credential answers.
type revokeAgentCredentialResponse struct {
	OK bool `json:"ok"`
	// Disconnected is how many live broker connections of the agent were
	// closed at once; the broker refuses its reconnects.
	Disconnected int `json:"disconnected"`
	// Pending, when set, says why the agent is not cut off yet: it is
	// refused only when its current authorization expires (within an
	// hour).
	Pending string `json:"pending,omitempty"`
}

// handleRevokeAgentCredential removes an agent's own credential and closes
// its live broker connections, so it is cut off at once: its reconnect
// is refused until it is enrolled again with a token. Without the
// broker's system account (MUSTRA_NATS_SYS_PASSWORD) the connection lasts
// until its JWT expires, at most an hour.
func (s *Server) handleRevokeAgentCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !bnats.ValidAgentID(id) {
		http.Error(w, "invalid agent id", http.StatusBadRequest)
		return
	}
	ok, err := s.store.RevokeAgentCredential(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "that agent has no credential", http.StatusNotFound)
		return
	}
	resp := revokeAgentCredentialResponse{OK: true}
	kctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	n, kerr := s.kickAgentConnections(kctx, id)
	cancel()
	resp.Disconnected = n
	if kerr != nil {
		resp.Pending = kerr.Error()
		s.logger.Warn("revoked agent not disconnected at once", "agent_id", id, "error", kerr)
	}
	s.audit(r.Context(), auditEvent{Action: "agent.credential.revoke", Actor: auth.CurrentUser(r.Context()).Username,
		Target: id, AgentID: id, Severity: "warning", Detail: map[string]any{"disconnected": n, "pending": resp.Pending}})
	writeJSONResponse(w, resp)
}
