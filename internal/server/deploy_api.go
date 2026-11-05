package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// requireVault is the common guard for every deploy-vault/push route.
func (s *Server) requireVault(w http.ResponseWriter) bool {
	if s.vault == nil {
		http.Error(w, "the credential vault is not configured — set MUSTRA_CREDENTIAL_ENCRYPTION_KEY on the server", http.StatusServiceUnavailable)
		return false
	}
	return true
}

type scanRequest struct {
	CIDR string `json:"cidr" api:"required"`
}

// deployScanResponse is what POST /api/deploy/scan answers.
type deployScanResponse struct {
	Results []ScanResult `json:"results"`
}

// handleDeployScan runs an explicit, opt-in TCP-22 sweep of one CIDR —
// never automatic, never scheduled. See internal/server/netscan.go.
func (s *Server) handleDeployScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.CIDR == "" {
		http.Error(w, "cidr is required, e.g. \"10.0.0.0/24\"", http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	s.logger.Info("network scan requested", "cidr", req.CIDR, "requested_by", u.Username)

	results, err := scanSubnet(r.Context(), req.CIDR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.annotateWithKnownAgents(r.Context(), results)
	writeJSONResponse(w, deployScanResponse{Results: results})
}

// deployAutoScanResponse is what POST /api/deploy/autoscan answers.
type deployAutoScanResponse struct {
	CIDR    string       `json:"cidr"`
	Results []ScanResult `json:"results"`
}

// handleDeployAutoScan is the "Auto scan" button: no CIDR input needed —
// it guesses the server's own LAN subnet (see detectLocalCIDR) and scans
// that. Still opt-in (a button click), never scheduled; just skips the
// "type your subnet" step for the common case of a single flat home/lab
// network.
func (s *Server) handleDeployAutoScan(w http.ResponseWriter, r *http.Request) {
	cidr, err := detectLocalCIDR(s.agentNATSURL())
	if err != nil {
		http.Error(w, "couldn't determine a local subnet to scan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u := auth.CurrentUser(r.Context())
	s.logger.Info("auto network scan requested", "cidr", cidr, "requested_by", u.Username)

	results, err := scanSubnet(r.Context(), cidr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.annotateWithKnownAgents(r.Context(), results)
	writeJSONResponse(w, deployAutoScanResponse{CIDR: cidr, Results: results})
}

// annotateWithKnownAgents fills in ScanResult.AgentInstalled/AgentVersion by
// matching a scanned IP against mustra's own known fleet (an agent reports
// every IP it sees on itself at registration/facts time — see
// store.AgentRecord.IPs). This is a correlation against mustra's existing
// inventory, not a live probe of the scanned host, so it only catches a
// mustra agent that has actually registered — a host running an agent that
// can't reach this NATS server (e.g. mid-firewall-change) would still show
// as not installed, same as it would everywhere else in the console.
func (s *Server) annotateWithKnownAgents(ctx context.Context, results []ScanResult) {
	if len(results) == 0 {
		return
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		s.logger.Warn("list agents for scan annotation failed", "error", err)
		return
	}
	byIP := make(map[string]string, len(agents)*2) // ip -> agent_version
	for _, a := range agents {
		for _, ip := range a.IPs {
			byIP[ip] = a.AgentVersion
		}
	}
	for i := range results {
		if v, ok := byIP[results[i].IP]; ok {
			results[i].AgentInstalled = true
			results[i].AgentVersion = v
		}
	}
}

type createCredentialRequest struct {
	Name       string `json:"name" api:"required"`
	Username   string `json:"username" api:"required"`
	AuthType   string `json:"auth_type" api:"required"`        // "password" | "private_key"
	Secret     string `json:"secret" api:"required,writeonly"` // password, or PEM private key contents
	Passphrase string `json:"passphrase" api:"writeonly"`      // optional: only for a passphrase-protected private_key
}

// listCredentialsResponse is what GET /api/deploy/credentials answers.
type listCredentialsResponse struct {
	Credentials []store.DeployCredential `json:"credentials"`
}

// handleListCredentials returns vault metadata only — secrets are never
// returned once stored, by design.
func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	creds, err := s.vault.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listCredentialsResponse{Credentials: creds})
}

func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	var req createCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Username == "" || req.Secret == "" {
		http.Error(w, "name, username, and secret are all required", http.StatusBadRequest)
		return
	}
	if req.AuthType != "password" && req.AuthType != "private_key" {
		http.Error(w, `auth_type must be "password" or "private_key"`, http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	cred, err := s.vault.Create(r.Context(), req.Name, req.Username, req.AuthType, req.Secret, req.Passphrase, u.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("deploy credential created", "name", cred.Name, "created_by", u.Username)
	writeJSONResponse(w, cred)
}

// credentialPublicKeyResponse is what GET
// /api/deploy/credentials/{id}/public-key answers.
type credentialPublicKeyResponse struct {
	PublicKey string `json:"public_key"`
}

// handleCredentialPublicKey returns the authorized_keys line for a stored
// private key, so an admin can paste it onto hosts that rejected it.
func (s *Server) handleCredentialPublicKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	pub, err := s.vault.PublicKey(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONResponse(w, credentialPublicKeyResponse{PublicKey: pub})
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	if err := s.vault.Delete(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type pushRequest struct {
	Hostname     string `json:"hostname,omitempty"` // what the scan resolved, for the deployment history
	Target       string `json:"target" api:"required"`
	CredentialID string `json:"credential_id" api:"required"`
	Site         string `json:"site"`
	// HostKeyFingerprint is the target's SSH host key fingerprint
	// (SHA256:…) as the operator verified it, for a target whose key is not
	// yet stored. See sshdeploy.go.
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	// NoRemoteCode installs in inventory-and-patching mode: the endpoint refuses
	// code from the server, and only an administrator on it can undo that.
	NoRemoteCode bool `json:"no_remote_code,omitempty"`
}

type pushResponse struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// handleDeployPush SSHes into one discovered host with a stored credential
// and runs the same install script the manual /install.sh /install.ps1
// routes serve. Synchronous and can take a while (binary download +
// service install on the remote host), so the console shows a spinner
// rather than streaming — v1 keeps this simple; see docs/ROADMAP.md for
// making pushes to many hosts concurrent/streamed.
func (s *Server) handleDeployPush(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	var req pushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Target == "" || req.CredentialID == "" {
		http.Error(w, "target and credential_id are required", http.StatusBadRequest)
		return
	}
	site := req.Site
	if site == "" {
		site = defaultSite
	}

	cred, err := s.vault.Resolve(r.Context(), req.CredentialID)
	if err != nil {
		http.Error(w, "resolving credential failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if cred == nil {
		http.Error(w, "no such credential", http.StatusNotFound)
		return
	}

	u := auth.CurrentUser(r.Context())
	s.logger.Info("agent push requested", "target", req.Target, "credential", req.CredentialID, "requested_by", u.Username)

	// Verify the host before any credential is offered to it.
	target := strings.ToLower(strings.TrimSpace(req.Target))
	var hostKey ssh.HostKeyCallback
	var confirmed ssh.PublicKey
	known, err := s.store.GetSSHKnownHost(r.Context(), target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch {
	case known != nil:
		pub, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(known.PublicKey))
		if perr != nil {
			http.Error(w, "the stored host key for "+target+" is unreadable", http.StatusInternalServerError)
			return
		}
		hostKey = pinnedHostKey(pub)
	case strings.TrimSpace(req.HostKeyFingerprint) != "":
		hostKey = fingerprintHostKey(req.HostKeyFingerprint, &confirmed)
	default:
		pctx, pcancel := context.WithTimeout(r.Context(), 20*time.Second)
		key, perr := fetchSSHHostKey(pctx, req.Target)
		pcancel()
		if perr != nil {
			writeJSONStatus(w, http.StatusBadGateway, pushResponse{OK: false, Error: perr.Error()})
			return
		}
		unknown := &hostKeyUnknownError{Target: target, KeyType: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
		writeJSONStatus(w, http.StatusConflict, map[string]any{"ok": false, "error": unknown.Error(),
			"host_key_unknown": true, "host_key_type": unknown.KeyType, "host_key_fingerprint": unknown.Fingerprint})
		return
	}

	// Recorded before the SSH session starts, so a push that never returns
	// (server restarted mid-install) still leaves a trace on the Deployments
	// view rather than vanishing with the browser tab that launched it.
	deploymentID := idgen.New("adep-")
	if err := s.store.StartAgentDeployment(r.Context(), store.AgentDeployment{
		ID: deploymentID, Target: req.Target, Hostname: strings.TrimSuffix(req.Hostname, "."), Site: site,
		Credential: cred.Username, StartedBy: u.Username,
	}); err != nil {
		s.logger.Warn("record agent deployment start failed", "error", err)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	// The same data /install.sh renders, not a hand-built subset: a push
	// once left out the NATS credentials, so the installer skipped the CA
	// and agent.env and the agent crash-looped on "certificate signed by
	// unknown authority" while the push reported success.
	// A push installs with a fresh single-use enrollment token of its own
	// (installScriptDataForPush), never a shared bus password.
	data, err := s.installScriptDataForPush(ctx, site, u.Username, req.Target, req.NoRemoteCode)
	var output string
	if err == nil {
		output, err = pushAgentViaSSH(ctx, req.Target, cred, data, hostKey)
	}
	if confirmed != nil {
		// Trusted from now on: the operator confirmed this fingerprint and
		// the host proved it holds the key.
		if serr := s.store.SaveSSHKnownHost(context.WithoutCancel(r.Context()), store.SSHKnownHost{
			Target: target, KeyType: confirmed.Type(), Fingerprint: ssh.FingerprintSHA256(confirmed),
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(confirmed))), ConfirmedBy: u.Username,
		}); serr != nil {
			s.logger.Warn("storing confirmed ssh host key failed", "target", target, "error", serr)
		}
		s.audit(r.Context(), auditEvent{Action: "deploy.ssh_host_key_confirmed", Actor: u.Username, Target: target,
			Severity: "notice", Detail: map[string]any{"fingerprint": ssh.FingerprintSHA256(confirmed)}})
	}
	resp := pushResponse{OK: err == nil, Output: output}
	status, errMsg := "succeeded", ""
	if err != nil {
		resp.Error = err.Error()
		status, errMsg = "failed", err.Error()
		s.logger.Warn("agent push failed", "target", req.Target, "error", err)
	} else {
		s.logger.Info("agent push succeeded", "target", req.Target)
	}
	// Detached from the request context: the outcome must be recorded even
	// if the caller has already navigated away and cancelled it.
	recCtx, recCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer recCancel()
	if err := s.store.FinishAgentDeployment(recCtx, deploymentID, status, errMsg, truncateOutput(output)); err != nil {
		s.logger.Warn("record agent deployment finish failed", "error", err)
	}
	writeJSONResponse(w, resp)
}

// truncateOutput keeps an install transcript to a reasonable row size —
// this table is a history view, not a log store. Rune-safe, because the
// row it lands in is Postgres text and an installer transcript is where
// multi-byte characters cluster; see safeTruncate.
func truncateOutput(out string) string {
	return safeTruncate(out, 8000)
}

// listAgentDeploymentsResponse is what GET /api/deploy/deployments answers.
type listAgentDeploymentsResponse struct {
	Deployments []store.AgentDeployment `json:"deployments"`
}

func (s *Server) handleListAgentDeployments(w http.ResponseWriter, r *http.Request) {
	deployments, err := s.store.ListAgentDeployments(r.Context(), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listAgentDeploymentsResponse{Deployments: deployments})
}
