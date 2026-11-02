package server

// Enterprise application credentials (Cert Manager → App Credentials).
//
// Client secrets, client certificates, SAML signing certificates and
// service-account keys live at identity providers — Microsoft Entra ID,
// Authentik, Okta, Google Cloud — and expire there, usually unnoticed until
// a sign-in breaks. A connection is an API login to a provider; from it the
// credentials of its applications are imported, or one is entered by hand.
// Each credential has a mode:
//
//   - remind: notify ahead of expiry; renewing stays manual.
//   - download: renew at the provider before expiry and keep the new
//     material (encrypted) for a one-time download for the grace period.
//   - push: renew, then write the new material on an endpoint — the whole
//     file, or one key's value in a config file — and reload the service.
//
// The credential it replaces is kept for grace_days so the application can
// switch over, then removed at the provider. A push that fails removes the
// credential it just made, so nothing is left half-rotated.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// credProvider is one identity provider's API.
type credProvider interface {
	// Test signs in and makes one read, to prove the connection works.
	Test(ctx context.Context) error
	// Discover lists the provider's application credentials.
	Discover(ctx context.Context) ([]store.AppCredential, error)
	// Rotate makes a new credential beside the current one.
	Rotate(ctx context.Context, c store.AppCredential) (credRotation, error)
	// Retire removes a credential (the one a rotation replaced).
	Retire(ctx context.Context, c store.AppCredential, externalID string) error
}

// credRotation is what a provider hands back for a new credential. Only
// one of Secret, KeyPEM (with CertPEM) or JSON is the private part.
type credRotation struct {
	ExternalID string
	ExpiresAt  *time.Time
	Secret     string
	CertPEM    string
	KeyPEM     string
	JSON       string
	Note       string
}

// material is what is downloaded or pushed for a rotation.
func (r credRotation) material() string {
	switch {
	case r.Secret != "":
		return r.Secret
	case r.JSON != "":
		return r.JSON
	case r.KeyPEM != "":
		return strings.TrimSpace(r.KeyPEM) + "\n" + strings.TrimSpace(r.CertPEM) + "\n"
	}
	return r.CertPEM
}

var appCredKinds = map[string]string{
	"entra":     "Microsoft Entra ID",
	"authentik": "Authentik",
	"okta":      "Okta",
	"gcp":       "Google Cloud",
	"manual":    "Entered by hand",
}

var appCredTypes = map[string]string{
	"client_secret":       "Client secret",
	"client_certificate":  "Client certificate",
	"saml_signing":        "SAML signing certificate",
	"service_account_key": "Service-account key",
	"certificate":         "Certificate",
}

func connAAD(id string) string     { return "app_cred_connection/secret/" + id }
func materialAAD(id string) string { return "app_credential/material/" + id }

// credProviderFor opens a connection's secret and builds its client.
func (s *Server) credProviderFor(ctx context.Context, connID string) (credProvider, *store.AppCredConnection, error) {
	conn, err := s.store.GetAppCredConnection(ctx, connID)
	if err != nil || conn == nil {
		return nil, nil, errors.New("the connection no longer exists")
	}
	secret, err := openWith(s.vault, connAAD(conn.ID), conn.Secret)
	if err != nil {
		return nil, conn, fmt.Errorf("the connection's secret cannot be read: %w", err)
	}
	cfg := conn.Config
	switch conn.Kind {
	case "entra":
		return &entraProvider{tenant: cfg["tenant_id"], clientID: cfg["client_id"], secret: secret}, conn, nil
	case "authentik":
		return &authentikProvider{base: strings.TrimRight(cfg["url"], "/"), token: secret}, conn, nil
	case "okta":
		return &oktaProvider{base: strings.TrimRight(cfg["url"], "/"), token: secret}, conn, nil
	case "gcp":
		p, _, err := newGCPProvider(cfg["project_id"], secret)
		return p, conn, err
	}
	return nil, conn, fmt.Errorf("unknown provider %q", conn.Kind)
}

// dueAt is when a credential is due: renew_days before it expires, or —
// for a secret with no expiry (Authentik, Okta) — rotate_days after it was
// last rotated or imported.
func dueAt(c store.AppCredential) *time.Time {
	if c.ExpiresAt != nil {
		t := c.ExpiresAt.Add(-time.Duration(c.RenewDays) * 24 * time.Hour)
		return &t
	}
	if c.RotateDays > 0 {
		base := c.CreatedAt
		if c.LastRotatedAt != nil {
			base = *c.LastRotatedAt
		}
		t := base.Add(time.Duration(c.RotateDays) * 24 * time.Hour)
		return &t
	}
	return nil
}

// rotatable says whether Mustra can renew a credential at its provider.
func rotatable(c store.AppCredential) bool {
	return c.Kind != "manual" && c.ConnectionID != "" && c.CredType != "certificate"
}

// --- rotation ---------------------------------------------------------------

// rotateAppCred renews one credential end to end.
func (s *Server) rotateAppCred(ctx context.Context, id, by string) error {
	c, err := s.store.GetAppCredential(ctx, id)
	if err != nil || c == nil {
		return errors.New("no such credential")
	}
	label := c.AppName + " · " + appCredTypes[c.CredType]
	fail := func(why string) error {
		_ = s.store.SetAppCredState(ctx, c.ID, "failed", why)
		s.notify(ctx, "warning", "Certificates", "App credential renewal failed: "+label, safeTruncate(why, 300), "/certificates#apps")
		s.audit(ctx, auditEvent{Action: "appcreds.rotate", Actor: by, Target: label, Outcome: "failed", Severity: "warning",
			Detail: map[string]any{"kind": c.Kind, "type": c.CredType, "error": why}})
		return errors.New(why)
	}
	if !rotatable(*c) {
		return fail("this credential is tracked only; Mustra cannot renew it at its provider")
	}
	if c.Mode == "push" && c.PushAgentID != "" {
		if a := s.agentByID(ctx, c.PushAgentID); a == nil || !a.Online {
			return fail("the endpoint it is pushed to is offline; nothing was changed")
		}
	}
	p, _, err := s.credProviderFor(ctx, c.ConnectionID)
	if err != nil {
		return fail(err.Error())
	}
	_ = s.store.SetAppCredState(ctx, c.ID, "rotating", "Creating the new credential at "+appCredKinds[c.Kind])
	rot, err := p.Rotate(ctx, *c)
	if err != nil {
		return fail("creating the new credential: " + err.Error())
	}
	var notes []string
	if rot.Note != "" {
		notes = append(notes, rot.Note)
	}
	material := rot.material()
	if c.Mode == "push" && c.PushAgentID != "" && c.PushPath != "" {
		_ = s.store.SetAppCredState(ctx, c.ID, "rotating", "Writing it on the endpoint")
		res, err := s.agentSecretWrite(ctx, c.PushAgentID, proto.SecretWriteJob{Path: c.PushPath, Key: c.PushKey, Content: material, ReloadCmd: c.PushReload})
		if err != nil || !res.OK {
			why := firstNonEmpty(res.Error, errString(err))
			// The application still uses the old one; take the new one back.
			if rerr := p.Retire(ctx, *c, rot.ExternalID); rerr != nil {
				why += "; removing the new credential at the provider also failed (" + rerr.Error() + "), remove it there by hand"
			}
			return fail("pushing it to the endpoint: " + why + " (agent 0.57.37 or newer)")
		}
		notes = append(notes, strings.TrimSpace(res.Output))
	}
	sealed, err := sealWith(s.vault, materialAAD(c.ID), material)
	if err != nil {
		sealed = ""
		notes = append(notes, "The new material could not be stored for download.")
	}
	grace := c.GraceDays
	if grace < 1 {
		grace = 1
	}
	retire := time.Now().Add(time.Duration(grace) * 24 * time.Hour)
	var retireAfter *time.Time
	prev := c.ExternalID
	if prev != "" && prev != rot.ExternalID {
		retireAfter = &retire
		notes = append(notes, fmt.Sprintf("The previous one is removed at the provider on %s.", retire.UTC().Format("2006-01-02")))
	}
	until := retire
	if c.Mode == "remind" || c.Mode == "download" {
		notes = append(notes, "Download the new one before "+until.UTC().Format("2006-01-02")+".")
	}
	detail := "Renewed at " + appCredKinds[c.Kind] + ". " + strings.Join(notes, " ")
	if err := s.store.SetAppCredRotation(ctx, c.ID, rot.ExternalID, prev, rot.ExpiresAt, retireAfter, sealed, &until, detail); err != nil {
		return fail(err.Error())
	}
	s.audit(ctx, auditEvent{Action: "appcreds.rotate", Actor: by, Target: label, Severity: "notice",
		Detail: map[string]any{"kind": c.Kind, "type": c.CredType, "mode": c.Mode, "pushed_to": c.PushAgentID}})
	if c.Mode != "push" {
		s.notify(ctx, "notice", "Certificates", "App credential renewed: "+label, "Download the new one under Cert Manager → App Credentials.", "/certificates#apps")
	}
	return nil
}

func (s *Server) agentSecretWrite(ctx context.Context, agentID string, job proto.SecretWriteJob) (proto.AgentCommandResult, error) {
	payload, err := json.Marshal(proto.AgentCommand{Cmd: "secret_write", Secret: &job})
	if err != nil {
		return proto.AgentCommandResult{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(agentID), payload)
	if err != nil {
		return proto.AgentCommandResult{}, fmt.Errorf("the endpoint did not answer: %w", err)
	}
	var res proto.AgentCommandResult
	err = json.Unmarshal(msg.Data, &res)
	return res, err
}

// appCredLoop checks every credential hourly: reminds, renews what is due,
// retires what a rotation replaced once its grace is over, and drops
// downloadable material that has outlived it.
func (s *Server) appCredLoop(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		s.checkAppCreds(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) checkAppCreds(ctx context.Context) {
	list, err := s.store.ListAppCredentials(ctx)
	if err != nil {
		return
	}
	now := time.Now()
	for _, c := range list {
		if c.MaterialUntil != nil && now.After(*c.MaterialUntil) && c.Material != "" {
			_ = s.store.ClearAppCredMaterial(ctx, c.ID)
		}
		if c.RetireAfter != nil && now.After(*c.RetireAfter) && c.PreviousExternalID != "" {
			if p, _, err := s.credProviderFor(ctx, c.ConnectionID); err == nil {
				if err := p.Retire(ctx, c, c.PreviousExternalID); err == nil {
					_ = s.store.ClearAppCredRetired(ctx, c.ID, "Removed the previous credential at the provider.")
				} else {
					s.logger.Warn("retiring a replaced app credential failed", "id", c.ID, "error", err)
				}
			}
		}
		due := dueAt(c)
		if due == nil || now.Before(*due) || c.State == "rotating" {
			continue
		}
		// Reminders are the expiry alerts' job (expiry_alerts.go), at the
		// thresholds set under Cert Manager → Alerts.
		if c.Mode == "remind" || !rotatable(c) {
			continue
		}
		if c.State == "failed" && c.NotifiedAt != nil && now.Sub(*c.NotifiedAt) < 12*time.Hour {
			continue
		}
		_ = s.store.SetAppCredNotified(ctx, c.ID)
		go func(id string) { _ = s.rotateAppCred(context.WithoutCancel(ctx), id, "schedule") }(c.ID)
	}
}

// --- API --------------------------------------------------------------------

type appCredView struct {
	store.AppCredential
	DueAt             *time.Time `json:"due_at,omitempty"`
	Rotatable         bool       `json:"rotatable"`
	MaterialAvailable bool       `json:"material_available"`
	KindLabel         string     `json:"kind_label"`
	TypeLabel         string     `json:"type_label"`
}

// listAppCredsResponse is what GET /api/certificates/apps answers.
type listAppCredsResponse struct {
	Connections []store.AppCredConnection `json:"connections"`
	Credentials []appCredView             `json:"credentials"`
	Kinds       map[string]string         `json:"kinds"`
	Types       map[string]string         `json:"types"`
}

// GET /api/certificates/apps
func (s *Server) handleListAppCreds(w http.ResponseWriter, r *http.Request) {
	conns, err := s.store.ListAppCredConnections(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	creds, err := s.store.ListAppCredentials(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]appCredView, 0, len(creds))
	for _, c := range creds {
		out = append(out, appCredView{AppCredential: c, DueAt: dueAt(c), Rotatable: rotatable(c),
			MaterialAvailable: c.Material != "" && c.MaterialUntil != nil && time.Now().Before(*c.MaterialUntil),
			KindLabel:         appCredKinds[c.Kind], TypeLabel: appCredTypes[c.CredType]})
	}
	writeJSONResponse(w, listAppCredsResponse{Connections: conns, Credentials: out, Kinds: appCredKinds, Types: appCredTypes})
}

type connBody struct {
	store.AppCredConnection
	SecretValue string `json:"secret" api:"writeonly"`
}

// saveAppCredConnectionResponse is what POST
// /api/certificates/apps/connections and PUT
// /api/certificates/apps/connections/{id} answer.
type saveAppCredConnectionResponse struct {
	ID        string `json:"id"`
	TestError string `json:"test_error"`
}

// POST /api/certificates/apps/connections (and PUT …/{id})
func (s *Server) handleSaveAppCredConnection(w http.ResponseWriter, r *http.Request) {
	var b connBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	c := b.AppCredConnection
	// A POST always creates, under an ID minted below, so it always needs
	// the secret: a body ID once skipped that check and stored a new
	// connection with none. A PUT updates the connection it names.
	isNew := r.PathValue("id") == ""
	if !isNew {
		old, err := s.store.GetAppCredConnection(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if old == nil {
			http.Error(w, "no such connection", http.StatusNotFound)
			return
		}
		c.ID, c.Kind = old.ID, old.Kind
	}
	if appCredKinds[c.Kind] == "" || c.Kind == "manual" {
		http.Error(w, "choose a provider", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(c.Name) == "" {
		c.Name = appCredKinds[c.Kind]
	}
	for k, v := range c.Config {
		c.Config[k] = strings.TrimSpace(v)
	}
	if u := c.Config["url"]; u != "" && !strings.HasPrefix(u, "https://") {
		http.Error(w, "the URL must start with https://", http.StatusBadRequest)
		return
	}
	if isNew {
		c.ID = idgen.New("acc-")
		c.CreatedBy = auth.CurrentUser(r.Context()).Username
		if strings.TrimSpace(b.SecretValue) == "" {
			http.Error(w, "the connection needs its secret, token or key", http.StatusBadRequest)
			return
		}
	}
	if v := strings.TrimSpace(b.SecretValue); v != "" {
		sealed, err := sealWith(s.vault, connAAD(c.ID), v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c.Secret = sealed
	}
	if err := s.store.SaveAppCredConnection(r.Context(), c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "appcreds.connection", Actor: auth.CurrentUser(r.Context()).Username, Target: c.Name, Severity: "notice",
		Detail: map[string]any{"kind": c.Kind, "secret_changed": b.SecretValue != ""}})
	// Test straight away, so a wrong secret shows up now, not at renewal.
	msg := ""
	if p, _, err := s.credProviderFor(r.Context(), c.ID); err == nil {
		if terr := p.Test(r.Context()); terr != nil {
			msg = terr.Error()
		}
	} else {
		msg = err.Error()
	}
	_ = s.store.SetAppCredConnectionStatus(r.Context(), c.ID, msg)
	writeJSONResponse(w, saveAppCredConnectionResponse{ID: c.ID, TestError: msg})
}

func (s *Server) handleDeleteAppCredConnection(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAppCredConnection(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// discoveredAppCred is an entry of what GET
// /api/certificates/apps/connections/{id}/discover answers.
type discoveredAppCred struct {
	store.AppCredential
	Imported  bool   `json:"imported"`
	TypeLabel string `json:"type_label"`
}

// discoverAppCredsResponse is what GET
// /api/certificates/apps/connections/{id}/discover answers.
type discoverAppCredsResponse struct {
	Found []discoveredAppCred `json:"found"`
}

// GET /api/certificates/apps/connections/{id}/discover
func (s *Server) handleDiscoverAppCreds(w http.ResponseWriter, r *http.Request) {
	p, conn, err := s.credProviderFor(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	found, err := p.Discover(r.Context())
	if conn != nil {
		_ = s.store.SetAppCredConnectionStatus(r.Context(), conn.ID, errString(err))
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	have := map[string]bool{}
	if list, err := s.store.ListAppCredentials(r.Context()); err == nil {
		for _, c := range list {
			if c.ConnectionID == conn.ID {
				have[c.AppID+"|"+c.CredType+"|"+c.ExternalID] = true
			}
		}
	}
	out := make([]discoveredAppCred, 0, len(found))
	for _, c := range found {
		c.ConnectionID, c.Kind = conn.ID, conn.Kind
		out = append(out, discoveredAppCred{c, have[c.AppID+"|"+c.CredType+"|"+c.ExternalID], appCredTypes[c.CredType]})
	}
	writeJSONResponse(w, discoverAppCredsResponse{Found: out})
}

type credBody struct {
	store.AppCredential
	CertPEM string `json:"cert_pem,omitempty"` // manual: read the expiry from it
}

// POST /api/certificates/apps/credentials (and PUT …/{id}): import from a
// connection, enter one by hand, or change a credential's settings.
func (s *Server) handleSaveAppCred(w http.ResponseWriter, r *http.Request) {
	var b credBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	c := b.AppCredential
	// The path decides which record is written: a POST creates one under an
	// ID minted here, whatever the body says, and a PUT updates the one it
	// names. A body ID once let a create skip the PUT's checks and rewrite
	// an existing credential, validated against the connection the body
	// claimed rather than the stored one.
	if id := r.PathValue("id"); id != "" {
		old, err := s.store.GetAppCredential(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if old == nil {
			http.Error(w, "no such credential", http.StatusNotFound)
			return
		}
		// Identity stays; only the settings change.
		c.ID, c.ConnectionID, c.Kind, c.AppID, c.AppName, c.CredType, c.ExternalID = old.ID, old.ConnectionID, old.Kind, old.AppID, old.AppName, old.CredType, old.ExternalID
		c.CreatedBy = old.CreatedBy
		if old.Kind != "manual" {
			c.ExpiresAt = old.ExpiresAt
		}
	} else {
		c.ID = idgen.New("acr-")
		c.CreatedBy = auth.CurrentUser(r.Context()).Username
	}
	if c.ConnectionID == "" {
		c.Kind = "manual"
	} else {
		conn, _ := s.store.GetAppCredConnection(r.Context(), c.ConnectionID)
		if conn == nil {
			http.Error(w, "no such connection", http.StatusBadRequest)
			return
		}
		c.Kind = conn.Kind
	}
	if appCredTypes[c.CredType] == "" {
		http.Error(w, "unknown credential type", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(b.CertPEM) != "" {
		block, _ := pem.Decode([]byte(b.CertPEM))
		if block == nil {
			http.Error(w, "that is not a PEM certificate", http.StatusBadRequest)
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			http.Error(w, "the certificate cannot be read: "+err.Error(), http.StatusBadRequest)
			return
		}
		na := cert.NotAfter
		c.ExpiresAt = &na
		if c.DisplayName == "" {
			c.DisplayName = cert.Subject.CommonName
		}
	}
	switch {
	case strings.TrimSpace(c.AppName) == "":
		http.Error(w, "name the application", http.StatusBadRequest)
		return
	case c.Mode != "remind" && c.Mode != "download" && c.Mode != "push":
		http.Error(w, "mode is remind, download or push", http.StatusBadRequest)
		return
	case c.Mode != "remind" && !rotatable(c):
		http.Error(w, "only credentials imported from a connection can be renewed by Mustra; use remind", http.StatusBadRequest)
		return
	case c.Mode == "push" && (c.PushAgentID == "" || !strings.HasPrefix(c.PushPath, "/") && !(len(c.PushPath) > 2 && c.PushPath[1] == ':')):
		http.Error(w, "push needs an endpoint and the full path of the file", http.StatusBadRequest)
		return
	case c.RenewDays < 1 || c.RenewDays > 365, c.GraceDays < 0 || c.GraceDays > 90, c.RotateDays < 0 || c.RotateDays > 3650:
		http.Error(w, "renew 1–365 days ahead, keep the old one 0–90 days, rotate at most every 10 years", http.StatusBadRequest)
		return
	case c.ExpiresAt == nil && c.RotateDays == 0 && c.Mode != "remind":
		http.Error(w, "this credential has no expiry; set how often to rotate it", http.StatusBadRequest)
		return
	}
	if err := s.store.SaveAppCredential(r.Context(), c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "appcreds.manage", Actor: auth.CurrentUser(r.Context()).Username, Target: c.AppName, Severity: "notice",
		Detail: map[string]any{"kind": c.Kind, "type": c.CredType, "mode": c.Mode, "push_to": c.PushAgentID, "path": c.PushPath}})
	// Answer with what was stored, as handleSaveManagedCert does: the body
	// has no state or created_at, and an update's body none of the fields
	// the server keeps (#86).
	saved, err := s.store.GetAppCredential(r.Context(), c.ID)
	if err == nil && saved == nil {
		err = fmt.Errorf("it was deleted meanwhile")
	}
	if err != nil {
		http.Error(w, "saved, but could not read it back: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, saved)
}

func (s *Server) handleDeleteAppCred(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAppCredential(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/certificates/apps/credentials/{id}/renew
func (s *Server) handleRenewAppCred(w http.ResponseWriter, r *http.Request) {
	if err := s.rotateAppCred(r.Context(), r.PathValue("id"), auth.CurrentUser(r.Context()).Username); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	c, _ := s.store.GetAppCredential(r.Context(), r.PathValue("id"))
	writeJSONResponse(w, c)
}

// GET /api/certificates/apps/credentials/{id}/download: the renewed
// material, while it is kept. Every download is audited.
func (s *Server) handleDownloadAppCred(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetAppCredential(r.Context(), r.PathValue("id"))
	if err != nil || c == nil {
		http.Error(w, "no such credential", http.StatusNotFound)
		return
	}
	if c.Material == "" || c.MaterialUntil == nil || time.Now().After(*c.MaterialUntil) {
		http.Error(w, "nothing to download: the renewed material is kept only for the grace period", http.StatusGone)
		return
	}
	material, err := openWith(s.vault, materialAAD(c.ID), c.Material)
	if err != nil {
		http.Error(w, "the material cannot be read", http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "appcreds.download", Actor: auth.CurrentUser(r.Context()).Username, Target: c.AppName, Severity: "notice",
		Detail: map[string]any{"kind": c.Kind, "type": c.CredType}})
	ext := ".txt"
	switch {
	case strings.HasPrefix(strings.TrimSpace(material), "{"):
		ext = ".json"
	case strings.Contains(material, "-----BEGIN"):
		ext = ".pem"
	}
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, c.AppName+"-"+c.CredType)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+ext+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(material))
}
