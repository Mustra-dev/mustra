package server

// Trusted roots (Cert Manager): push a CA's root certificate into every
// endpoint's system trust store, so what that CA signs is trusted without
// a warning. The roots are the ones Mustra knows: its private CA and, once
// AD CS is set up, the domain's enterprise CA. A root set to "every
// endpoint" also reaches endpoints enrolled later; "remove" takes it back
// out. Linux and Windows agents change the store themselves; macOS only
// trusts a new root from an MDM profile, so Macs go through Fleet.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	settingADCSCACert   = "certs.adcs_ca_cert"
	settingTrustPushPre = "certs.trust_push." // + root id: "all", "remove" or ""

	trustRetryFailed      = 6 * time.Hour
	trustRetryUnsupported = 24 * time.Hour
	trustParallel         = 8
)

type trustRootInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"not_after"`
	Mode        string    `json:"mode"`
	pem         string
}

func parseRootPEM(text string) (*x509.Certificate, string, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, "", errors.New("no certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(c.Raw)
	return c, hex.EncodeToString(sum[:]), nil
}

// trustRoots lists the roots Mustra can push, with each one's push mode.
func (s *Server) trustRoots(ctx context.Context) ([]trustRootInfo, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}
	var out []trustRootInfo
	for _, r := range []struct{ id, name, key string }{
		{"private", "Mustra Private CA", settingCACert},
		{"adcs", "AD CS enterprise CA", settingADCSCACert},
	} {
		text := settings[r.key]
		if text == "" {
			continue
		}
		c, fp, err := parseRootPEM(text)
		if err != nil {
			s.logger.Warn("trusted roots: unreadable certificate", "root", r.id, "error", err)
			continue
		}
		// Go prints domainComponent by OID; AD CS roots are full of them.
		subject := strings.ReplaceAll(c.Subject.String(), "0.9.2342.19200300.100.1.25=", "DC=")
		out = append(out, trustRootInfo{ID: r.id, Name: r.name, Fingerprint: fp, Subject: subject,
			NotAfter: c.NotAfter, Mode: settings[settingTrustPushPre+r.id], pem: text})
	}
	return out, nil
}

func (s *Server) kickTrustRoots() {
	select {
	case s.trustKick <- struct{}{}:
	default:
	}
}

func (s *Server) trustRootLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		s.pushTrustRoots(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.trustKick:
		}
	}
}

// fetchADCSRoot asks the AD CS submitting endpoint for the CA's
// certificate when AD CS is set up and the root is not yet known.
func (s *Server) fetchADCSRoot(ctx context.Context) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil || settings[settingADCSCACert] != "" || settings[settingADCSAgent] == "" || settings[settingADCSConfig] == "" {
		return
	}
	a := s.agentByID(ctx, settings[settingADCSAgent])
	if a == nil || !a.Online {
		return
	}
	res, err := s.agentCertCommand(ctx, a.AgentID, "cert_adcs_ca", proto.CertJob{RequestID: idgen.New("adcs-"), CAConfig: settings[settingADCSConfig]}, time.Minute)
	if err != nil || !res.OK {
		s.logger.Info("trusted roots: AD CS root not fetched", "error", firstNonEmpty(res.Error, errString(err)))
		return
	}
	c, _, err := parseRootPEM(res.Output)
	if err != nil || !c.IsCA {
		s.logger.Warn("trusted roots: the AD CS endpoint returned no CA certificate")
		return
	}
	_ = s.store.SetSetting(ctx, settingADCSCACert, res.Output, "system (AD CS)")
}

func (s *Server) pushTrustRoots(ctx context.Context) {
	s.fetchADCSRoot(ctx)
	roots, err := s.trustRoots(ctx)
	if err != nil {
		s.logger.Warn("trusted roots: listing failed", "error", err)
		return
	}
	for _, root := range roots {
		if root.Mode != "all" && root.Mode != "remove" {
			continue
		}
		states, err := s.store.ListRootTrust(ctx, root.Fingerprint)
		if err != nil {
			s.logger.Warn("trusted roots: listing endpoints failed", "error", err)
			continue
		}
		sem := make(chan struct{}, trustParallel)
		var wg sync.WaitGroup
		for _, st := range states {
			if !trustDue(root.Mode, st, time.Now()) {
				continue
			}
			a := s.agentByID(ctx, st.AgentID)
			if a == nil || !a.Online {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(a store.AgentRecord) {
				defer wg.Done()
				defer func() { <-sem }()
				s.pushTrustRoot(ctx, root, a)
			}(*a)
		}
		wg.Wait()
	}
}

// trustDue says whether an endpoint needs the root pushed (or removed)
// now: never twice once done, failures retried after a pause.
func trustDue(mode string, st store.RootTrust, now time.Time) bool {
	if mode == "remove" {
		return st.State == "installed"
	}
	switch st.State {
	case "installed":
		return false
	case "failed":
		return now.Sub(st.UpdatedAt) > trustRetryFailed
	case "unsupported":
		return now.Sub(st.UpdatedAt) > trustRetryUnsupported
	}
	return true
}

func (s *Server) pushTrustRoot(ctx context.Context, root trustRootInfo, a store.AgentRecord) {
	remove := root.Mode == "remove"
	done := map[bool]string{false: "installed", true: "removed"}[remove]
	res, err := s.agentCertCommand(ctx, a.AgentID, "trust_root", proto.CertJob{RequestID: idgen.New("trust-"), CertPEM: root.pem, Remove: remove}, 2*time.Minute)
	state, via, detail := done, "agent", res.Output
	switch {
	case err != nil:
		state, detail = "failed", "the endpoint did not answer: "+err.Error()
	case res.OK:
	case strings.HasPrefix(res.Error, "mdm-required: ") && a.OS == "darwin":
		state, via, detail = s.trustViaMDM(ctx, root, a, remove)
	case strings.HasPrefix(res.Error, "unsupported: "):
		state, detail = "unsupported", strings.TrimPrefix(res.Error, "unsupported: ")
	case strings.Contains(res.Error, "unknown command"):
		state, detail = "failed", "the agent is too old to manage trusted roots (0.57.27 or newer)"
	default:
		state, detail = "failed", firstNonEmpty(res.Error, "failed")+"\n"+res.Output
	}
	if err := s.store.SetRootTrust(ctx, a.AgentID, root.Fingerprint, state, via, safeTruncate(strings.TrimSpace(detail), 1000)); err != nil {
		s.logger.Warn("trusted roots: recording failed", "error", err)
	}
	if state == done {
		s.audit(ctx, auditEvent{Action: "certs.trust_root", Actor: "system", Target: a.Hostname, AgentID: a.AgentID, Severity: "info",
			Detail: map[string]any{"root": root.Name, "fingerprint": root.Fingerprint, "result": state, "via": via}})
	}
}

// trustViaMDM installs (or removes) a root-certificate profile on a Mac
// through Fleet. The profile identifier comes from the fingerprint, so a
// second push replaces rather than duplicates it.
func (s *Server) trustViaMDM(ctx context.Context, root trustRootInfo, a store.AgentRecord, remove bool) (state, via, detail string) {
	fc, _, err := s.fleetConfig(ctx)
	if err != nil || fc == nil {
		return "failed", "mdm", "macOS trusts a new root only from an MDM profile, and no MDM is set up (Settings → Fleet MDM; docs/MACOS-UPDATES.md)"
	}
	host, err := fc.hostUUID(ctx, a.Hostname)
	if err != nil {
		return "failed", "mdm", err.Error()
	}
	var cmdUUID string
	if remove {
		cmdUUID, err = fc.command(ctx, host, "RemoveProfile", "<key>Identifier</key><string>"+rootProfileID(root.Fingerprint)+"</string>")
	} else {
		profile, perr := rootProfile(root)
		if perr != nil {
			return "failed", "mdm", perr.Error()
		}
		cmdUUID, err = fc.command(ctx, host, "InstallProfile", "<key>Payload</key><data>"+base64.StdEncoding.EncodeToString(profile)+"</data>")
	}
	if err != nil {
		return "failed", "mdm", "Fleet: " + err.Error()
	}
	status, res, err := fc.await(ctx, cmdUUID, 2*time.Minute)
	switch {
	case err != nil:
		return "failed", "mdm", "Fleet: " + err.Error()
	case status == "Acknowledged":
		return map[bool]string{false: "installed", true: "removed"}[remove], "mdm", "profile " + rootProfileID(root.Fingerprint) + " " + map[bool]string{false: "installed", true: "removed"}[remove] + " through Fleet"
	case status == "Pending" || status == "NotNow":
		// The Mac is asleep or busy; it will pick the command up later.
		return "failed", "mdm", "the Mac has not answered the MDM command yet (" + status + "); it will be retried"
	}
	return "failed", "mdm", "MDM " + status + ": " + errorChain(res)
}

func rootProfileID(fingerprint string) string { return "dev.mustra.trust." + fingerprint[:8] }

// rootProfile builds an unsigned configuration profile holding one root
// certificate (com.apple.security.root), which MDM may install silently.
func rootProfile(root trustRootInfo) ([]byte, error) {
	c, fp, err := parseRootPEM(root.pem)
	if err != nil {
		return nil, err
	}
	uuid := func(salt string) string {
		h := sha256.Sum256([]byte(salt + fp))
		x := strings.ToUpper(hex.EncodeToString(h[:16]))
		return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
	}
	id := rootProfileID(fp)
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadContent</key><data>` + base64.StdEncoding.EncodeToString(c.Raw) + `</data>
<key>PayloadDisplayName</key><string>` + xmlEscape(root.Name) + `</string>
<key>PayloadIdentifier</key><string>` + id + `.cert</string>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadUUID</key><string>` + uuid("cert") + `</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>Mustra trusted root: ` + xmlEscape(root.Name) + `</string>
<key>PayloadIdentifier</key><string>` + id + `</string>
<key>PayloadScope</key><string>System</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>` + uuid("profile") + `</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>
`), nil
}

// trustRootView is an entry of what GET /api/certificates/trust answers.
type trustRootView struct {
	trustRootInfo
	Counts    map[string]int    `json:"counts"`
	Endpoints []store.RootTrust `json:"endpoints"`
}

// listTrustRootsResponse is what GET /api/certificates/trust answers.
type listTrustRootsResponse struct {
	Roots []trustRootView `json:"roots"`
}

// GET /api/certificates/trust
func (s *Server) handleListTrustRoots(w http.ResponseWriter, r *http.Request) {
	roots, err := s.trustRoots(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := []trustRootView{}
	for _, root := range roots {
		states, err := s.store.ListRootTrust(r.Context(), root.Fingerprint)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		counts := map[string]int{"total": len(states)}
		for _, st := range states {
			counts[firstNonEmpty(st.State, "pending")]++
		}
		out = append(out, trustRootView{root, counts, states})
	}
	writeJSONResponse(w, listTrustRootsResponse{Roots: out})
}

// setTrustRootRequest is the body of POST /api/certificates/trust/{id}.
type setTrustRootRequest struct {
	Mode string `json:"mode" api:"required"`
}

// POST /api/certificates/trust/{id} {"mode":"all"|"off"|"remove"}
func (s *Server) handleSetTrustRoot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body setTrustRootRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	value := map[string]string{"all": "all", "off": "", "remove": "remove"}
	v, ok := value[body.Mode]
	if !ok {
		http.Error(w, "mode must be all, off or remove", http.StatusBadRequest)
		return
	}
	roots, err := s.trustRoots(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var root *trustRootInfo
	for i := range roots {
		if roots[i].ID == id {
			root = &roots[i]
		}
	}
	if root == nil {
		http.Error(w, "no such root", http.StatusNotFound)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	if err := s.store.SetSetting(r.Context(), settingTrustPushPre+id, v, who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "certs.trust_push", Actor: who, Target: root.Name, Severity: "notice",
		Detail: map[string]any{"mode": body.Mode, "fingerprint": root.Fingerprint}})
	s.kickTrustRoots()
	s.handleListTrustRoots(w, r)
}
