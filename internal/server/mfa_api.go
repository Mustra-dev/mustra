package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Two-step sign-in (TOTP) for local accounts: the account's own setup in
// Preferences, the administrator's reset, and the policy that requires it.
// The sign-in step itself is in auth/totp.go.

const settingLocalMFARequired = "auth.local_mfa_required"

func (s *Server) localMFARequired(ctx context.Context) bool {
	v, _ := s.store.GetSetting(ctx, settingLocalMFARequired)
	return v == "true"
}

func (s *Server) wireMFA() {
	cfg := auth.MFAConfig{
		Required:          s.localMFARequired,
		ShowRecoveryCodes: s.showRecoveryCodesAfterSignIn,
		Audit: func(ctx context.Context, action, username string, detail map[string]any) {
			s.audit(ctx, auditEvent{Action: action, Actor: username, Target: username, Severity: "notice", Detail: detail})
		},
	}
	// A nil *vault.Vault in the interface would not compare equal to nil.
	if s.vault != nil {
		cfg.Box = s.vault
	}
	s.auth.SetMFA(cfg)
}

// qrSVG draws text as a QR code in SVG, one path, so the setup screens need
// no image request and no script. Medium error correction; the quiet zone
// is part of the drawing.
func qrSVG(text string) (template.HTML, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := code.Size + 2*quiet
	var b bytes.Buffer
	fmt.Fprintf(&b, `<svg class="qr" viewBox="0 0 %d %d" role="img" aria-label="QR code for your authenticator app" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()), nil // #nosec: built from integers only
}

// groupSecret spaces a base32 secret in fours, for typing it by hand.
func groupSecret(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}

// mfaStatus is the signed-in account's two-step sign-in state.
type mfaStatus struct {
	// Applies is false for SSO and API-token callers: their sign-in is
	// not a local password, so this factor has nothing to protect.
	Applies bool `json:"applies"`
	// Available is false when the server has no credential encryption key.
	Available         bool       `json:"available"`
	Required          bool       `json:"required"`
	Enabled           bool       `json:"enabled"`
	EnabledAt         *time.Time `json:"enabled_at,omitempty"`
	RecoveryCodesLeft int        `json:"recovery_codes_left"`
}

func (s *Server) mfaStatusFor(ctx context.Context, u *store.User) (mfaStatus, error) {
	st := mfaStatus{Available: s.auth.MFAAvailable(), Required: s.localMFARequired(ctx)}
	if u == nil || u.Source != "local" || u.ID == auth.APITokenUserID {
		return st, nil
	}
	st.Applies = true
	t, err := s.store.GetUserTOTP(ctx, u.ID)
	if err != nil {
		return st, err
	}
	if t != nil && t.Enabled() {
		st.Enabled, st.EnabledAt = true, t.EnabledAt
		if st.RecoveryCodesLeft, err = s.store.RecoveryCodesLeft(ctx, u.ID); err != nil {
			return st, err
		}
	}
	return st, nil
}

// localAccount answers for the routes that only make sense for a local
// account signed in with a session.
func (s *Server) localAccount(w http.ResponseWriter, r *http.Request) *store.User {
	u := auth.CurrentUser(r.Context())
	if _, isToken := auth.TokenPermissions(r.Context()); isToken || u == nil {
		http.Error(w, "two-step sign-in belongs to a person's account; an API token has none", http.StatusConflict)
		return nil
	}
	if u.Source != "local" {
		http.Error(w, "this account signs in through single sign-on; use your identity provider's two-step sign-in", http.StatusConflict)
		return nil
	}
	if !s.auth.MFAAvailable() {
		http.Error(w, "two-step sign-in needs the server's credential encryption key (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)", http.StatusServiceUnavailable)
		return nil
	}
	return u
}

func (s *Server) handleGetMFA(w http.ResponseWriter, r *http.Request) {
	st, err := s.mfaStatusFor(r.Context(), auth.CurrentUser(r.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, st)
}

// mfaSetupResponse is a new, not yet confirmed authenticator secret.
type mfaSetupResponse struct {
	// Secret is the base32 key, for typing into an app by hand.
	Secret string `json:"secret"`
	// OTPAuthURI is the same key as an otpauth:// URI.
	OTPAuthURI string `json:"otpauth_uri"`
	// QRSVG draws OTPAuthURI as an SVG QR code.
	QRSVG string `json:"qr_svg"`
}

func (s *Server) handleSetupMFA(w http.ResponseWriter, r *http.Request) {
	u := s.localAccount(w, r)
	if u == nil {
		return
	}
	secret, err := s.auth.BeginTOTPSetup(r.Context(), u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	uri := auth.OTPAuthURI("mustra", u.Username+"@"+requestHost(r), secret)
	svg, err := qrSVG(uri)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, mfaSetupResponse{Secret: groupSecret(secret), OTPAuthURI: uri, QRSVG: string(svg)})
}

func requestHost(r *http.Request) string {
	h := r.Host
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h
}

// mfaCodeRequest carries a code from the authenticator app (or, where
// noted, a recovery code).
type mfaCodeRequest struct {
	Code string `json:"code"`
}

// mfaRecoveryCodesResponse lists recovery codes, shown this once.
type mfaRecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

func decodeCode(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req mfaCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		http.Error(w, "code is required", http.StatusBadRequest)
		return "", false
	}
	return req.Code, true
}

func (s *Server) handleEnableMFA(w http.ResponseWriter, r *http.Request) {
	u := s.localAccount(w, r)
	if u == nil {
		return
	}
	code, ok := decodeCode(w, r)
	if !ok {
		return
	}
	codes, ok, err := s.auth.ConfirmTOTP(r.Context(), u.ID, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "that code does not match; check the time on your device and try the newest code", http.StatusBadRequest)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "auth.mfa_enrolled", Actor: u.Username, Target: u.Username, Severity: "notice", Detail: map[string]any{"at": "preferences"}})
	writeJSONResponse(w, mfaRecoveryCodesResponse{RecoveryCodes: codes})
}

func (s *Server) handleMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	u := s.localAccount(w, r)
	if u == nil {
		return
	}
	code, ok := decodeCode(w, r)
	if !ok {
		return
	}
	ok, _, err := s.auth.CheckSecondFactor(r.Context(), u.ID, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "that code is not valid", http.StatusBadRequest)
		return
	}
	codes, err := s.auth.NewRecoveryCodesFor(r.Context(), u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "auth.recovery_codes_replaced", Actor: u.Username, Target: u.Username, Severity: "notice"})
	writeJSONResponse(w, mfaRecoveryCodesResponse{RecoveryCodes: codes})
}

func (s *Server) handleDisableMFA(w http.ResponseWriter, r *http.Request) {
	u := s.localAccount(w, r)
	if u == nil {
		return
	}
	if s.localMFARequired(r.Context()) {
		http.Error(w, "two-step sign-in is required for local accounts; to move to a new device, an administrator can reset it", http.StatusConflict)
		return
	}
	code, ok := decodeCode(w, r)
	if !ok {
		return
	}
	ok, _, err := s.auth.CheckSecondFactor(r.Context(), u.ID, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "that code is not valid", http.StatusBadRequest)
		return
	}
	if !s.auditIdentity(w, r, "auth.mfa_disabled", u.Username, map[string]any{"by": "self"}) {
		return
	}
	if err := s.store.DisableTOTP(r.Context(), u.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.handleGetMFA(w, r)
}

// handleResetUserMFA removes another account's authenticator, for someone
// who lost their device and their recovery codes. Their sessions end, so
// the next sign-in sets it up again when the policy requires it.
func (s *Server) handleResetUserMFA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target, perr := s.protectedAccount(r.Context(), id)
	if target == nil && perr == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusForbidden)
		return
	}
	if !s.auditIdentity(w, r, "users.mfa_reset", target.Username, map[string]any{"user_id": id}) {
		return
	}
	if err := s.store.DisableTOTP(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.DeleteSessionsForUser(r.Context(), id); err != nil {
		s.logger.Warn("signing a user out after an MFA reset failed", "user_id", id, "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- the login page's second step -------------------------------------

// loginMFAView is the second step on the login page.
type loginMFAView struct {
	Enroll   bool
	Username string
	Secret   string
	URI      string
	QR       template.HTML
	// RecoveryCodes, once set, replaces the form: enrollment finished and
	// these are shown this once before continuing to Next.
	RecoveryCodes []string
	Next          string
}

func (s *Server) showRecoveryCodesAfterSignIn(w http.ResponseWriter, r *http.Request, codes []string, next string) {
	s.renderLogin(w, r, loginPageData{LogoURL: s.logoURL(), MFA: &loginMFAView{RecoveryCodes: codes, Next: next}})
}

func (s *Server) loginMFAStep(r *http.Request) (*loginMFAView, error) {
	p, err := s.auth.Pending(r)
	if err != nil || p == nil {
		return nil, err
	}
	v := &loginMFAView{Enroll: p.Purpose == "enroll", Username: p.Username}
	if v.Enroll {
		v.Secret, v.URI = groupSecret(p.Secret), p.URI
		if v.QR, err = qrSVG(p.URI); err != nil {
			return nil, err
		}
	}
	return v, nil
}
