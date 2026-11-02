package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// Two-step sign-in for local accounts: a time-based one-time password
// (RFC 6238; SHA-1, six digits, 30-second steps, which is what every
// authenticator app speaks) after the password, plus single-use recovery
// codes. SSO accounts are left to their identity provider's MFA.
//
// NIST SP 800-63B counts an authenticator app as a "single-factor OTP
// device"; with the password it makes the two factors AAL2 asks for.

const (
	totpPeriod = 30
	totpDigits = 6
	// totpSkew is how many steps either side of now a code may be from:
	// one, so a clock up to ~30 s off still works.
	totpSkew = 1

	// challengeTTL bounds the gap between password and code.
	challengeTTL = 5 * time.Minute
	// maxChallengeAttempts wrong codes end the challenge; the password
	// has to be entered again, which also feeds the sign-in limiter.
	maxChallengeAttempts = 5

	recoveryCodeCount = 10
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 160-bit secret in base32, the form
// authenticator apps take.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand read failed: %v", err))
	}
	return b32.EncodeToString(b)
}

func totpAt(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

// VerifyTOTP checks code against secret at now and returns the step it
// matched, which the caller records so the same code is not accepted
// twice.
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	code = normalizeOTP(code)
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil || len(key) == 0 {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		if subtle.ConstantTimeCompare([]byte(totpAt(key, cur+d)), []byte(code)) == 1 {
			return cur + d, true
		}
	}
	return 0, false
}

// normalizeOTP drops the spaces and dashes people type or paste.
func normalizeOTP(code string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(code))
}

// OTPAuthURI is the otpauth:// URI an authenticator app scans.
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// NewRecoveryCodes returns n codes to show once, and their hashes to keep.
// Each is 16 base32 characters (80 bits), grouped as xxxx-xxxx-xxxx-xxxx.
func NewRecoveryCodes(n int) (codes, hashes []string) {
	for range n {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			panic(fmt.Sprintf("crypto/rand read failed: %v", err))
		}
		s := strings.ToLower(b32.EncodeToString(b))
		code := s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes
}

// HashRecoveryCode is what user_recovery_codes stores for a code, after
// normalizing case and separators.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(normalizeOTP(code))))
	return hex.EncodeToString(sum[:])
}

// SecretBox seals and opens values bound to a record; the credential
// vault is one.
type SecretBox interface {
	Seal(plaintext, aad string) ([]byte, error)
	Open(ciphertext []byte, aad string) (plaintext string, legacy bool, err error)
}

// TOTPAAD binds a sealed TOTP secret to its user, so it cannot be moved
// to another account.
func TOTPAAD(userID string) string { return "user_totp/" + userID }

// MFAConfig wires two-step sign-in into Auth.
type MFAConfig struct {
	// Box encrypts TOTP secrets. Nil leaves two-step sign-in unavailable.
	Box SecretBox
	// Required reports whether every local account must use it.
	Required func(ctx context.Context) bool
	// ShowRecoveryCodes renders the codes made when someone enrolls while
	// signing in, then continues to next. The session already exists.
	ShowRecoveryCodes func(w http.ResponseWriter, r *http.Request, codes []string, next string)
	// Audit records enrollment and recovery-code use.
	Audit func(ctx context.Context, action, username string, detail map[string]any)
}

// SetMFA enables two-step sign-in.
func (a *Auth) SetMFA(cfg MFAConfig) { a.mfa = cfg }

// MFAAvailable reports whether this server can store TOTP secrets.
func (a *Auth) MFAAvailable() bool { return a.mfa.Box != nil }

// LocalMFARequired reports the policy for local accounts.
func (a *Auth) LocalMFARequired(ctx context.Context) bool {
	return a.mfa.Required != nil && a.mfa.Required(ctx)
}

func (a *Auth) audit(ctx context.Context, action, username string, detail map[string]any) {
	if a.mfa.Audit != nil {
		a.mfa.Audit(ctx, action, username, detail)
	}
}

// SealTOTPSecret encrypts a secret for userID.
func (a *Auth) SealTOTPSecret(userID, secret string) ([]byte, error) {
	if a.mfa.Box == nil {
		return nil, errMFAUnavailable
	}
	return a.mfa.Box.Seal(secret, TOTPAAD(userID))
}

func (a *Auth) openTOTPSecret(userID string, sealed []byte) (string, error) {
	if a.mfa.Box == nil {
		return "", errMFAUnavailable
	}
	s, _, err := a.mfa.Box.Open(sealed, TOTPAAD(userID))
	return s, err
}

var errMFAUnavailable = errors.New("two-step sign-in needs the credential encryption key (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)")

// CheckSecondFactor verifies a code for a user with TOTP enabled: a
// current authenticator code (spent, so it cannot be replayed) or an
// unused recovery code. It reports which kind matched.
func (a *Auth) CheckSecondFactor(ctx context.Context, userID, code string) (ok, recovery bool, err error) {
	t, err := a.store.GetUserTOTP(ctx, userID)
	if err != nil || t == nil || !t.Enabled() {
		return false, false, err
	}
	if len(normalizeOTP(code)) == totpDigits {
		secret, err := a.openTOTPSecret(userID, t.Secret)
		if err != nil {
			return false, false, err
		}
		step, ok := VerifyTOTP(secret, code, time.Now())
		if !ok {
			return false, false, nil
		}
		fresh, err := a.store.AdvanceTOTPStep(ctx, userID, step)
		return fresh, false, err
	}
	used, err := a.store.UseRecoveryCode(ctx, userID, HashRecoveryCode(code))
	return used, used, err
}

// ConfirmTOTP verifies the first code for a pending secret and, if it
// matches, enables the factor and returns new recovery codes to show.
func (a *Auth) ConfirmTOTP(ctx context.Context, userID, code string) ([]string, bool, error) {
	t, err := a.store.GetUserTOTP(ctx, userID)
	if err != nil || t == nil || t.Enabled() || len(t.Secret) == 0 {
		return nil, false, err
	}
	secret, err := a.openTOTPSecret(userID, t.Secret)
	if err != nil {
		return nil, false, err
	}
	step, ok := VerifyTOTP(secret, code, time.Now())
	if !ok {
		return nil, false, nil
	}
	codes, hashes := NewRecoveryCodes(recoveryCodeCount)
	if err := a.store.EnableTOTP(ctx, userID, step, hashes); err != nil {
		return nil, false, err
	}
	return codes, true, nil
}

// NewRecoveryCodesFor replaces a user's recovery codes.
func (a *Auth) NewRecoveryCodesFor(ctx context.Context, userID string) ([]string, error) {
	codes, hashes := NewRecoveryCodes(recoveryCodeCount)
	if err := a.store.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// BeginTOTPSetup stores a new pending secret and returns it. It refuses
// when the factor is already enabled.
func (a *Auth) BeginTOTPSetup(ctx context.Context, userID string) (string, error) {
	secret := NewTOTPSecret()
	sealed, err := a.SealTOTPSecret(userID, secret)
	if err != nil {
		return "", err
	}
	ok, err := a.store.SetPendingTOTP(ctx, userID, sealed)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("two-step sign-in is already on; turn it off first to set up a new authenticator")
	}
	return secret, nil
}

// --- the sign-in step --------------------------------------------------

func (a *Auth) mfaCookieName() string {
	if a.cookieHTTPS {
		return "__Host-mustra_mfa"
	}
	return "mustra_mfa"
}

func (a *Auth) setMFACookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: a.mfaCookieName(), Value: token, Path: "/", HttpOnly: true,
		Secure: a.cookieHTTPS, SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	})
}

// secondStep decides, once the password is right, whether a code is owed.
// It reports true when it has answered the request (a challenge started,
// or sign-in refused) and false when the session can be issued now.
func (a *Auth) secondStep(w http.ResponseWriter, r *http.Request, user *store.User, next string) bool {
	ctx := r.Context()
	t, err := a.store.GetUserTOTP(ctx, user.ID)
	if err != nil {
		a.logger.Error("two-step sign-in lookup failed", "error", err)
		redirectLoginError(w, r, "sign-in is temporarily unavailable")
		return true
	}
	purpose := ""
	switch {
	case t != nil && t.Enabled():
		purpose = "totp"
	case a.LocalMFARequired(ctx):
		// Required and not set up: enroll now, before any session exists.
		// A secret already pending (scanned, then the code mistyped) is
		// kept, so the entry already in the app stays the right one.
		if t != nil && len(t.Secret) > 0 {
			purpose = "enroll"
			break
		}
		if _, err := a.BeginTOTPSetup(ctx, user.ID); err != nil {
			a.logger.Error("two-step sign-in is required but could not be set up", "username", user.Username, "error", err)
			redirectLoginError(w, r, "two-step sign-in is required but this server cannot set it up; ask an administrator")
			return true
		}
		purpose = "enroll"
	default:
		return false
	}
	token := newToken()
	if err := a.store.CreateLoginChallenge(ctx, HashSessionToken(token), user.ID, purpose, next, challengeTTL); err != nil {
		a.logger.Error("create login challenge failed", "error", err)
		redirectLoginError(w, r, "sign-in is temporarily unavailable")
		return true
	}
	a.setMFACookie(w, token, int(challengeTTL.Seconds()))
	http.Redirect(w, r, "/login?step=code", http.StatusFound)
	return true
}

// PendingMFA describes the step a browser owes, for the login page.
type PendingMFA struct {
	Purpose  string // "totp" | "enroll"
	Username string
	// Secret and URI are set while enrolling.
	Secret string
	URI    string
}

func (a *Auth) challenge(r *http.Request) (string, *store.LoginChallenge, error) {
	c, err := r.Cookie(a.mfaCookieName())
	if err != nil || c.Value == "" {
		return "", nil, nil
	}
	hash := HashSessionToken(c.Value)
	ch, err := a.store.GetLoginChallenge(r.Context(), hash)
	return hash, ch, err
}

// Pending returns the step this browser owes, or nil.
func (a *Auth) Pending(r *http.Request) (*PendingMFA, error) {
	_, ch, err := a.challenge(r)
	if err != nil || ch == nil {
		return nil, err
	}
	user, err := a.store.GetUserByID(r.Context(), ch.UserID)
	if err != nil || user == nil {
		return nil, err
	}
	p := &PendingMFA{Purpose: ch.Purpose, Username: user.Username}
	if ch.Purpose == "enroll" {
		t, err := a.store.GetUserTOTP(r.Context(), user.ID)
		if err != nil || t == nil || len(t.Secret) == 0 {
			return nil, err
		}
		if p.Secret, err = a.openTOTPSecret(user.ID, t.Secret); err != nil {
			return nil, err
		}
		p.URI = OTPAuthURI("mustra", user.Username+"@"+hostOnly(r.Host), p.Secret)
	}
	return p, nil
}

func hostOnly(h string) string {
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

// HandleMFALogin takes the code for a pending challenge (POST /login/code).
func (a *Auth) HandleMFALogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectLoginError(w, r, "could not parse the form: "+err.Error())
		return
	}
	ctx := r.Context()
	started := time.Now()
	hash, ch, err := a.challenge(r)
	if err != nil {
		a.logger.Error("login challenge lookup failed", "error", err)
		redirectLoginError(w, r, "sign-in is temporarily unavailable")
		return
	}
	if ch == nil {
		a.setMFACookie(w, "", -1)
		redirectLoginError(w, r, "that sign-in has expired; enter your password again")
		return
	}
	user, err := a.store.GetUserByID(ctx, ch.UserID)
	if err != nil || user == nil || !user.Active || user.Source != "local" {
		a.setMFACookie(w, "", -1)
		redirectLoginError(w, r, "invalid username or password")
		return
	}
	ip := ClientIP(r)
	codeFail := func(reason string) {
		if d := loginFloor - time.Since(started); d > 0 {
			time.Sleep(d)
		}
		http.Redirect(w, r, "/login?step=code&error="+url.QueryEscape(reason), http.StatusFound)
	}
	if wait := a.limiter.blocked(ip, user.Username); wait > 0 {
		w.Header().Set("Retry-After", itoa(int(wait.Seconds())+1))
		codeFail("too many failed sign-in attempts; try again later")
		return
	}

	code := r.FormValue("code")
	var ok, recovery bool
	var codes []string
	switch ch.Purpose {
	case "totp":
		ok, recovery, err = a.CheckSecondFactor(ctx, user.ID, code)
	case "enroll":
		codes, ok, err = a.ConfirmTOTP(ctx, user.ID, code)
	}
	if err != nil {
		a.logger.Error("checking a sign-in code failed", "username", user.Username, "error", err)
		codeFail("sign-in is temporarily unavailable")
		return
	}
	if !ok {
		a.limiter.fail(ip, user.Username)
		a.logger.Warn("sign-in code rejected", "username", user.Username, "ip", ip)
		if n, _ := a.store.FailLoginChallenge(ctx, hash); n >= maxChallengeAttempts {
			_ = a.store.DeleteLoginChallenge(ctx, hash)
			a.setMFACookie(w, "", -1)
			redirectLoginError(w, r, "too many wrong codes; enter your password again")
			return
		}
		codeFail("that code is not valid; check the time on your device and try the newest code")
		return
	}
	a.limiter.succeed(ip, user.Username)
	_ = a.store.DeleteLoginChallenge(ctx, hash)
	a.setMFACookie(w, "", -1)
	if err := a.setSessionCookie(ctx, w, user.ID); err != nil {
		a.logger.Error("create session failed", "error", err)
		redirectLoginError(w, r, "creating the session failed: "+err.Error())
		return
	}
	switch {
	case ch.Purpose == "enroll":
		a.audit(ctx, "auth.mfa_enrolled", user.Username, map[string]any{"at": "sign-in"})
		a.logger.Info("local login succeeded; two-step sign-in set up", "username", user.Username)
		if a.mfa.ShowRecoveryCodes != nil {
			a.mfa.ShowRecoveryCodes(w, r, codes, ch.Next)
			return
		}
	case recovery:
		left, _ := a.store.RecoveryCodesLeft(ctx, user.ID)
		a.audit(ctx, "auth.recovery_code_used", user.Username, map[string]any{"remaining": left})
		a.logger.Warn("local login succeeded with a recovery code", "username", user.Username, "remaining", left)
	default:
		a.logger.Info("local login succeeded", "username", user.Username, "two_step", true)
	}
	http.Redirect(w, r, ch.Next, http.StatusFound)
}
