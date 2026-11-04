package server

// Email: the one outbound channel a person reads without opening anything of
// ours. Administration → Email holds one SMTP account; reports and the email
// integration send through it. There is no queue here. A report records a
// failed delivery on its run, and an integration on its row, the same as a
// webhook that did not answer.
//
// The server dials through guardedDial, so an internal relay needs the same
// allowlist entry as an internal webhook. Certificates are always verified,
// and a password is only ever sent over TLS. Unencrypted delivery is for a
// relay on the allowlist, again as with plain http webhooks: fleet data must
// not cross the internet in the clear because of one dropdown.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

const (
	settingMailHost     = "mail.host"
	settingMailPort     = "mail.port"
	settingMailSecurity = "mail.security"
	settingMailUsername = "mail.username"
	settingMailPassword = "mail.password"
	settingMailFrom     = "mail.from"

	mailSecurityStartTLS = "starttls"
	mailSecurityTLS      = "tls"
	mailSecurityNone     = "none"

	mailTimeout       = 30 * time.Second
	mailMaxRecipients = 50
	// mailMaxBytes keeps a report under the 10 MB most providers accept once
	// base64 has added its third.
	mailMaxBytes = 7 << 20
)

var errMailNotConfigured = errors.New("email is not set up: fill in Administration → Email first")

// mailConfig is one SMTP account. tlsConfig is only set by tests.
type mailConfig struct {
	Host     string
	Port     int
	Security string
	Username string
	Password string
	From     string

	tlsConfig *tls.Config
}

type mailMessage struct {
	To      []string
	Subject string
	Text    string
	HTML    string
}

// parseMailRecipients reads addresses separated by commas, semicolons or
// spaces into bare, distinct addresses. Display names are not accepted: the
// result goes on an audit line and into the SMTP envelope as it is.
func parseMailRecipients(raw string) ([]string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		addr, err := mail.ParseAddress(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not an email address", f)
		}
		if !slices.Contains(out, addr.Address) {
			out = append(out, addr.Address)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one email address is required")
	}
	if len(out) > mailMaxRecipients {
		return nil, fmt.Errorf("at most %d email addresses", mailMaxRecipients)
	}
	return out, nil
}

// validateMailConfig checks what an administrator entered. allowed is the
// internal destinations allowlist.
func validateMailConfig(c mailConfig, allowed map[string]bool) error {
	if c.Host == "" && c.From == "" && c.Username == "" {
		return nil // blank turns email off
	}
	if c.Host == "" || strings.ContainsAny(c.Host, " \t\r\n/\\@:") {
		return errors.New("the SMTP server is a host name, with no scheme or port")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("the SMTP port must be between 1 and 65535")
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return errors.New("the From address is not an email address")
	}
	switch c.Security {
	case mailSecurityStartTLS, mailSecurityTLS:
	case mailSecurityNone:
		if c.Username != "" {
			return errors.New("a username and password need STARTTLS or TLS: they are never sent unencrypted")
		}
		if !allowed[strings.ToLower(strings.TrimSuffix(c.Host, "."))] {
			return fmt.Errorf("unencrypted email is only for a relay on the internal destinations allowlist; add %s there or use STARTTLS", c.Host)
		}
	default:
		return errors.New("security must be starttls, tls or none")
	}
	return nil
}

func (s *Server) loadMailConfig(ctx context.Context) (mailConfig, error) {
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		return mailConfig{}, err
	}
	c := mailConfig{
		Host: settings[settingMailHost], Security: settings[settingMailSecurity],
		Username: settings[settingMailUsername], From: settings[settingMailFrom],
	}
	if c.Host == "" || c.From == "" {
		return mailConfig{}, errMailNotConfigured
	}
	c.Port, _ = strconv.Atoi(settings[settingMailPort])
	if stored := settings[settingMailPassword]; stored != "" {
		if c.Password, err = s.openSetting(settingMailPassword, stored); err != nil {
			return mailConfig{}, fmt.Errorf("read the SMTP password: %w", err)
		}
	}
	return c, nil
}

// sendMail sends one message through the configured account.
func (s *Server) sendMail(ctx context.Context, msg mailMessage) error {
	cfg, err := s.loadMailConfig(ctx)
	if err != nil {
		return err
	}
	allowed := s.webhookAllowedHosts(ctx)
	// Checked here as well as on save: the host may have left the allowlist.
	if err := validateMailConfig(cfg, allowed); err != nil {
		return err
	}
	helo := "localhost"
	if base, _ := s.agentPublicURLOrEmpty(ctx); base != "" {
		if u, err := url.Parse(base); err == nil && u.Hostname() != "" {
			helo = u.Hostname()
		}
	}
	return deliverMail(ctx, cfg, allowed, helo, msg, time.Now())
}

func deliverMail(ctx context.Context, cfg mailConfig, allowed map[string]bool, helo string, msg mailMessage, now time.Time) error {
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return fmt.Errorf("the From address: %w", err)
	}
	raw, err := buildMailMessage(from, msg, now)
	if err != nil {
		return err
	}
	if len(raw) > mailMaxBytes*4/3 {
		return fmt.Errorf("the message is %d MB, too large to email; show fewer rows", len(raw)>>20)
	}
	ctx, cancel := context.WithTimeout(ctx, mailTimeout)
	defer cancel()
	conn, err := guardedDial(ctx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)), allowed, 15*time.Second)
	if err != nil {
		return fmt.Errorf("connect to the SMTP server: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	tlsConf := cfg.tlsConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tlsConf = tlsConf.Clone()
	tlsConf.ServerName = cfg.Host
	if cfg.Security == mailSecurityTLS {
		tc := tls.Client(conn, tlsConf)
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("TLS with the SMTP server: %w", err)
		}
		conn = tc
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer client.Close()
	if err := client.Hello(helo); err != nil {
		return fmt.Errorf("SMTP hello: %w", err)
	}
	if cfg.Security == mailSecurityStartTLS {
		// Refused rather than carried on in the clear: a downgrade by
		// whoever sits on the path looks exactly like a server without it.
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("the SMTP server does not offer STARTTLS")
		}
		if err := client.StartTLS(tlsConf); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if cfg.Username != "" {
		if err := mailAuthenticate(client, cfg); err != nil {
			return err
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("SMTP sender refused: %w", err)
	}
	for _, to := range msg.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP recipient %s refused: %w", to, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP data: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("SMTP data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP server refused the message: %w", err)
	}
	return client.Quit()
}

func mailAuthenticate(client *smtp.Client, cfg mailConfig) error {
	ok, mechs := client.Extension("AUTH")
	if !ok {
		return errors.New("the SMTP server does not offer authentication; remove the username, or use a server that does")
	}
	fields := strings.Fields(strings.ToUpper(mechs))
	var a smtp.Auth
	switch {
	case slices.Contains(fields, "PLAIN"):
		a = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	case slices.Contains(fields, "LOGIN"):
		a = loginAuth{cfg.Username, cfg.Password}
	default:
		return fmt.Errorf("the SMTP server offers %q; mustra signs in with PLAIN or LOGIN", mechs)
	}
	if err := client.Auth(a); err != nil {
		return fmt.Errorf("SMTP sign-in: %w", err)
	}
	return nil
}

// loginAuth is the LOGIN mechanism, which Microsoft 365 offers instead of
// PLAIN. net/smtp only has PLAIN and CRAM-MD5.
type loginAuth struct{ username, password string }

func (a loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("refusing to send a password over an unencrypted connection")
	}
	return "LOGIN", nil, nil
}

func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:":
		return []byte(a.username), nil
	case "password:":
		return []byte(a.password), nil
	}
	return nil, fmt.Errorf("unexpected SMTP sign-in prompt %q", fromServer)
}

// buildMailMessage renders the message. Header values never carry a line
// break: the subject can hold a report's name or a CVE summary.
func buildMailMessage(from *mail.Address, msg mailMessage, now time.Time) ([]byte, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	domain := "mustra.invalid"
	if at := strings.LastIndex(from.Address, "@"); at >= 0 {
		domain = from.Address[at+1:]
	}
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(msg.Subject)

	var b bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	header("From", from.String())
	header("To", strings.Join(msg.To, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", safeTruncate(subject, 200)))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(idBytes)+"@"+domain+">")
	header("MIME-Version", "1.0")
	// RFC 3834: no out-of-office replies to a machine.
	header("Auto-Submitted", "auto-generated")

	if msg.HTML == "" {
		header("Content-Type", `text/plain; charset="utf-8"`)
		header("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		writeMailBase64(&b, msg.Text)
		return b.Bytes(), nil
	}
	mw := multipart.NewWriter(&b)
	header("Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
	b.WriteString("\r\n")
	for _, part := range []struct{ kind, body string }{{"text/plain", msg.Text}, {"text/html", msg.HTML}} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.kind + `; charset="utf-8"`},
			"Content-Transfer-Encoding": {"base64"},
		})
		if err != nil {
			return nil, err
		}
		var encoded bytes.Buffer
		writeMailBase64(&encoded, part.body)
		if _, err := w.Write(encoded.Bytes()); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// writeMailBase64 wraps at 76 columns, as RFC 2045 requires.
func writeMailBase64(b *bytes.Buffer, s string) {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
}

// eventMail is an integration event as an email. Plain text only: a
// notification is a line or two and a link.
func eventMail(to []string, ev integrationEvent, title, link string) mailMessage {
	body := ev.Body
	if body == "" {
		_, body = eventText(ev)
	}
	if link != "" {
		body = strings.TrimRight(body, "\n") + "\n\nOpen in mustra: " + link
	}
	return mailMessage{To: to, Subject: "[mustra] " + title, Text: strings.TrimLeft(body, "\n") + "\n"}
}

// updateMailSettings applies the email fields of a settings save. It answers
// false once it has written an error.
func (s *Server) updateMailSettings(w http.ResponseWriter, r *http.Request, req updateSettingsRequest, who string) bool {
	if req.MailHost == nil && req.MailPort == nil && req.MailSecurity == nil &&
		req.MailUsername == nil && req.MailPassword == nil && req.MailFrom == nil {
		return true
	}
	ctx := r.Context()
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	c := mailConfig{
		Host: settings[settingMailHost], Security: settings[settingMailSecurity],
		Username: settings[settingMailUsername], From: settings[settingMailFrom],
	}
	c.Port, _ = strconv.Atoi(settings[settingMailPort])
	oldHost := c.Host
	if req.MailHost != nil {
		c.Host = strings.TrimSpace(*req.MailHost)
	}
	if req.MailPort != nil {
		c.Port = *req.MailPort
	}
	if req.MailSecurity != nil {
		c.Security = strings.TrimSpace(*req.MailSecurity)
	}
	if req.MailUsername != nil {
		c.Username = strings.TrimSpace(*req.MailUsername)
	}
	if req.MailFrom != nil {
		c.From = strings.TrimSpace(*req.MailFrom)
	}
	if err := validateMailConfig(c, s.webhookAllowedHosts(ctx)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	if mailPasswordMustBeReentered(oldHost, c.Host, settings[settingMailPassword] != "", req.MailPassword) {
		http.Error(w, "enter the password again to use it with a different SMTP server", http.StatusBadRequest)
		return false
	}
	values := map[string]string{
		settingMailHost: c.Host, settingMailPort: strconv.Itoa(c.Port), settingMailSecurity: c.Security,
		settingMailUsername: c.Username, settingMailFrom: c.From,
	}
	// A password left behind when the username goes would be sent nowhere
	// and kept for nothing.
	if c.Username == "" && settings[settingMailPassword] != "" && req.MailPassword == nil {
		values[settingMailPassword] = ""
	}
	if req.MailPassword != nil {
		sealed, err := s.sealSetting(settingMailPassword, *req.MailPassword)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
		values[settingMailPassword] = sealed
	}
	for k, v := range values {
		if err := s.store.SetSetting(ctx, k, v, who); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
	}
	detail := map[string]any{"host": c.Host, "port": c.Port, "security": c.Security, "username": c.Username, "from": c.From}
	if req.MailPassword != nil {
		detail["password"] = map[bool]string{true: "cleared", false: "set"}[*req.MailPassword == ""]
	}
	s.audit(ctx, auditEvent{Action: "settings.mail", Actor: who, Target: "email", Severity: "notice", Detail: detail})
	return true
}

// mailPasswordMustBeReentered stops a saved password following a new host.
// The form never shows it, so anyone who may edit settings could otherwise
// read it by pointing the server at their own.
func mailPasswordMustBeReentered(oldHost, newHost string, passwordSet bool, newPassword *string) bool {
	return passwordSet && newPassword == nil && newHost != "" && !strings.EqualFold(oldHost, newHost)
}

// mailTestRequest is the body of POST /api/admin/mail-test.
type mailTestRequest struct {
	// To is who receives the test: addresses separated by commas.
	To string `json:"to"`
}

// mailTestResponse is what POST /api/admin/mail-test answers.
type mailTestResponse struct {
	Result string `json:"result"`
}

// POST /api/admin/mail-test sends one message now, through what was last
// saved, and answers with what the server said.
func (s *Server) handleMailTest(w http.ResponseWriter, r *http.Request) {
	var req mailTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	to, err := parseMailRecipients(req.To)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	err = s.sendMail(r.Context(), mailMessage{To: to, Subject: "[mustra] Test email",
		Text: "If you can read this, mustra can send email.\n"})
	s.audit(r.Context(), auditEvent{Action: "settings.mail_test", Actor: who, Target: strings.Join(to, ", "), Severity: "notice",
		Detail: map[string]any{"sent": err == nil}})
	if errors.Is(err, errMailNotConfigured) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSONResponse(w, mailTestResponse{Result: "sent"})
}
