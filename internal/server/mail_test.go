package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// fakeSMTP is just enough of a mail server to see what the client does.
type fakeSMTP struct {
	addr      string
	host      string
	port      int
	pool      *x509.CertPool
	implicit  bool
	starttls  bool
	authMechs string

	mu       sync.Mutex
	commands []string
	data     string
	authed   []string
	wasTLS   bool
}

func (f *fakeSMTP) saw(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commands {
		if strings.HasPrefix(strings.ToUpper(c), prefix) {
			return true
		}
	}
	return false
}

func startFakeSMTP(t *testing.T, implicit, starttls bool, authMechs string) *fakeSMTP {
	t.Helper()
	ts := httptest.NewTLSServer(nil)
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	tlsConf := &tls.Config{Certificates: ts.TLS.Certificates}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tcp := ln.Addr().(*net.TCPAddr)
	f := &fakeSMTP{addr: ln.Addr().String(), host: "127.0.0.1", port: tcp.Port, pool: pool,
		implicit: implicit, starttls: starttls, authMechs: authMechs}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, tlsConf)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn, tlsConf *tls.Config) {
	defer func() { c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	isTLS := false
	if f.implicit {
		c = tls.Server(c, tlsConf)
		isTLS = true
	}
	r := bufio.NewReader(c)
	reply := func(s string) { fmt.Fprint(c, s+"\r\n") }
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.mu.Lock()
		f.commands = append(f.commands, line)
		f.mu.Unlock()
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			lines := []string{"fake"}
			if f.starttls && !isTLS {
				lines = append(lines, "STARTTLS")
			}
			if f.authMechs != "" {
				lines = append(lines, "AUTH "+f.authMechs)
			}
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				reply("250" + sep + l)
			}
		case cmd == "STARTTLS":
			reply("220 go")
			c = tls.Server(c, tlsConf)
			r = bufio.NewReader(c)
			isTLS = true
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			f.mu.Lock()
			f.authed = append(f.authed, string(raw))
			f.mu.Unlock()
			reply("235 ok")
		case strings.HasPrefix(cmd, "AUTH LOGIN"):
			reply("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			u, _ := r.ReadString('\n')
			reply("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			p, _ := r.ReadString('\n')
			du, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
			dp, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
			f.mu.Lock()
			f.authed = append(f.authed, string(du)+":"+string(dp))
			f.mu.Unlock()
			reply("235 ok")
		case cmd == "DATA":
			reply("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data, f.wasTLS = b.String(), isTLS
			f.mu.Unlock()
			reply("250 queued")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func (f *fakeSMTP) config(security string) mailConfig {
	return mailConfig{Host: f.host, Port: f.port, Security: security, From: "mustra@example.com",
		tlsConfig: &tls.Config{RootCAs: f.pool, MinVersion: tls.VersionTLS12}}
}

var loopbackAllowed = map[string]bool{"127.0.0.1": true}

func testMail() mailMessage {
	return mailMessage{To: []string{"a@example.com", "b@example.com"}, Subject: "hello", Text: "body\n"}
}

func TestMailOverSTARTTLSSignsInAfterEncrypting(t *testing.T) {
	f := startFakeSMTP(t, false, true, "PLAIN LOGIN")
	cfg := f.config(mailSecurityStartTLS)
	cfg.Username, cfg.Password = "user", "secret"
	if err := deliverMail(context.Background(), cfg, loopbackAllowed, "mustra.test", testMail(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if !f.wasTLS {
		t.Error("the message went unencrypted")
	}
	if len(f.authed) != 1 || !strings.Contains(f.authed[0], "secret") {
		t.Errorf("sign-in: %q", f.authed)
	}
	for _, want := range []string{"MAIL FROM:<MUSTRA@EXAMPLE.COM>", "RCPT TO:<A@EXAMPLE.COM>", "RCPT TO:<B@EXAMPLE.COM>"} {
		if !f.saw(want) {
			t.Errorf("no %s in %q", want, f.commands)
		}
	}
}

// A server, or whoever sits in front of it, not offering STARTTLS must not
// turn into fleet data and a password in the clear.
func TestMailRefusesToContinueWithoutSTARTTLS(t *testing.T) {
	f := startFakeSMTP(t, false, false, "PLAIN")
	cfg := f.config(mailSecurityStartTLS)
	cfg.Username, cfg.Password = "user", "secret"
	err := deliverMail(context.Background(), cfg, loopbackAllowed, "mustra.test", testMail(), time.Now())
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	if f.saw("AUTH") || f.saw("MAIL") {
		t.Errorf("carried on in the clear: %q", f.commands)
	}
}

func TestMailOverImplicitTLSUsesLOGINWhenThatIsAllThereIs(t *testing.T) {
	f := startFakeSMTP(t, true, false, "LOGIN")
	cfg := f.config(mailSecurityTLS)
	cfg.Username, cfg.Password = "user", "secret"
	if err := deliverMail(context.Background(), cfg, loopbackAllowed, "mustra.test", testMail(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(f.authed) != 1 || f.authed[0] != "user:secret" {
		t.Errorf("sign-in: %q", f.authed)
	}
}

func TestMailRefusesAnUntrustedCertificate(t *testing.T) {
	f := startFakeSMTP(t, false, true, "PLAIN")
	cfg := f.config(mailSecurityStartTLS)
	cfg.Username, cfg.Password = "user", "secret"
	cfg.tlsConfig = nil // the system's roots, which do not hold the test CA
	if err := deliverMail(context.Background(), cfg, loopbackAllowed, "mustra.test", testMail(), time.Now()); err == nil {
		t.Fatal("sent to an untrusted server")
	}
	if f.saw("AUTH") {
		t.Error("sent the password to an untrusted server")
	}
}

func TestMailToAnInternalAddressNeedsTheAllowlist(t *testing.T) {
	f := startFakeSMTP(t, false, true, "")
	err := deliverMail(context.Background(), f.config(mailSecurityStartTLS), nil, "mustra.test", testMail(), time.Now())
	if err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoginAuthRefusesAnUnencryptedConnection(t *testing.T) {
	_, _, err := loginAuth{"u", "p"}.Start(&smtp.ServerInfo{Name: "x", TLS: false})
	if err == nil {
		t.Fatal("offered a password in the clear")
	}
}

func TestParseMailRecipients(t *testing.T) {
	got, err := parseMailRecipients("a@example.com, b@example.com;c@example.com a@example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "a@example.com,b@example.com,c@example.com" {
		t.Errorf("got %q", got)
	}
	for _, bad := range []string{"", " , ", "not-an-address", "a@example.com, nope", "a@example.com\r\nBcc: x@example.com"} {
		if _, err := parseMailRecipients(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := parseMailRecipients(manyRecipients(mailMaxRecipients + 1)); err == nil {
		t.Error("too many recipients accepted")
	}
}

func manyRecipients(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "u%d@example.com ", i)
	}
	return b.String()
}

func TestValidateMailConfig(t *testing.T) {
	good := mailConfig{Host: "smtp.example.com", Port: 587, Security: mailSecurityStartTLS, From: "m@example.com"}
	if err := validateMailConfig(good, nil); err != nil {
		t.Errorf("good config refused: %v", err)
	}
	if err := validateMailConfig(mailConfig{}, nil); err != nil {
		t.Errorf("blank should turn email off: %v", err)
	}
	relay := mailConfig{Host: "relay.lan", Port: 25, Security: mailSecurityNone, From: "m@example.com"}
	if err := validateMailConfig(relay, map[string]bool{"relay.lan": true}); err != nil {
		t.Errorf("allowlisted relay refused: %v", err)
	}
	for name, c := range map[string]mailConfig{
		"scheme in host":  {Host: "smtp://x", Port: 25, Security: mailSecurityTLS, From: "m@example.com"},
		"port in host":    {Host: "x:25", Port: 25, Security: mailSecurityTLS, From: "m@example.com"},
		"no port":         {Host: "x", Security: mailSecurityTLS, From: "m@example.com"},
		"bad from":        {Host: "x", Port: 25, Security: mailSecurityTLS, From: "nope"},
		"bad security":    {Host: "x", Port: 25, Security: "ssl3", From: "m@example.com"},
		"clear password":  {Host: "relay.lan", Port: 25, Security: mailSecurityNone, From: "m@example.com", Username: "u"},
		"clear, off-list": {Host: "smtp.example.com", Port: 25, Security: mailSecurityNone, From: "m@example.com"},
	} {
		if err := validateMailConfig(c, map[string]bool{"relay.lan": true}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestMailPasswordDoesNotFollowANewHost(t *testing.T) {
	pw := "new"
	for _, c := range []struct {
		old, new string
		set      bool
		given    *string
		want     bool
	}{
		{"a.example.com", "evil.example.com", true, nil, true},
		{"a.example.com", "evil.example.com", true, &pw, false},
		{"a.example.com", "A.example.com", true, nil, false},
		{"a.example.com", "a.example.com", true, nil, false},
		{"a.example.com", "b.example.com", false, nil, false},
		{"a.example.com", "", true, nil, false},
	} {
		if got := mailPasswordMustBeReentered(c.old, c.new, c.set, c.given); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

func TestBuildMailMessage(t *testing.T) {
	from := &mail.Address{Name: "mustra", Address: "m@example.com"}
	raw, err := buildMailMessage(from, mailMessage{To: []string{"a@example.com"},
		Subject: "Über\r\nBcc: victim@example.com", Text: "plain ✓", HTML: "<p>html ✓</p>"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Bcc") != "" {
		t.Error("a line break in the subject became a header")
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || !strings.HasPrefix(subject, "Über") {
		t.Errorf("subject %q, %v", subject, err)
	}
	if msg.Header.Get("Auto-Submitted") != "auto-generated" {
		t.Error("no Auto-Submitted header")
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	want := map[string]string{"text/plain": "plain ✓", "text/html": "<p>html ✓</p>"}
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		media, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		body, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, p))
		if string(body) != want[media] {
			t.Errorf("%s = %q", media, body)
		}
		delete(want, media)
	}
	if len(want) != 0 {
		t.Errorf("missing parts: %v", want)
	}
}

// Through the settings, as a relay that needs no sign-in has no password
// stored at all, and that must not read as a secret that cannot be opened.
func TestSendMailThroughTheSettingsWithNoPassword(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	t.Setenv("MUSTRA_WEBHOOK_ALLOWED_HOSTS", "127.0.0.1")
	f := startFakeSMTP(t, false, false, "")
	for k, v := range map[string]string{
		settingMailHost: f.host, settingMailPort: fmt.Sprint(f.port), settingMailSecurity: mailSecurityNone,
		settingMailUsername: "", settingMailPassword: "", settingMailFrom: "mustra@example.com",
	} {
		if err := st.SetSetting(ctx, k, v, "test"); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{store: st, logger: slog.Default()}
	if err := s.sendMail(ctx, testMail()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.data, "Subject: hello") {
		t.Errorf("message: %q", f.data)
	}
}
