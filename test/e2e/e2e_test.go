//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// The admin the harness creates through first-run setup.
const (
	adminUser     = "e2e-admin"
	adminPassword = "E2e-Admin-Passw0rd!" // throwaway stack; never a real credential
	// oldAgentVersion is what the harness stamps on an agent it builds
	// itself, so the console has something to update.
	oldAgentVersion = "0.0.1"
	// uninstallPassword gates the local uninstall script.
	uninstallPassword = "e2e-uninstall-pass"
)

// run is the state one end-to-end pass accumulates, step by step.
type run struct {
	e       *env
	c       *console
	ep1     *endpoint
	ep2     *endpoint
	agent1  agent
	agent2  agent
	serving string // the agent version the console serves
}

// TestE2E is one ordered pass over a fresh stack. The steps depend on each
// other (nothing can enroll before setup, nothing can deploy before an
// agent registers), so a step that leaves no usable state stops the pass
// rather than letting every later step fail for the same reason.
func TestE2E(t *testing.T) {
	e := loadEnv(t)
	r := &run{e: e, c: newConsole(t, e.consoleURL)}
	start := time.Now()
	t.Cleanup(func() {
		failed := t.Failed()
		for _, ep := range []*endpoint{r.ep1, r.ep2} {
			if ep != nil {
				ep.remove(failed)
			}
		}
		t.Logf("end-to-end pass took %s", time.Since(start).Round(time.Second))
	})

	steps := []struct {
		name     string
		critical bool
		fn       func(*testing.T, *run)
	}{
		{"setup", true, stepSetup},
		{"public-url", true, stepPublicURL},
		{"install-scripts", false, stepInstallScripts},
		{"enroll", true, stepEnroll},
		{"nats-isolation", false, stepNATSIsolation},
		{"csrf", false, stepCSRF},
		{"open-redirect", false, stepOpenRedirect},
		{"path-traversal", false, stepPathTraversal},
		{"security-headers", false, stepSecurityHeaders},
		{"signed-update", false, stepSignedUpdate},
		{"software", false, stepSoftware},
		{"patching", false, stepPatching},
		{"uninstall-reinstall", false, stepUninstallReinstall},
		{"revoke", false, stepRevoke},
		{"ui-crawl", false, stepUICrawl},
	}
	for _, s := range steps {
		ok := t.Run(s.name, func(t *testing.T) {
			r.bind(t)
			s.fn(t, r)
		})
		r.bind(t)
		if !ok && s.critical {
			t.Fatalf("step %s failed; the steps after it need what it sets up", s.name)
		}
	}
}

// bind points the console and endpoint helpers at the test that is
// running, so a failure is reported (and stops) where it happened.
func (r *run) bind(t *testing.T) {
	r.c.t = t
	for _, ep := range []*endpoint{r.ep1, r.ep2} {
		if ep != nil {
			ep.t = t
		}
	}
}

// stepSetup claims the fresh deployment with the setup token from the
// server log, then checks that the setup door is shut behind it.
func stepSetup(t *testing.T, r *run) {
	c := r.c
	resp, _ := c.do(http.MethodGet, "/setup", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /setup without the token: %d, want 403", resp.StatusCode)
	}
	tok := r.e.setupToken(t)

	resp, _ = c.do(http.MethodGet, "/setup?token=wrong"+tok[:4], nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET /setup with a wrong token: %d, want 403", resp.StatusCode)
	}
	resp, _ = c.do(http.MethodPost, "/setup", map[string]string{
		"username": adminUser, "password": adminPassword, "confirm": adminPassword, "token": "0" + tok[1:] + "0",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST /setup with a wrong token: %d, want 403", resp.StatusCode)
	}

	resp, _ = c.do(http.MethodGet, "/setup?token="+tok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /setup?token=: %d, want 200", resp.StatusCode)
	}
	var setupCookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "mustra_setup" {
			setupCookie = ck
		}
	}
	if setupCookie == nil || !setupCookie.HttpOnly || setupCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("setup cookie %+v: want HttpOnly, SameSite=Strict", setupCookie)
	}

	resp, raw := c.do(http.MethodPost, "/setup", map[string]string{
		"username": adminUser, "password": "short", "confirm": "short", "token": tok,
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "12 characters") {
		t.Errorf("weak setup password: %d %s, want 400 naming the 12-character minimum", resp.StatusCode, snippet(raw))
	}
	resp, raw = c.do(http.MethodPost, "/setup", map[string]string{
		"username": adminUser, "password": adminPassword, "confirm": adminPassword, "token": tok,
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "Terms of Use") {
		t.Errorf("setup without accepting the terms: %d %s, want 400 naming the Terms of Use", resp.StatusCode, snippet(raw))
	}
	c.call(http.MethodPost, "/setup", map[string]any{
		"username": adminUser, "password": adminPassword, "confirm": adminPassword, "token": tok, "accept_terms": true,
	}, http.StatusOK, nil)

	resp, _ = c.do(http.MethodPost, "/setup", map[string]string{
		"username": "second", "password": adminPassword, "confirm": adminPassword, "token": tok,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("second setup: %d, want 409", resp.StatusCode)
	}
	resp, _ = c.do(http.MethodGet, "/setup", nil)
	if resp.StatusCode != http.StatusFound {
		t.Errorf("GET /setup after setup: %d, want a redirect to /login", resp.StatusCode)
	}

	r.login(t)
	c.call(http.MethodGet, "/api/agents", nil, http.StatusOK, nil)
}

// login signs in as the setup admin and keeps the session cookie.
func (r *run) login(t *testing.T) {
	t.Helper()
	r.c.session = nil
	resp, _ := r.c.do(http.MethodPost, "/login/local", url.Values{"username": {adminUser}, "password": {adminPassword}})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("login: %d to %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, ck := range resp.Cookies() {
		if strings.Contains(ck.Name, "session") && ck.Value != "" {
			if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
				t.Errorf("session cookie %s: want HttpOnly and SameSite=Strict", ck.Name)
			}
			r.c.session = &http.Cookie{Name: ck.Name, Value: ck.Value}
		}
	}
	if r.c.session == nil {
		t.Fatal("login set no session cookie")
	}
}

// stepPublicURL sets the console's public URL the way an operator does
// under Settings -> Agent identity. Until it is set, no install script is
// served.
func stepPublicURL(t *testing.T, r *run) {
	c := r.c
	resp, raw := c.do(http.MethodGet, "/install.sh", nil, noSession())
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("install.sh before a public URL: %d %s, want 503", resp.StatusCode, snippet(raw))
	}
	u := r.e.publicURL
	if strings.HasPrefix(u, "http://") {
		resp, raw = c.do(http.MethodPut, "/api/agent-trust", map[string]any{"public_url": u})
		if resp.StatusCode/100 == 2 {
			t.Errorf("plain-http public URL accepted without allow_http: %s", snippet(raw))
		}
	}
	c.call(http.MethodPut, "/api/agent-trust", map[string]any{"public_url": u, "allow_http": strings.HasPrefix(u, "http://")}, http.StatusOK, nil)
	var trust struct {
		PublicURL string `json:"public_url"`
		Enforced  bool   `json:"identity_enforced"`
		Legacy    bool   `json:"legacy_configured"`
	}
	c.call(http.MethodGet, "/api/agent-trust", nil, http.StatusOK, &trust)
	if trust.PublicURL != u {
		t.Fatalf("public URL is %q, want %q", trust.PublicURL, u)
	}
	if trust.Legacy {
		t.Errorf("a fresh install reports a legacy shared agent password")
	}
}

// stepInstallScripts: the unauthenticated install scripts carry no secret,
// ignore forged Host headers and refuse a site that is not a plain name.
func stepInstallScripts(t *testing.T, r *run) {
	c := r.c
	secrets := map[string]string{}
	for _, k := range []string{"POSTGRES_PASSWORD", "MUSTRA_NATS_SERVER_PASSWORD", "MUSTRA_NATS_CALLOUT_SEED",
		"MUSTRA_AGENT_SIGNING_KEY", "MUSTRA_CREDENTIAL_ENCRYPTION_KEY", "MUSTRA_NATS_AGENT_PASSWORD"} {
		if v := r.e.dotenv[k]; len(v) >= 8 {
			secrets[k] = v
		}
	}
	if len(secrets) < 4 {
		t.Fatalf("deploy/.env has only %d of the generated secrets; is it the stack's .env?", len(secrets))
	}
	for _, path := range []string{"/install.sh", "/install.ps1"} {
		resp, raw := c.do(http.MethodGet, path, nil, noSession())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d", path, resp.StatusCode)
		}
		body := string(raw)
		for k, v := range secrets {
			if strings.Contains(body, v) {
				t.Errorf("unauthenticated %s contains %s", path, k)
			}
		}
		for _, marker := range []string{"mte_", "PRIVATE KEY"} {
			if strings.Contains(body, marker) {
				t.Errorf("unauthenticated %s contains %q", path, marker)
			}
		}
		if !strings.Contains(body, r.e.publicURL) {
			t.Errorf("%s does not name the public URL %s", path, r.e.publicURL)
		}

		// Forged Host and forwarding headers must not reach the script.
		resp, raw = c.do(http.MethodGet, path, nil, noSession(), hostHeader("evil.example"),
			header("X-Forwarded-Host", "evil.example"), header("X-Forwarded-Proto", "https"),
			header("Forwarded", "host=evil.example;proto=https"))
		if resp.StatusCode != http.StatusOK || strings.Contains(string(raw), "evil.example") {
			t.Errorf("%s with a forged Host: %d, mentions evil.example=%v", path, resp.StatusCode, strings.Contains(string(raw), "evil.example"))
		}

		for _, site := range []string{"x'y", "a$(id)", "a`id`", "a\nb", "a;id", `a"b`, "a b", strings.Repeat("s", 65)} {
			resp, _ = c.do(http.MethodGet, path+"?site="+url.QueryEscape(site), nil, noSession())
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s?site=%q: %d, want 400", path, site, resp.StatusCode)
			}
		}
		resp, raw = c.do(http.MethodGet, path+"?site=lab", nil, noSession())
		if resp.StatusCode != http.StatusOK || !(strings.Contains(string(raw), "SITE='lab'") || strings.Contains(string(raw), "$Site = 'lab'")) {
			t.Errorf("%s?site=lab: %d, site not rendered single-quoted", path, resp.StatusCode)
		}
	}
	var trust struct {
		PublicURL string `json:"public_url"`
	}
	c.call(http.MethodGet, "/api/agent-trust", nil, http.StatusOK, &trust)
	if trust.PublicURL != r.e.publicURL {
		t.Errorf("forged requests changed the stored public URL to %q", trust.PublicURL)
	}
	// A bad site is refused when a token is minted, too.
	resp, _ := c.do(http.MethodPost, "/api/enrollment-tokens", map[string]any{"label": "bad site", "site": "a$(id)"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("enrollment token with site a$(id): %d, want 400", resp.StatusCode)
	}
}

type enrollToken struct {
	Token    string            `json:"token"`
	Commands map[string]string `json:"commands"`
	Error    string            `json:"commands_error"`
	Record   struct {
		ID string `json:"id"`
	} `json:"record"`
}

func (r *run) mintToken(t *testing.T, label string) enrollToken {
	t.Helper()
	var tok enrollToken
	r.c.call(http.MethodPost, "/api/enrollment-tokens", map[string]any{"label": label, "site": "lab", "max_uses": 1}, http.StatusOK, &tok)
	if tok.Commands["unix"] == "" {
		t.Fatalf("enrollment token has no unix one-liner: %s", tok.Error)
	}
	return tok
}

// install runs the console's unix one-liner on the endpoint, exactly as an
// operator pastes it.
func install(t *testing.T, ep *endpoint, oneLiner string) {
	t.Helper()
	out, err := ep.sh(oneLiner)
	if err != nil || !strings.Contains(out, "started via systemd") {
		t.Fatalf("install on %s: %v\n%s", ep.name, err, out)
	}
}

// stepEnroll installs two endpoints with single-use tokens, and checks
// that a spent token and a missing token both enroll nothing.
func stepEnroll(t *testing.T, r *run) {
	r.e.ensureImage(t)
	r.ep1 = r.e.startEndpoint(t, "ep1")
	r.ep2 = r.e.startEndpoint(t, "ep2")

	// The uninstall password is carried to endpoints by token installs, so
	// set it before they enroll; uninstall-reinstall checks it later.
	r.c.call(http.MethodPost, "/api/admin/settings", map[string]any{"uninstall_password": uninstallPassword}, http.StatusOK, nil)

	tok1 := r.mintToken(t, "e2e ep1")
	if !strings.Contains(tok1.Commands["unix"], "Authorization: Bearer "+tok1.Token) || !strings.Contains(tok1.Commands["unix"], r.e.publicURL+"/install.sh?site=lab") {
		t.Fatalf("unexpected one-liner: %s", tok1.Commands["unix"])
	}
	// The one-liner runs the script with sudo bash; run it under a permissive umask to
	// prove the installer sets its own modes.
	install(t, r.ep1, "umask 000; "+tok1.Commands["unix"])
	r.agent1 = r.c.waitAgent(r.ep1.name, 90*time.Second, "ep1 registration", nil)
	if r.agent1.Site != "lab" || r.agent1.OS != "linux" {
		t.Errorf("ep1 registered as site=%q os=%q, want lab/linux", r.agent1.Site, r.agent1.OS)
	}
	modes := r.ep1.must(`stat -c '%a %n' /var/lib/mustra-agent /var/lib/mustra-agent/agent-credential.json /opt/mustra-agent /opt/mustra-agent/mustra-agent;
		test ! -e /var/lib/mustra-agent/enroll.token && echo token-gone;
		find /opt/mustra-agent /var/lib/mustra-agent -perm -o+w ! -type l | sed 's/^/world-writable /';
		tr '\0' '\n' < /proc/$(systemctl show -p MainPID --value mustra-agent)/environ | grep -c '^MUSTRA_NATS_PASSWORD=' || true`)
	for _, want := range []string{"700 /var/lib/mustra-agent\n", "600 /var/lib/mustra-agent/agent-credential.json", "755 /opt/mustra-agent\n", "755 /opt/mustra-agent/mustra-agent", "token-gone"} {
		if !strings.Contains(modes, want) {
			t.Errorf("ep1 file modes: missing %q in\n%s", want, modes)
		}
	}
	if strings.Contains(modes, "world-writable") {
		t.Errorf("ep1 has world-writable files:\n%s", modes)
	}
	if !strings.HasSuffix(strings.TrimSpace(modes), "0") {
		t.Errorf("the agent's environment carries MUSTRA_NATS_PASSWORD:\n%s", modes)
	}

	// A spent single-use token: refused by the console and by the installer.
	resp, raw := r.c.do(http.MethodGet, "/install.sh?site=lab", nil, noSession(), header("Authorization", "Bearer "+tok1.Token))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("spent token: %d %s, want 401", resp.StatusCode, snippet(raw))
	}
	// pipefail: without it a pipe into bash reports success whenever curl
	// fails, because bash ran (an empty script) successfully.
	if out, err := r.ep2.sh("set -o pipefail; " + tok1.Commands["unix"]); err == nil || strings.Contains(out, "started via systemd") {
		t.Errorf("ep2 installed with ep1's spent token:\n%s", out)
	}
	// No token at all: a new endpoint is refused rather than enrolled.
	if out, err := r.ep2.sh("set -o pipefail; curl -fsSL " + r.e.publicURL + "/install.sh | sudo bash"); err == nil || !strings.Contains(out, "enrollment token") {
		t.Errorf("tokenless install on a new endpoint: err=%v\n%s", err, out)
	}
	if out, _ := r.ep2.sh("systemctl list-unit-files mustra-agent.service --no-legend | wc -l; test -e /var/lib/mustra-agent/agent-credential.json && echo cred"); strings.TrimSpace(out) != "0" {
		t.Errorf("refused installs left something behind on ep2: %s", out)
	}
	resp, _ = r.c.do(http.MethodGet, "/install.sh", nil, noSession(), header("Authorization", "Bearer mte_garbage"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("garbage token: %d, want 401", resp.StatusCode)
	}

	tok2 := r.mintToken(t, "e2e ep2")
	install(t, r.ep2, tok2.Commands["unix"])
	r.agent2 = r.c.waitAgent(r.ep2.name, 90*time.Second, "ep2 registration", nil)
	if r.agent1.AgentID == r.agent2.AgentID {
		t.Fatal("two endpoints share an agent ID")
	}
}

// stepNATSIsolation connects to the broker with ep1's own credential and
// tries to act as ep2: every cross-agent publish and subscribe must be
// refused, while ep1's own subjects work.
func stepNATSIsolation(t *testing.T, r *run) {
	raw := r.ep1.must("cat /var/lib/mustra-agent/agent-credential.json")
	var cred struct {
		AgentID string `json:"agent_id"`
		Secret  string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(raw), &cred); err != nil || cred.Secret == "" {
		t.Fatalf("ep1 credential: %v", err)
	}
	if cred.AgentID != r.agent1.AgentID {
		t.Fatalf("credential is for %s, console knows ep1 as %s", cred.AgentID, r.agent1.AgentID)
	}
	perr := make(chan error, 16)
	nc, err := nats.Connect(r.e.natsURL, nats.UserInfo(cred.AgentID, cred.Secret), nats.RootCAs(r.e.caFile),
		nats.Timeout(10*time.Second), nats.CustomInboxPrefix("_INBOX_"+cred.AgentID),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			select {
			case perr <- err:
			default:
			}
		}))
	if err != nil {
		t.Fatalf("connect with ep1's credential: %v", err)
	}
	defer nc.Close()

	check := func(label string, wantDenied bool, fn func() error) {
		t.Helper()
		for len(perr) > 0 {
			<-perr
		}
		if err := fn(); err != nil {
			if !wantDenied {
				t.Errorf("%s: %v, want allowed", label, err)
			}
			return
		}
		if err := nc.Flush(); err != nil && !wantDenied {
			t.Errorf("%s: flush: %v", label, err)
		}
		select {
		case err := <-perr:
			if !wantDenied {
				t.Errorf("%s: %v, want allowed", label, err)
			} else if !strings.Contains(strings.ToLower(err.Error()), "permission") {
				t.Errorf("%s: refused with %v, want a permissions violation", label, err)
			}
		case <-time.After(1500 * time.Millisecond):
			if wantDenied {
				t.Errorf("%s: allowed, want a permissions violation", label)
			}
		}
	}
	v, own := r.agent2.AgentID, cred.AgentID
	pub := func(s string) func() error { return func() error { return nc.Publish(s, []byte("{}")) } }
	sub := func(s string) func() error {
		return func() error {
			sb, err := nc.SubscribeSync(s)
			if err == nil {
				defer sb.Unsubscribe()
				nc.Flush()
				time.Sleep(200 * time.Millisecond)
			}
			return err
		}
	}
	check("pub beacon.agent.<ep2>.heartbeat", true, pub("beacon.agent."+v+".heartbeat"))
	check("pub beacon.agent.<ep2>.facts", true, pub("beacon.agent."+v+".facts"))
	check("pub beacon.agent.<ep2>.actionresult", true, pub("beacon.agent."+v+".actionresult"))
	check("pub beacon.r.q1.<ep2>", true, pub("beacon.r.q1."+v))
	check("sub beacon.cmd.<ep2>", true, sub("beacon.cmd."+v))
	check("sub beacon.shell.<ep2>", true, sub("beacon.shell."+v))
	check("sub _INBOX.>", true, sub("_INBOX.>"))
	check("sub beacon.agent.*.>", true, sub("beacon.agent.*.>"))
	check("sub beacon.shell.*", true, sub("beacon.shell.*"))
	check("pub beacon.agent.<own>.heartbeat", false, pub("beacon.agent."+own+".heartbeat"))
	check("sub beacon.cmd.<own>", false, sub("beacon.cmd."+own))

	// The legacy shared credential is not configured on a fresh install.
	for _, pw := range []string{"", "changeme", "mustra-agent", "password"} {
		nc2, err := nats.Connect(r.e.natsURL, nats.UserInfo("mustra-agent", pw), nats.RootCAs(r.e.caFile),
			nats.Timeout(10*time.Second), nats.NoReconnect())
		if err == nil {
			nc2.Close()
			t.Errorf("legacy user mustra-agent connected with password %q", pw)
		}
	}
}

// stepCSRF: a state-changing request carrying the admin's cookie is
// refused when the browser says it came from another site.
func stepCSRF(t *testing.T, r *run) {
	c := r.c
	body := map[string]any{"label": "csrf probe", "max_uses": 1, "expires_hours": 0.05}
	for _, h := range [][2]string{{"Origin", "http://evil.example"}, {"Origin", "null"}, {"Sec-Fetch-Site", "cross-site"}, {"Referer", "http://evil.example/x"}} {
		resp, _ := c.do(http.MethodPost, "/api/enrollment-tokens", body, header(h[0], h[1]))
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST with %s: %s: %d, want 403", h[0], h[1], resp.StatusCode)
		}
	}
	var tok enrollToken
	c.call(http.MethodPost, "/api/enrollment-tokens", body, http.StatusOK, &tok, header("Origin", c.base.Scheme+"://"+c.base.Host))
	c.call(http.MethodDelete, "/api/enrollment-tokens/"+tok.Record.ID, nil, http.StatusOK, nil, header("Origin", c.base.Scheme+"://"+c.base.Host))
}

// stepOpenRedirect: the login's next parameter never leaves the site.
func stepOpenRedirect(t *testing.T, r *run) {
	saved := r.c.session
	defer func() { r.c.session = saved }()
	r.c.session = nil
	for _, next := range []string{"//evil.example", "/\\evil.example", "/\\/evil.example", "https://evil.example", "/\t/evil.example", "http:evil.example"} {
		resp, _ := r.c.do(http.MethodPost, "/login/local", url.Values{"username": {adminUser}, "password": {adminPassword}, "next": {next}})
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || loc != "/" {
			t.Errorf("next=%q: %d to %q, want 302 to /", next, resp.StatusCode, loc)
		}
	}
	resp, _ := r.c.do(http.MethodPost, "/login/local", url.Values{"username": {adminUser}, "password": {adminPassword}, "next": {"/patches?x=1"}})
	if loc := resp.Header.Get("Location"); loc != "/patches?x=1" {
		t.Errorf("a same-site next was not kept: %q", loc)
	}
}

// stepPathTraversal: package-file routes refuse traversal before touching
// the filesystem.
func stepPathTraversal(t *testing.T, r *run) {
	for _, id := range []string{"..%2F..%2F..%2Fetc%2Fpasswd", "..%2f..%2fetc%2fshadow", "pf-..%2F..%2Fetc", "....%2F%2Fetc%2Fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"} {
		for _, req := range []struct{ method, path string }{
			{http.MethodDelete, "/api/software/files/" + id},
			{http.MethodGet, "/package-files/" + id},
		} {
			resp, raw := r.c.do(req.method, req.path, nil)
			if resp.StatusCode/100 == 2 || resp.StatusCode/100 == 5 || strings.Contains(string(raw), "root:") {
				t.Errorf("%s %s: %d %s", req.method, req.path, resp.StatusCode, snippet(raw))
			}
		}
	}
}

// navPages lists every console page the navigation links to, read from
// the NAV_TREE in the app.js the console serves.
func navPages(t *testing.T, c *console) []string {
	t.Helper()
	_, js := c.do(http.MethodGet, "/static/app.js", nil)
	start := strings.Index(string(js), "const NAV_TREE = [")
	if start < 0 {
		t.Fatal("app.js has no NAV_TREE")
	}
	end := strings.Index(string(js)[start:], "\n];")
	seen := map[string]bool{}
	var pages []string
	for _, h := range regexp.MustCompile(`href: "(/[a-z0-9/-]*)"`).FindAllStringSubmatch(string(js)[start:start+end], -1) {
		if !seen[h[1]] {
			seen[h[1]] = true
			pages = append(pages, h[1])
		}
	}
	if len(pages) < 15 {
		t.Fatalf("only %d nav pages found in NAV_TREE: %v", len(pages), pages)
	}
	return pages
}

// stepSecurityHeaders: every page the navigation reaches has the full
// header set and a per-request nonce CSP.
func stepSecurityHeaders(t *testing.T, r *run) {
	pages := append(navPages(t, r.c), "/endpoint/"+r.agent1.AgentID, "/login")
	want := map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Referrer-Policy":            "",
		"Cross-Origin-Opener-Policy": "same-origin",
		"Permissions-Policy":         "",
	}
	if r.e.dotenv["MUSTRA_COOKIE_SECURE"] != "false" {
		want["Strict-Transport-Security"] = "max-age="
	}
	nonces := map[string]bool{}
	for _, p := range pages {
		resp, _ := r.c.do(http.MethodGet, p, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", p, resp.StatusCode)
			continue
		}
		for h, v := range want {
			if got := resp.Header.Get(h); got == "" || !strings.Contains(got, v) {
				t.Errorf("%s: %s = %q", p, h, got)
			}
		}
		csp := resp.Header.Get("Content-Security-Policy")
		n := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(csp)
		if n == nil || strings.Contains(csp, "'unsafe-inline' 'unsafe-eval'") || !strings.Contains(csp, "frame-ancestors") {
			t.Errorf("%s: weak or missing CSP %q", p, csp)
			continue
		}
		if nonces[n[1]] {
			t.Errorf("%s: CSP nonce reused across responses", p)
		}
		nonces[n[1]] = true
	}
	t.Logf("checked %d pages", len(pages))
}

// stepSignedUpdate: an agent the console considers outdated takes a signed
// update; with a pinned key that does not match, it refuses the update
// and keeps running.
func stepSignedUpdate(t *testing.T, r *run) {
	ep := r.ep1
	// An agent older than the one the console serves, built here from this
	// checkout with only its version stamp changed.
	old := filepath.Join(t.TempDir(), "mustra-agent")
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-X main.version="+oldAgentVersion, "-o", old, "./cmd/agent")
	build.Dir = r.e.repo
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the old agent: %v\n%s", err, out)
	}
	ep.must("systemctl stop mustra-agent")
	ep.copyIn(old, "/opt/mustra-agent/mustra-agent")
	ep.must("chmod 755 /opt/mustra-agent/mustra-agent && systemctl start mustra-agent")
	a := r.c.waitAgent(ep.name, 90*time.Second, "ep1 on "+oldAgentVersion, func(a agent) bool { return a.AgentVersion == oldAgentVersion })
	if a.AgentID != r.agent1.AgentID {
		t.Fatalf("restarting with another binary changed the agent ID: %s -> %s", r.agent1.AgentID, a.AgentID)
	}

	type outcome struct {
		Serving string `json:"serving"`
		Started int    `json:"started"`
		Results []struct {
			Started bool   `json:"started"`
			Detail  string `json:"detail"`
		} `json:"results"`
	}

	// Wrong key: pin a fresh key nobody signs with. The agent must refuse
	// the manifest and stay on its version.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ep.must(fmt.Sprintf(`set -e; cd /var/lib/mustra-agent; cp -p agent-credential.json /root/cred.bak; cp -p update-signing.pub /root/key.bak 2>/dev/null || true
		python3 -c 'import json,sys; p="agent-credential.json"; d=json.load(open(p)); d["update_signing_key"]=sys.argv[1]; json.dump(d,open(p,"w"))' %s
		printf '%%s\n' %s > update-signing.pub; systemctl restart mustra-agent`, base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(pub)))
	time.Sleep(3 * time.Second)
	r.c.waitAgent(ep.name, 60*time.Second, "ep1 back online with the wrong key", nil)
	var wrong outcome
	r.c.call(http.MethodPost, "/api/agents/"+r.agent1.AgentID+"/update", nil, http.StatusOK, &wrong)
	r.serving = wrong.Serving
	if m := regexp.MustCompile(`^\d+\.\d+\.\d+`).FindString(r.serving); m == "" || r.serving == oldAgentVersion {
		t.Fatalf("the console serves agent version %q; build the stack with MUSTRA_VERSION set to a release newer than %s", r.serving, oldAgentVersion)
	}
	if wrong.Started != 0 || len(wrong.Results) != 1 || !strings.Contains(wrong.Results[0].Detail, "does not verify") {
		t.Errorf("update with a wrong pinned key: %+v, want refused with a signature error", wrong)
	}
	time.Sleep(5 * time.Second)
	if a := r.c.waitAgent(ep.name, 30*time.Second, "ep1 still running", nil); a.AgentVersion != oldAgentVersion {
		t.Errorf("after a refused update ep1 runs %s", a.AgentVersion)
	}
	if s := strings.TrimSpace(ep.must("systemctl is-active mustra-agent || true")); s != "active" {
		t.Errorf("after a refused update the service is %s", s)
	}

	ep.must(`set -e; cd /var/lib/mustra-agent; cp -p /root/cred.bak agent-credential.json; if [ -f /root/key.bak ]; then cp -p /root/key.bak update-signing.pub; else rm -f update-signing.pub; fi; systemctl restart mustra-agent`)
	time.Sleep(3 * time.Second)
	r.c.waitAgent(ep.name, 60*time.Second, "ep1 back online with its real key", nil)

	var good outcome
	r.c.call(http.MethodPost, "/api/agents/"+r.agent1.AgentID+"/update", nil, http.StatusOK, &good)
	if good.Started != 1 {
		t.Fatalf("signed update did not start: %+v", good)
	}
	a = r.c.waitAgent(ep.name, 3*time.Minute, "ep1 on "+r.serving, func(a agent) bool { return a.AgentVersion == r.serving })
	if a.AgentID != r.agent1.AgentID {
		t.Errorf("the update changed the agent ID: %s -> %s", r.agent1.AgentID, a.AgentID)
	}
	if out := ep.must("systemctl is-active mustra-agent; systemctl show -p NRestarts --value mustra-agent"); !strings.HasPrefix(out, "active\n") {
		t.Errorf("after the update: %s", out)
	}
	// Already current: asking again does nothing.
	var again outcome
	r.c.call(http.MethodPost, "/api/agents/"+r.agent1.AgentID+"/update", nil, http.StatusOK, &again)
	if again.Started != 0 {
		t.Errorf("an update to the version already running was started: %+v", again)
	}
}

// ---- software ----

type pkgRecord struct {
	ID string `json:"id"`
}

func (r *run) createPackage(t *testing.T, fixture string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.e.repo, "test", "e2e", "testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	var p pkgRecord
	r.c.call(http.MethodPost, "/api/software", json.RawMessage(raw), http.StatusOK, &p)
	if p.ID == "" {
		t.Fatalf("creating %s returned no id", fixture)
	}
	return p.ID
}

// deploy sends one operation of a package to ep1 and waits for its
// device result.
func (r *run) deploy(t *testing.T, pkgID, op string, timeout time.Duration) agentAction {
	t.Helper()
	var resp struct {
		RunID   string `json:"run_id"`
		Targets int    `json:"targets"`
	}
	r.c.call(http.MethodPost, "/api/software/deploy", map[string]any{
		"package_id": pkgID, "operation": op, "agent_ids": []string{r.agent1.AgentID},
	}, http.StatusOK, &resp)
	if resp.Targets != 1 {
		t.Fatalf("%s of %s reached %d endpoints, want 1", op, pkgID, resp.Targets)
	}
	return r.c.waitAction(r.agent1.AgentID, resp.RunID, timeout)
}

// waitState waits for the package's applicability on ep1 to read state.
func (r *run) waitState(t *testing.T, pkgID, state string, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, 3*time.Second, pkgID+" "+state+" on ep1", func() (bool, string) {
		var out struct {
			Endpoints []struct {
				AgentID string `json:"agent_id"`
				State   string `json:"state"`
			} `json:"endpoints"`
		}
		r.c.call(http.MethodGet, "/api/software/"+pkgID+"/applicability", nil, http.StatusOK, &out)
		for _, e := range out.Endpoints {
			if e.AgentID == r.agent1.AgentID {
				return e.State == state, e.State
			}
		}
		return false, "ep1 not listed"
	})
}

func stepSoftware(t *testing.T, r *run) {
	parent := t
	t.Run("install-remove", func(t *testing.T) {
		r.bind(t)
		id := r.createPackage(t, "packages/htop-install.json")
		r.waitState(t, id, "install_eligible", 3*time.Minute)
		if a := r.deploy(t, id, "install", 5*time.Minute); a.Status != "succeeded" {
			t.Fatalf("htop install: %s %s", a.Status, a.Detail)
		}
		r.ep1.must("command -v htop")
		r.waitState(t, id, "installed", 3*time.Minute)
		if a := r.deploy(t, id, "remove", 5*time.Minute); a.Status != "succeeded" {
			t.Fatalf("htop remove: %s %s", a.Status, a.Detail)
		}
		if out, err := r.ep1.sh("command -v htop"); err == nil {
			t.Errorf("htop still installed after remove: %s", out)
		}
		r.waitState(t, id, "install_eligible", 3*time.Minute)
	})
	t.Run("fails", func(t *testing.T) {
		r.bind(t)
		id := r.createPackage(t, "packages/always-fails.json")
		a := r.deploy(t, id, "install", 2*time.Minute)
		if a.Status != "failed" || !strings.Contains(a.Detail, "exit status 7") || !strings.Contains(a.Detail, "fails on purpose") {
			t.Errorf("always-fails: %s %q, want failed with exit status 7 and stderr", a.Status, a.Detail)
		}
	})
	t.Run("times-out", func(t *testing.T) {
		r.bind(t)
		id := r.createPackage(t, "packages/always-times-out.json")
		a := r.deploy(t, id, "install", 3*time.Minute)
		took := a.FinishedAt.Sub(a.StartedAt)
		if a.Status != "timed_out" || took > 45*time.Second {
			t.Errorf("always-times-out: %s after %s (%q), want timed_out near the 10s budget", a.Status, took, a.Detail)
		}
		if out, _ := r.ep1.sh("pgrep -fx 'sleep 120' || true"); strings.TrimSpace(out) != "" {
			t.Errorf("the timed-out command's child survived: pids %s", out)
		}
	})
	t.Run("run-env-probe", func(t *testing.T) {
		r.bind(t)
		id := r.createPackage(t, "packages/env-credential-probe.json")
		a := r.deploy(t, id, "run", 2*time.Minute)
		if a.Status != "succeeded" || !strings.Contains(a.Detail, "nats_password_vars_visible=0") {
			t.Errorf("env probe via run: %s %q, want succeeded with no MUSTRA_NATS_PASSWORD visible", a.Status, a.Detail)
		}
	})
	t.Run("custom-payload", func(t *testing.T) {
		defer r.bind(parent)
		r.bind(t)
		id := r.createPackage(t, "custom-payload/package.json")
		payload, err := os.ReadFile(filepath.Join(r.e.repo, "test", "e2e", "testdata", "custom-payload", "mustra-hello.sh"))
		if err != nil {
			t.Fatal(err)
		}
		r.c.upload("/api/software/"+id+"/files", "file", "mustra-hello.sh", payload)
		r.waitState(t, id, "install_eligible", 3*time.Minute)
		a := r.deploy(t, id, "install", 3*time.Minute)
		if a.Status != "succeeded" || !strings.Contains(a.Detail, "hello from mustra test payload") {
			t.Errorf("custom payload: %s %q", a.Status, a.Detail)
		}
		r.ep1.must("test -x /usr/local/bin/mustra-hello")
	})
}

// ---- patching ----

// patchPending reports the version /api/patches says ep1 can move
// mustra-dummy to ("" when none).
func (r *run) patchPending(t *testing.T) string {
	t.Helper()
	var out struct {
		Patches []struct {
			Name           string `json:"name"`
			AffectedAgents []struct {
				AgentID    string `json:"agent_id"`
				NewVersion string `json:"new_version"`
			} `json:"affected_agents"`
		} `json:"patches"`
	}
	r.c.call(http.MethodGet, "/api/patches", nil, http.StatusOK, &out)
	for _, p := range out.Patches {
		if p.Name != "mustra-dummy" {
			continue
		}
		for _, a := range p.AffectedAgents {
			if a.AgentID == r.agent1.AgentID {
				return a.NewVersion
			}
		}
	}
	return ""
}

func (r *run) rescanUntil(t *testing.T, version string) {
	t.Helper()
	eventually(t, 3*time.Minute, 5*time.Second, "mustra-dummy "+version+" pending on ep1", func() (bool, string) {
		r.c.call(http.MethodPost, "/api/patches/rescan", map[string]any{"agent_ids": []string{r.agent1.AgentID}}, http.StatusOK, nil)
		got := r.patchPending(t)
		return strings.HasPrefix(got, version), "pending " + got
	})
}

func (r *run) deployPatches(t *testing.T) agentAction {
	t.Helper()
	var resp struct {
		RunID   string            `json:"run_id"`
		Started []string          `json:"started"`
		Failed  map[string]string `json:"failed"`
	}
	r.c.call(http.MethodPost, "/api/patches/deploy", map[string]any{"target_agent": r.agent1.AgentID}, http.StatusOK, &resp)
	if len(resp.Started) != 1 {
		t.Fatalf("patch deploy started on %v (failed %v)", resp.Started, resp.Failed)
	}
	return r.c.waitAction(r.agent1.AgentID, resp.RunID, 15*time.Minute)
}

func stepPatching(t *testing.T, r *run) {
	ep := r.ep1
	ep.must("mkdir -p /root/patching")
	for _, f := range []string{"build-debs.sh", "publish.sh", "build-broken-1.2.sh"} {
		ep.copyIn(filepath.Join(r.e.repo, "test", "e2e", "testdata", "patching", f), "/root/patching/"+f)
	}
	ep.must(`set -e; cd /root/patching; chmod 755 *.sh; ./build-debs.sh /srv/mustra-dummy; ./publish.sh /srv/mustra-dummy 1.0
		echo "deb [trusted=yes] file:/srv/mustra-dummy/repo ./" > /etc/apt/sources.list.d/mustra-dummy.list
		apt-get update -qq; apt-get install -y -qq mustra-dummy=1.0; ./publish.sh /srv/mustra-dummy 1.1; apt-get update -qq`)
	r.rescanUntil(t, "1.1")
	if a := r.deployPatches(t); a.Status != "succeeded" {
		t.Fatalf("patch deploy: %s %q", a.Status, a.Detail)
	}
	if v := strings.TrimSpace(ep.must("dpkg-query -W -f '${Version}' mustra-dummy")); v != "1.1" {
		t.Errorf("after the patch deploy mustra-dummy is %s, want 1.1", v)
	}

	ep.must(`set -e; cd /root/patching; ./build-broken-1.2.sh /srv/mustra-dummy; ./publish.sh /srv/mustra-dummy 1.2; apt-get update -qq`)
	r.rescanUntil(t, "1.2")
	if a := r.deployPatches(t); a.Status != "failed" {
		t.Errorf("broken patch deploy: %s %q, want failed", a.Status, a.Detail)
	}
	// Leave dpkg consistent for whatever runs next on this endpoint.
	ep.sh("rm -f /etc/apt/sources.list.d/mustra-dummy.list /var/lib/dpkg/info/mustra-dummy.postinst; dpkg --configure -a")
}

// stepUninstallReinstall: the local uninstall honors the console's
// password and removes everything; a reinstall then enrolls a new agent.
func stepUninstallReinstall(t *testing.T, r *run) {
	ep := r.ep2
	ep.must("test -s /opt/mustra-agent/uninstall.hash && stat -c %a /opt/mustra-agent/uninstall.hash | grep -qx 600")
	out, err := ep.sh("printf 'wrong1\\nwrong2\\nwrong3\\n' | /opt/mustra-agent/uninstall.sh")
	if err == nil || !strings.Contains(out, "Uninstall cancelled") {
		t.Errorf("uninstall with wrong passwords: err=%v\n%s", err, out)
	}
	if s := strings.TrimSpace(ep.must("systemctl is-active mustra-agent || true")); s != "active" {
		t.Errorf("after a cancelled uninstall the service is %s", s)
	}
	out = ep.must("printf '%s\\n' " + uninstallPassword + " | /opt/mustra-agent/uninstall.sh")
	if !strings.Contains(out, "mustra removed") {
		t.Errorf("uninstall: %s", out)
	}
	if left := ep.must("systemctl list-unit-files mustra-agent.service --no-legend | wc -l; ls -d /opt/mustra-agent /var/lib/mustra-agent 2>/dev/null || true"); strings.TrimSpace(left) != "0" {
		t.Errorf("uninstall left behind: %s", left)
	}

	tok := r.mintToken(t, "e2e ep2 reinstall")
	install(t, ep, tok.Commands["unix"])
	a := r.c.waitAgent(ep.name, 90*time.Second, "ep2 re-registration", func(a agent) bool { return a.AgentID != r.agent2.AgentID })
	// The old row is inventory: deleting it removes the stale endpoint.
	r.c.call(http.MethodDelete, "/api/agents/"+r.agent2.AgentID, nil, http.StatusNoContent, nil)
	for _, x := range r.c.agents() {
		if x.AgentID == r.agent2.AgentID {
			t.Errorf("deleted agent %s still listed", x.AgentID)
		}
	}
	r.agent2 = a
}

// stepRevoke revokes ep2's credential and checks the agent is cut off at
// once: its live connection is closed through the broker's system
// account, its reconnect is refused, and it goes offline within the
// stale-after window instead of when its JWT expires an hour later.
func stepRevoke(t *testing.T, r *run) {
	var resp struct {
		OK           bool   `json:"ok"`
		Disconnected int    `json:"disconnected"`
		Pending      string `json:"pending"`
	}
	r.c.call(http.MethodPost, "/api/agents/"+r.agent2.AgentID+"/revoke-credential", nil, http.StatusOK, &resp,
		header("Origin", r.c.base.Scheme+"://"+r.c.base.Host))
	if !resp.OK || resp.Disconnected < 1 || resp.Pending != "" {
		t.Fatalf("revoke: %+v, want ok with at least one connection closed at once", resp)
	}
	eventually(t, 90*time.Second, 3*time.Second, "revoked ep2 goes offline", func() (bool, string) {
		for _, a := range r.c.agents() {
			if a.AgentID == r.agent2.AgentID {
				return !a.Online, fmt.Sprintf("online=%v", a.Online)
			}
		}
		return true, ""
	})
	if log := r.ep2.must("journalctl -u mustra-agent --no-pager -n 200 || true"); !strings.Contains(strings.ToLower(log), "authorization") {
		t.Errorf("ep2's agent log shows no refused reconnect:\n%s", log)
	}
}

// stepUICrawl drives a real browser through every navigation page, in both
// themes, at desktop and phone widths (test/e2e/ui/crawl.cjs).
func stepUICrawl(t *testing.T, r *run) {
	if os.Getenv("MUSTRA_E2E_UI") == "0" {
		t.Skip("MUSTRA_E2E_UI=0")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("node is required for the UI crawl (or set MUSTRA_E2E_UI=0)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	report := filepath.Join(r.e.artifacts, "ui-report.json")
	cmd := exec.CommandContext(ctx, "node", filepath.Join(r.e.repo, "test", "e2e", "ui", "crawl.cjs"))
	cmd.Env = append(os.Environ(),
		"MUSTRA_E2E_CONSOLE_URL="+r.c.base.String(),
		"MUSTRA_E2E_COOKIE="+r.c.session.Name+"="+r.c.session.Value,
		"MUSTRA_E2E_ENDPOINT_ID="+r.agent1.AgentID,
		"MUSTRA_E2E_REPORT="+report,
		"MUSTRA_E2E_SHOTS="+filepath.Join(r.e.artifacts, "shots"),
	)
	out, err := cmd.CombinedOutput()
	t.Logf("crawl output:\n%s", out)
	raw, rerr := os.ReadFile(report)
	if rerr != nil {
		t.Fatalf("crawl wrote no report (%v): %v", err, rerr)
	}
	var rep struct {
		Loads  int `json:"loads"`
		Pages  int `json:"pages"`
		Issues []struct {
			Page, Theme, Viewport, Kind, Detail string
		} `json:"issues"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	for _, i := range rep.Issues {
		t.Errorf("%s [%s, %s] %s: %s", i.Page, i.Theme, i.Viewport, i.Kind, i.Detail)
	}
	if rep.Pages < 15 || rep.Loads != rep.Pages*4 {
		t.Errorf("crawl covered %d pages in %d loads, want every nav page x 2 themes x 2 widths", rep.Pages, rep.Loads)
	}
	if err != nil && len(rep.Issues) == 0 {
		t.Errorf("crawl exited with %v", err)
	}
	t.Logf("crawl: %d pages, %d loads, %d issues", rep.Pages, rep.Loads, len(rep.Issues))
}
