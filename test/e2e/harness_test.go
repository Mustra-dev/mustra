//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// env is everything the harness learns about the stack under test. Each
// value has a default that matches `deploy/init.sh --start` in a checkout,
// and an MUSTRA_E2E_* override for a stack that differs (other ports, a
// compose project name, a prebuilt endpoint image).
type env struct {
	repo       string            // repository root
	deployDir  string            // where compose runs (deploy/)
	dotenv     map[string]string // deploy/.env, which holds the stack's secrets
	consoleURL *url.URL          // where this harness and the browser reach the console
	publicURL  string            // what endpoints are told the console is
	natsURL    string            // what endpoints dial: tls://host:port
	caFile     string            // the NATS CA the stack generated
	prefix     string            // container name prefix for endpoints
	image      string            // endpoint image
	artifacts  string            // logs, reports and screenshots land here
	keep       bool              // leave endpoint containers running
}

func loadEnv(t *testing.T) *env {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repo := wd
	for {
		if _, err := os.Stat(filepath.Join(repo, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(repo)
		if parent == repo {
			t.Fatal("cannot find the repository root (go.mod) above " + wd)
		}
		repo = parent
	}
	e := &env{repo: repo, deployDir: getenv("MUSTRA_E2E_DEPLOY_DIR", filepath.Join(repo, "deploy"))}
	e.dotenv, err = readDotenv(filepath.Join(e.deployDir, ".env"))
	if err != nil {
		t.Fatalf("read deploy/.env (run deploy/init.sh --start first): %v", err)
	}
	e.natsURL = e.dotenv["MUSTRA_AGENT_NATS_URL"]
	nu, err := url.Parse(e.natsURL)
	if err != nil || nu.Hostname() == "" {
		t.Fatalf("deploy/.env has no usable MUSTRA_AGENT_NATS_URL (%q)", e.natsURL)
	}
	port := firstNonEmpty(e.dotenv["MUSTRA_CONSOLE_PORT"], os.Getenv("MUSTRA_CONSOLE_PORT"), "8080")
	// localhost rather than 127.0.0.1: a browser treats it as a secure
	// context, so the console's Secure session cookie works over plain
	// http here exactly as it does through an SSH tunnel.
	cu := getenv("MUSTRA_E2E_CONSOLE_URL", "http://localhost:"+port)
	e.consoleURL, err = url.Parse(cu)
	if err != nil {
		t.Fatalf("MUSTRA_E2E_CONSOLE_URL: %v", err)
	}
	// The address endpoints use is the one init.sh put in the NATS
	// certificate and the agent NATS URL; the console is on the same host.
	e.publicURL = getenv("MUSTRA_E2E_PUBLIC_URL", "http://"+nu.Hostname()+":"+port)
	e.caFile = getenv("MUSTRA_E2E_NATS_CA", filepath.Join(e.deployDir, "nats", "certs", "ca.crt"))
	e.prefix = getenv("MUSTRA_E2E_PREFIX", firstNonEmpty(os.Getenv("COMPOSE_PROJECT_NAME"), "mustra-e2e"))
	e.image = os.Getenv("MUSTRA_E2E_ENDPOINT_IMAGE")
	e.artifacts = getenv("MUSTRA_E2E_ARTIFACTS", filepath.Join(os.TempDir(), "mustra-e2e-artifacts"))
	e.keep = os.Getenv("MUSTRA_E2E_KEEP") == "1"
	if err := os.MkdirAll(e.artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Logf("console %s, endpoints see %s and %s, artifacts in %s", e.consoleURL, e.publicURL, e.natsURL, e.artifacts)
	return e
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func readDotenv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return out, sc.Err()
}

// ---- console client ----

// console is an HTTP client for the API that never follows redirects
// (several checks are about where a redirect points) and carries the
// session cookie by hand: Go's cookie jar would not send a Secure cookie
// over the plain-http listener the stack publishes.
type console struct {
	t       *testing.T
	base    *url.URL
	hc      *http.Client
	session *http.Cookie
}

func newConsole(t *testing.T, base *url.URL) *console {
	return &console{t: t, base: base, hc: &http.Client{
		Timeout:       2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type reqOpt func(*http.Request)

func header(k, v string) reqOpt  { return func(r *http.Request) { r.Header.Set(k, v) } }
func hostHeader(h string) reqOpt { return func(r *http.Request) { r.Host = h } }
func noSession() reqOpt          { return func(r *http.Request) { r.Header.Del("Cookie") } }

// do sends one request. body may be nil, []byte, url.Values (a form) or
// anything else (sent as JSON). path may carry a pre-escaped query and
// percent-encoded segments, which are sent exactly as written.
func (c *console) do(method, path string, body any, opts ...reqOpt) (*http.Response, []byte) {
	c.t.Helper()
	var rd io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case url.Values:
		rd, ctype = strings.NewReader(b.Encode()), "application/x-www-form-urlencoded"
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			c.t.Fatal(err)
		}
		rd, ctype = bytes.NewReader(raw), "application/json"
	}
	req, err := http.NewRequest(method, c.base.String()+path, rd)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if c.session != nil {
		req.AddCookie(c.session)
	}
	for _, o := range opts {
		o(req)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// call sends a request, requires the status and decodes a JSON reply into
// out (when out is non-nil).
func (c *console) call(method, path string, body any, want int, out any, opts ...reqOpt) []byte {
	c.t.Helper()
	resp, raw := c.do(method, path, body, opts...)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, snippet(raw))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatalf("%s %s: decode %T: %v: %s", method, path, out, err, snippet(raw))
		}
	}
	return raw
}

func (c *console) upload(path, field, filename string, content []byte) []byte {
	c.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		c.t.Fatal(err)
	}
	fw.Write(content)
	mw.Close()
	resp, raw := c.do(http.MethodPost, path, buf.Bytes(), header("Content-Type", mw.FormDataContentType()))
	if resp.StatusCode/100 != 2 {
		c.t.Fatalf("upload %s: status %d: %s", path, resp.StatusCode, snippet(raw))
	}
	return raw
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return s
}

type agent struct {
	AgentID      string `json:"agent_id"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Site         string `json:"site"`
	AgentVersion string `json:"agent_version"`
	Platform     string `json:"platform"`
	Online       bool   `json:"online"`
}

func (c *console) agents() []agent {
	c.t.Helper()
	var out struct {
		Agents []agent `json:"agents"`
	}
	c.call(http.MethodGet, "/api/agents", nil, http.StatusOK, &out)
	return out.Agents
}

// waitAgent waits for an online agent with this hostname that satisfies
// cond (nil: any), and returns it.
func (c *console) waitAgent(hostname string, timeout time.Duration, what string, cond func(agent) bool) agent {
	c.t.Helper()
	var found agent
	eventually(c.t, timeout, 2*time.Second, what, func() (bool, string) {
		var seen []string
		for _, a := range c.agents() {
			if a.Hostname != hostname {
				continue
			}
			seen = append(seen, fmt.Sprintf("%s online=%v version=%s", a.AgentID, a.Online, a.AgentVersion))
			if a.Online && (cond == nil || cond(a)) {
				found = a
				return true, ""
			}
		}
		return false, fmt.Sprintf("agents named %s: %v", hostname, seen)
	})
	return found
}

type agentAction struct {
	ID         string     `json:"id"`
	RunID      string     `json:"run_id"`
	Kind       string     `json:"kind"`
	Summary    string     `json:"summary"`
	Status     string     `json:"status"`
	Detail     string     `json:"detail"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// waitAction waits until the device result for runID on this agent is
// final, and returns it.
func (c *console) waitAction(agentID, runID string, timeout time.Duration) agentAction {
	c.t.Helper()
	var found agentAction
	eventually(c.t, timeout, 2*time.Second, "device result for "+runID, func() (bool, string) {
		var out struct {
			Actions []agentAction `json:"actions"`
		}
		c.call(http.MethodGet, "/api/agents/"+agentID+"/actions", nil, http.StatusOK, &out)
		for _, a := range out.Actions {
			if a.RunID != runID {
				continue
			}
			if a.FinishedAt != nil && a.Status != "started" {
				found = a
				return true, ""
			}
			return false, "status " + a.Status
		}
		return false, "no action recorded yet"
	})
	return found
}

// eventually polls cond until it reports true or timeout passes.
func eventually(t *testing.T, timeout, every time.Duration, what string, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		ok, msg := cond()
		if ok {
			return
		}
		if msg != "" {
			last = msg
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s (last: %s)", timeout, what, last)
		}
		time.Sleep(every)
	}
}

// ---- docker ----

func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// endpoint is one systemd container standing in for a managed Linux host.
type endpoint struct {
	t    *testing.T
	e    *env
	name string
}

// ensureImage builds the endpoint image from test/e2e/endpoint unless one
// was named with MUSTRA_E2E_ENDPOINT_IMAGE.
func (e *env) ensureImage(t *testing.T) {
	t.Helper()
	if e.image != "" {
		return
	}
	e.image = e.prefix + "-endpoint:local"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if out, err := docker(ctx, "build", "-q", "-t", e.image, filepath.Join(e.repo, "test", "e2e", "endpoint")); err != nil {
		t.Fatalf("build endpoint image: %v\n%s", err, out)
	}
}

func (e *env) startEndpoint(t *testing.T, short string) *endpoint {
	t.Helper()
	ep := &endpoint{t: t, e: e, name: e.prefix + "-" + short}
	ctx := context.Background()
	docker(ctx, "rm", "-f", ep.name)
	// systemd as PID 1 needs a writable cgroup tree and its own /run.
	out, err := docker(ctx, "run", "-d", "--name", ep.name, "--hostname", ep.name,
		"--privileged", "--tmpfs", "/run", "--tmpfs", "/run/lock", e.image)
	if err != nil {
		t.Fatalf("start endpoint %s: %v\n%s", ep.name, err, out)
	}
	eventually(t, 60*time.Second, time.Second, ep.name+" systemd boot", func() (bool, string) {
		s, _ := docker(ctx, "exec", ep.name, "systemctl", "is-system-running")
		s = strings.TrimSpace(s)
		return s == "running" || s == "degraded", s
	})
	return ep
}

// remove saves the agent's journal when the test failed, then deletes the
// container (unless MUSTRA_E2E_KEEP=1).
func (ep *endpoint) remove(failed bool) {
	ctx := context.Background()
	if failed {
		j, _ := docker(ctx, "exec", ep.name, "journalctl", "--no-pager", "-u", "mustra-agent", "-n", "2000")
		_ = os.WriteFile(filepath.Join(ep.e.artifacts, ep.name+"-journal.log"), []byte(j), 0o644)
	}
	if !ep.e.keep {
		docker(ctx, "rm", "-f", ep.name)
	}
}

// sh runs a bash script as root on the endpoint and returns its combined
// output and exit error.
func (ep *endpoint) sh(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return docker(ctx, "exec", ep.name, "bash", "-c", script)
}

// must runs a script that has to succeed.
func (ep *endpoint) must(script string) string {
	ep.t.Helper()
	out, err := ep.sh(script)
	if err != nil {
		ep.t.Fatalf("%s: %q: %v\n%s", ep.name, script, err, out)
	}
	return out
}

func (ep *endpoint) copyIn(src, dst string) {
	ep.t.Helper()
	if out, err := docker(context.Background(), "cp", src, ep.name+":"+dst); err != nil {
		ep.t.Fatalf("docker cp %s: %v\n%s", src, err, out)
	}
}

// composeLogs returns the server's log, from compose in the deploy
// directory with whatever COMPOSE_PROJECT_NAME / COMPOSE_FILE the caller
// exported.
func (e *env) composeLogs(service string) (string, error) {
	cmd := exec.Command("docker", "compose", "logs", "--no-color", service)
	cmd.Dir = e.deployDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

var setupTokenRE = regexp.MustCompile(`FIRST-RUN SETUP.*?setup\?token=([0-9a-f]+)`)

// setupToken is the newest one-time setup token in the server log. A
// restart issues a new one, so the last line is the live one.
func (e *env) setupToken(t *testing.T) string {
	t.Helper()
	if tok := os.Getenv("MUSTRA_E2E_SETUP_TOKEN"); tok != "" {
		return tok
	}
	var tok string
	eventually(t, 2*time.Minute, 2*time.Second, "FIRST-RUN SETUP line in the server log", func() (bool, string) {
		logs, err := e.composeLogs("server")
		if err != nil {
			return false, err.Error()
		}
		m := setupTokenRE.FindAllStringSubmatch(logs, -1)
		if len(m) == 0 {
			return false, "not logged yet"
		}
		tok = m[len(m)-1][1]
		return true, ""
	})
	return tok
}
