//go:build loadsim

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// console is a signed-in console session (break-glass login).
type console struct {
	base string
	hc   *http.Client
}

func login(base, user, pass string) (*console, error) {
	jar, _ := cookiejar.New(nil)
	c := &console{base: strings.TrimRight(base, "/"), hc: &http.Client{Jar: jar, Timeout: 5 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{MaxIdleConnsPerHost: 64}}}
	req, _ := http.NewRequest(http.MethodPost, c.base+"/login/local", strings.NewReader(url.Values{"username": {user}, "password": {pass}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", c.base)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("login: status %d", resp.StatusCode)
	}
	return c, nil
}

func (c *console) do(method, path string, body any) (int, []byte, time.Duration, error) {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", c.base)
	st := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, time.Since(st), err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, time.Since(st), err
}

func (c *console) getJSON(path string, out any) error {
	code, raw, _, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("GET %s: %d %s", path, code, snip(raw))
	}
	return json.Unmarshal(raw, out)
}

func snip(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return strings.TrimSpace(string(b))
}

func consoleFlags(fs *flag.FlagSet) (*string, *string, *string) {
	return fs.String("url", envDefault("LOADSIM_CONSOLE_URL", "http://127.0.0.1:18801"), "console URL"),
		fs.String("admin", envDefault("MUSTRA_BREAKGLASS_USERNAME", "loadadmin"), "break-glass user"),
		fs.String("password", os.Getenv("MUSTRA_BREAKGLASS_PASSWORD"), "break-glass password")
}

// runAPI is three measurements of the console under load:
//
//	-mode latency  page APIs, -c concurrent viewers for -d; p50/p99 each
//	-mode query    a live query to every endpoint; dispatch, time to all
//	-mode deploy   a package install to every eligible endpoint
//	-mode token    print a new enrollment token with -uses uses
func runAPI(args []string) {
	fs := flag.NewFlagSet("api", flag.ExitOnError)
	u, user, pass := consoleFlags(fs)
	mode := fs.String("mode", "latency", "latency | query | deploy | token")
	conc := fs.Int("c", 4, "concurrent viewers (latency)")
	dur := fs.Duration("d", 60*time.Second, "duration (latency) or deadline (query, deploy)")
	kind := fs.String("kind", "facts", "query kind")
	uses := fs.Int("uses", 1000, "token uses")
	_ = fs.Parse(args)
	c, err := login(*u, *user, *pass)
	if err != nil {
		fatal(err)
	}
	switch *mode {
	case "latency":
		apiLatency(c, *conc, *dur)
	case "query":
		apiQuery(c, *kind, *dur)
	case "deploy":
		apiDeploy(c, *dur)
	case "token":
		var tok struct {
			Token string `json:"token"`
		}
		code, raw, _, err := c.do(http.MethodPost, "/api/enrollment-tokens", map[string]any{"label": "loadsim", "site": "lab", "max_uses": *uses})
		if err != nil || code != 200 {
			fatal(fmt.Errorf("token: %d %v %s", code, err, snip(raw)))
		}
		_ = json.Unmarshal(raw, &tok)
		fmt.Println(tok.Token)
	default:
		fatal(errors.New("unknown -mode"))
	}
}

// pageCalls are the requests the console pages make on load, grouped by
// page. The endpoint page fetches the whole agent list to find its one
// agent, so it is included as written.
func pageCalls(c *console) (map[string][]string, error) {
	var agents struct {
		Agents []struct {
			ID string `json:"agent_id"`
		} `json:"agents"`
	}
	if err := c.getJSON("/api/agents", &agents); err != nil {
		return nil, err
	}
	if len(agents.Agents) == 0 {
		return nil, errors.New("no agents")
	}
	id := url.PathEscape(agents.Agents[len(agents.Agents)/2].ID)
	var dbs struct {
		Dashboards []struct {
			ID string `json:"id"`
		} `json:"dashboards"`
	}
	if err := c.getJSON("/api/dashboards", &dbs); err != nil {
		return nil, err
	}
	pages := map[string][]string{
		"agents":      {"/api/agents"},
		"endpoint":    {"/api/agents", "/api/agents/" + id + "/sensor/processes", "/api/agents/" + id + "/sensor/installed_apps", "/api/agents/" + id + "/actions", "/api/agents/" + id + "/attributes", "/api/risk", "/api/deploy/jobs"},
		"patches":     {"/api/patches"},
		"deployments": {"/api/patches/deployments"},
		"dashboards":  {"/api/dashboards"},
	}
	for _, d := range dbs.Dashboards {
		pages["dashboards"] = append(pages["dashboards"], "/api/dashboards/"+d.ID+"/data?range=24h")
	}
	return pages, nil
}

func apiLatency(c *console, conc int, dur time.Duration) {
	pages, err := pageCalls(c)
	if err != nil {
		fatal(err)
	}
	var names []string
	for n := range pages {
		names = append(names, n)
	}
	sort.Strings(names)
	// Per page: the wall time to load all its calls in parallel, as a
	// browser does. Per call: each request on its own.
	pageLat := map[string]*latencies{}
	callLat := map[string]*latencies{}
	var mu sync.Mutex
	errs := map[string]int{}
	for _, n := range names {
		pageLat[n] = &latencies{}
		for _, p := range pages[n] {
			callLat[p] = &latencies{}
		}
	}
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	for w := range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; time.Now().Before(deadline); i++ {
				n := names[i%len(names)]
				st := time.Now()
				var pw sync.WaitGroup
				for _, p := range pages[n] {
					pw.Add(1)
					go func() {
						defer pw.Done()
						code, raw, d, err := c.do(http.MethodGet, p, nil)
						if err != nil || code != 200 {
							mu.Lock()
							errs[fmt.Sprintf("%s %d %v %s", p, code, err, snip(raw))]++
							mu.Unlock()
							return
						}
						callLat[p].add(d)
					}()
				}
				pw.Wait()
				pageLat[n].add(time.Since(st))
			}
		}()
	}
	wg.Wait()
	fmt.Printf("page loads, %d concurrent viewers for %s:\n", conc, dur)
	for _, n := range names {
		fmt.Printf("  %-12s %s\n", n, summarize(pageLat[n].snapshot(false)))
	}
	fmt.Println("calls:")
	var calls []string
	for p := range callLat {
		calls = append(calls, p)
	}
	sort.Strings(calls)
	for _, p := range calls {
		fmt.Printf("  %-70s %s\n", trimID(p), summarize(callLat[p].snapshot(false)))
	}
	for e, n := range errs {
		fmt.Printf("  ERROR x%d: %s\n", n, e)
	}
}

func trimID(p string) string {
	if len(p) > 70 {
		return p[:67] + "..."
	}
	return p
}

// apiQuery starts a live query to every endpoint and follows its SSE
// stream until every expected agent has answered or the deadline passes.
func apiQuery(c *console, kind string, deadline time.Duration) {
	st := time.Now()
	code, raw, d, err := c.do(http.MethodPost, "/api/query", map[string]string{"kind": kind})
	if err != nil || code != 200 {
		fatal(fmt.Errorf("start query: %d %v %s", code, err, snip(raw)))
	}
	var q struct {
		QueryID  string `json:"query_id"`
		Expected int    `json:"expected"`
	}
	_ = json.Unmarshal(raw, &q)
	fmt.Printf("query %s kind=%s expected=%d dispatch(POST)=%.1fms\n", q.QueryID, kind, q.Expected, ms(d))
	req, _ := http.NewRequest(http.MethodGet, c.base+"/api/query/"+q.QueryID+"/stream", nil)
	hc := *c.hc
	hc.Timeout = deadline
	resp, err := hc.Do(req)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReaderSize(resp.Body, 1<<20)
	events, bytesRead := 0, 0
	last := 0
	var firstAt, lastAt time.Duration
	for {
		line, err := r.ReadBytes('\n')
		bytesRead += len(line)
		if err != nil {
			break
		}
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		events++
		var snap struct {
			Responded int `json:"responded"`
		}
		_ = json.Unmarshal(line[6:], &snap)
		if snap.Responded > 0 && firstAt == 0 {
			firstAt = time.Since(st)
		}
		if snap.Responded > last {
			last = snap.Responded
			lastAt = time.Since(st)
		}
		if last >= q.Expected {
			break
		}
	}
	fmt.Printf("responded %d/%d; first result %.0fms, last %.0fms after start; %d SSE events, %.1f MB streamed\n",
		last, q.Expected, ms(firstAt), ms(lastAt), events, float64(bytesRead)/1e6)
}

// apiDeploy creates (once) a package no endpoint has installed and installs
// it on every eligible endpoint, then polls the deployment until every
// action has finished.
func apiDeploy(c *console, deadline time.Duration) {
	var list []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	_ = c.getJSON("/api/software", &list)
	pkgID := ""
	for _, p := range list {
		if p.Name == "loadsim-tool" {
			pkgID = p.ID
		}
	}
	if pkgID == "" {
		body := map[string]any{"name": "loadsim-tool", "kind": "software", "version": "1.0", "enabled": true,
			"detect": map[string]string{"app_name": "loadsim-tool"},
			"commands": map[string]map[string]string{
				"linux": {"install": "echo install loadsim-tool"}, "windows": {"install": "echo install loadsim-tool"}, "darwin": {"install": "echo install loadsim-tool"},
			}}
		code, raw, _, err := c.do(http.MethodPost, "/api/software", body)
		if err != nil || code != 200 {
			fatal(fmt.Errorf("create package: %d %v %s", code, err, snip(raw)))
		}
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &p)
		pkgID = p.ID
	}
	st := time.Now()
	code, raw, d, err := c.do(http.MethodPost, "/api/software/deploy", map[string]any{"package_id": pkgID, "operation": "install"})
	if err != nil || code != 200 {
		fatal(fmt.Errorf("deploy: %d %v %s", code, err, snip(raw)))
	}
	var run struct {
		RunID   string `json:"run_id"`
		Targets int    `json:"targets"`
		Skipped int    `json:"skipped"`
	}
	_ = json.Unmarshal(raw, &run)
	fmt.Printf("deploy run %s: targets=%d skipped=%d, POST took %.0fms\n", run.RunID, run.Targets, run.Skipped, ms(d))
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		var dep struct {
			Deployment struct {
				Outcomes map[string]int `json:"outcomes"`
			} `json:"deployment"`
		}
		if err := c.getJSON("/api/patches/deployments/"+run.RunID, &dep); err == nil {
			done := 0
			for k, v := range dep.Deployment.Outcomes {
				if k != "running" && k != "pending" && k != "queued" && k != "started" && k != "dispatched" {
					done += v
				}
			}
			if done >= run.Targets {
				fmt.Printf("all %d finished after %.1fs: %v\n", run.Targets, time.Since(st).Seconds(), dep.Deployment.Outcomes)
				return
			}
		}
		time.Sleep(time.Second)
	}
	fmt.Println("deadline passed before every action finished")
}
