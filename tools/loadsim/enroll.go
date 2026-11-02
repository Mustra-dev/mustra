//go:build loadsim

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

// identity is one enrolled simulated agent, as written to the creds file.
type identity struct {
	AgentID  string `json:"agent_id"`
	Secret   string `json:"secret"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Site     string `json:"site"`
	Index    int    `json:"index"`
}

// osFor gives the simulated fleet a mixed population (80% Linux, 15%
// Windows, 5% macOS) so OS-scoped subjects and targeting see realistic
// splits. The payload templates are a Linux agent's; only AgentInfo and
// facts carry the OS.
func osFor(i int) string {
	switch {
	case i%20 == 0:
		return "darwin"
	case i%20 < 4:
		return "windows"
	}
	return "linux"
}

func siteFor(i int) string { return fmt.Sprintf("site-%d", i%8) }

// runEnroll enrolls identities through the production path: each one
// opens its own short-lived broker connection authenticated with the
// enrollment token (auth callout), and asks beacon.enroll.token for a
// credential — exactly what internal/agent/identity.go enrollOnce does.
func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	nf := natsFlags(fs)
	n := fs.Int("n", 100, "identities to enroll")
	start := fs.Int("start", 0, "index of the first identity (hostname loadsim-<index>)")
	token := fs.String("token", os.Getenv("LOADSIM_ENROLL_TOKEN"), "enrollment token (max_uses >= n)")
	out := fs.String("out", "creds.jsonl", "file the credentials are appended to")
	conc := fs.Int("c", 32, "concurrent enrollments")
	_ = fs.Parse(args)
	if *token == "" {
		fatal(errors.New("-token is required"))
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	var mu sync.Mutex
	var lat latencies
	var ok, failed atomic.Int64
	jobs := make(chan int)
	var wg sync.WaitGroup
	t0 := time.Now()
	for range *conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				st := time.Now()
				id, err := enrollOne(nf, *token, i)
				if err != nil {
					failed.Add(1)
					fmt.Fprintf(os.Stderr, "enroll %d: %v\n", i, err)
					continue
				}
				lat.add(time.Since(st))
				ok.Add(1)
				raw, _ := json.Marshal(id)
				mu.Lock()
				w.Write(append(raw, '\n'))
				mu.Unlock()
			}
		}()
	}
	for i := *start; i < *start+*n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	_ = w.Flush()
	el := time.Since(t0)
	fmt.Printf("enrolled %d (failed %d) in %s = %.1f/s; per enrollment %s\n",
		ok.Load(), failed.Load(), el.Round(time.Millisecond), float64(ok.Load())/el.Seconds(), summarize(lat.snapshot(false)))
}

func enrollOne(nf *natsOpts, token string, i int) (identity, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	nonce := hex.EncodeToString(b)
	host := fmt.Sprintf("loadsim-%05d", i)
	id := identity{Hostname: host, OS: osFor(i), Site: siteFor(i), Index: i}
	nc, err := gonats.Connect(nf.url, gonats.Name("enroll:"+host), gonats.RootCAs(nf.ca),
		gonats.UserInfo(bnats.EnrollUser(nonce), token), gonats.CustomInboxPrefix(bnats.EnrollInboxPrefix(nonce)),
		gonats.Timeout(30*time.Second))
	if err != nil {
		return id, err
	}
	defer nc.Close()
	req, _ := json.Marshal(proto.EnrollRequest{Token: token, Info: proto.AgentInfo{Hostname: host, OS: id.OS, Arch: "amd64", Site: id.Site, Version: simVersion}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	msg, err := nc.RequestWithContext(ctx, bnats.EnrollToken(), req)
	if err != nil {
		return id, err
	}
	var resp proto.EnrollResponse
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return id, err
	}
	if !resp.OK {
		return id, errors.New(resp.Error)
	}
	id.AgentID, id.Secret = resp.AgentID, resp.Secret
	return id, nil
}

// simVersion is what simulated agents report; a real version string so the
// agent-version applicability logic compares rather than skips.
const simVersion = "0.9.0"

func loadIdentities(path string, n int) ([]identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []identity
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < n {
		var id identity
		if err := json.Unmarshal(sc.Bytes(), &id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if len(out) < n {
		return nil, fmt.Errorf("%s holds %d identities, %d requested; run loadsim enroll", path, len(out), n)
	}
	return out, sc.Err()
}
