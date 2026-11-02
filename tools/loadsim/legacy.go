//go:build loadsim

package main

import (
	"flag"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
)

// runLegacy opens -n connections with the legacy shared agent credential,
// each retrying every 5 s as an unenrolled agent's connect loop does, for
// -for, and reports how many the broker admitted and how long each attempt
// took. The server must have MUSTRA_AGENT_NATS_PASSWORD set and "Allow
// legacy shared agent credential" on.
func runLegacy(args []string) {
	fs := flag.NewFlagSet("legacy", flag.ExitOnError)
	nf := natsFlags(fs)
	n := fs.Int("n", 10, "legacy connections")
	pass := fs.String("legacy-pass", "", "the shared agent password")
	dur := fs.Duration("for", time.Minute, "how long to keep trying")
	_ = fs.Parse(args)
	var ok, failed atomic.Int64
	var okLat, failLat latencies
	var lastErr atomic.Value
	deadline := time.Now().Add(*dur)
	var wg sync.WaitGroup
	for range *n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				st := time.Now()
				nc, err := gonats.Connect(nf.url, gonats.Name("legacy-sim"), gonats.RootCAs(nf.ca),
					gonats.UserInfo(bnats.LegacyAgentUser, *pass), gonats.Timeout(20*time.Second))
				if err == nil {
					okLat.add(time.Since(st))
					ok.Add(1)
					nc.Close()
				} else {
					failLat.add(time.Since(st))
					failed.Add(1)
					lastErr.Store(err.Error())
				}
				time.Sleep(5 * time.Second)
			}
		}()
	}
	wg.Wait()
	fmt.Printf("legacy connects: ok %d (%s), refused %d (%s), last error: %v\n",
		ok.Load(), summarize(okLat.snapshot(false)), failed.Load(), summarize(failLat.snapshot(false)), lastErr.Load())
}
