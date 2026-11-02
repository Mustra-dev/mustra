//go:build loadsim

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gonats "github.com/nats-io/nats.go"

	bnats "github.com/mustra-dev/mustra/internal/nats"
)

// runCapture listens as the server's NATS user and writes the newest
// payload of every agent subject kind (heartbeat, facts, sensor.<kind>,
// register) to -out, so the fleet replays what a real agent sends rather
// than invented data of guessed sizes.
func runCapture(args []string) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	nf := natsFlags(fs)
	out := fs.String("out", "templates", "directory for captured payloads")
	dur := fs.Duration("for", 3*time.Minute, "how long to listen")
	_ = fs.Parse(args)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal(err)
	}
	nc, err := bnats.ConnectWithCreds(nf.url, "loadsim-capture", bnats.Creds{CAFile: nf.ca, User: nf.user, Password: nf.pass}, nil)
	if err != nil {
		fatal(err)
	}
	defer nc.Close()
	var mu sync.Mutex
	seen := map[string]int{}
	save := func(kind string, data []byte) {
		mu.Lock()
		defer mu.Unlock()
		if seen[kind] == 0 {
			fmt.Printf("%-28s %7d bytes\n", kind, len(data))
		}
		seen[kind]++
		_ = os.WriteFile(filepath.Join(*out, kind+".json"), data, 0o644)
	}
	if _, err := nc.Subscribe("beacon.agent.>", func(m *gonats.Msg) {
		// beacon.agent.<id>.<kind...>
		parts := strings.SplitN(m.Subject, ".", 4)
		if len(parts) == 4 {
			save(parts[3], m.Data)
		}
	}); err != nil {
		fatal(err)
	}
	if _, err := nc.Subscribe("beacon.register.*", func(m *gonats.Msg) { save("register", m.Data) }); err != nil {
		fatal(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case <-time.After(*dur):
	case <-sig:
	}
	fmt.Println("captured:", seen)
}

type natsOpts struct{ url, ca, user, pass string }

func natsFlags(fs *flag.FlagSet) *natsOpts {
	o := &natsOpts{}
	fs.StringVar(&o.url, "nats", envDefault("LOADSIM_NATS_URL", "tls://localhost:14801"), "broker URL")
	fs.StringVar(&o.ca, "ca", os.Getenv("LOADSIM_NATS_CA"), "broker CA certificate")
	fs.StringVar(&o.user, "user", "mustra-server", "server NATS user (capture, measure)")
	fs.StringVar(&o.pass, "pass", os.Getenv("LOADSIM_NATS_SERVER_PASSWORD"), "server NATS password")
	return o
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
