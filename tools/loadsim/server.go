//go:build loadsim

package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof on http.DefaultServeMux
	"os"

	"github.com/mustra-dev/mustra/internal/servercmd"
)

// runServer is the real control plane (servercmd.Main, the same code as
// cmd/server) plus a pprof listener on a loopback address, so a load run
// can take CPU, heap and goroutine profiles without the production binary
// carrying a profiling endpoint.
func runServer(args []string) {
	addr := os.Getenv("LOADSIM_PPROF_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18802"
	}
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Fprintln(os.Stderr, "pprof listener:", err)
		}
	}()
	os.Args = append([]string{"mustra-server"}, args...)
	servercmd.Main("server")
}
